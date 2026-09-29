from datetime import date
from uuid import uuid4

from .audit import AuditTrail
from .domain import Actor, ConflictError, NotFoundError
from .rules import (
    BYPASS_LIVE_STATUSES,
    CHANGE_TERMINAL_STATUSES,
    RuleEngine,
    bypass_blockers,
)

SYSTEM_ACTOR = Actor("system", "admin")


class DomainService:
    def __init__(self, repository, rules=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)

    def _lookup(self, kind, field, value):
        return self.repository.find_entities(self.rules.normalize_kind(kind), field, value)

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    # -- 联锁旁路：系统级联动 -------------------------------------------------

    def _system_update(self, entity, next_status, data_patch, action, detail):
        """规则引擎之外的系统自动迁移：带版本自增与审计记录。"""
        merged = dict(entity["data"])
        merged.update(data_patch)
        updated = self.repository.update_entity(
            entity["id"], entity["version"], next_status, merged
        )
        self.audit.record(
            entity["id"],
            SYSTEM_ACTOR,
            action,
            entity["status"],
            next_status,
            detail,
        )
        return updated

    def sweep_expired_bypasses(self):
        """恢复期限已到：未了结旁路自动失效（到期/撤回/拒绝/关闭后只保留记录）。

        采用懒触发：任何创建或动作前执行，无需后台定时器。
        """
        today = self.rules.now().date()
        swept = []
        for entity in self.repository.list_entities(kind="interlock_bypass"):
            deadline_text = entity["data"].get("restore_deadline")
            if entity["status"] not in BYPASS_LIVE_STATUSES or not deadline_text:
                continue
            try:
                deadline = date.fromisoformat(str(deadline_text)[:10])
            except ValueError:
                continue
            if today > deadline:
                swept.append(
                    self._system_update(
                        entity,
                        "expired",
                        {},
                        "auto_expire",
                        {"restore_deadline": deadline_text},
                    )
                )
        return swept

    def _flag_unit_shutdown_bypasses(self, unit_id):
        for entity in self.repository.list_entities(kind="interlock_bypass"):
            if entity["status"] != "active":
                continue
            if entity["data"].get("unit_id") != unit_id:
                continue
            self._system_update(
                entity,
                "pending_resign",
                {
                    "resign_reason": "unit_shutdown",
                    "resign_requested_by": SYSTEM_ACTOR.user_id,
                    "resign_requested_at": self.rules.now().isoformat(),
                },
                "auto_require_resign",
                {"resign_reason": "unit_shutdown", "trigger": "unit_shutdown"},
            )

    def _void_change_bypasses(self, change_id, change_status):
        for entity in self.repository.list_entities(kind="interlock_bypass"):
            if entity["status"] not in BYPASS_LIVE_STATUSES:
                continue
            if entity["data"].get("change_id") != change_id:
                continue
            self._system_update(
                entity,
                "auto_invalidated",
                {
                    "resign_reason": None,
                    "resign_requested_by": None,
                    "resign_requested_at": None,
                    "void_reason": "change_" + change_status,
                },
                "auto_invalidate",
                {"change_status": change_status},
            )

    # -- 用例 ----------------------------------------------------------------

    def create(self, actor, kind, data, idempotency_key=None):
        kind = self.rules.normalize_kind(kind)
        payload = dict(data or {})
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return entity
        self.sweep_expired_bypasses()
        self.rules.validate_create(actor, kind, payload, self._lookup)
        entity_id = str(payload.pop("id", "") or uuid4())
        if self.repository.get_entity(entity_id):
            raise ConflictError("entity already exists: " + entity_id)
        status = self.rules.initial_status(kind)
        entity = self.repository.create_entity(entity_id, kind, status, payload, actor.user_id)
        self.audit.record(entity_id, actor, "create", None, status, {"kind": kind})
        if idempotency_key:
            self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return entity

    def transition(self, actor, entity_id, action, data=None, expected_version=None):
        self.sweep_expired_bypasses()
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        expected = int(expected_version) if expected_version is not None else entity["version"]
        next_status, patch = self.rules.validate_transition(
            actor, entity, action, dict(data or {}), self._lookup
        )
        merged = dict(entity["data"])
        merged.update(patch)
        updated = self.repository.update_entity(entity_id, expected, next_status, merged)
        self.audit.record(
            entity_id,
            actor,
            action,
            entity["status"],
            updated["status"],
            {"patch": patch},
        )
        # 联动：装置停机 -> 生效旁路挂起待重新签认
        if entity["kind"] == "unit" and next_status == "shutdown":
            self._flag_unit_shutdown_bypasses(entity_id)
        # 联动：变更被拒绝/撤回/关闭 -> 未恢复旁路自动失效（记录保留）
        if entity["kind"] == "change" and next_status in CHANGE_TERMINAL_STATUSES:
            self._void_change_bypasses(entity_id, next_status)
        return updated

    def commission_blockers(self, change_id):
        """投产请求的具体阻塞项：行动项 + 未恢复联锁旁路。"""
        self.sweep_expired_bypasses()
        change = self.repository.get_entity(change_id)
        if not change:
            raise NotFoundError("entity not found: " + change_id)
        items = self.repository.find_entities("action_item", "change_id", change_id)
        unresolved = [
            {"action_item_id": item["id"], "status": item["status"],
             "reason": "action item %s is %s, not verified" % (item["id"], item["status"])}
            for item in items
            if item["status"] != "verified"
        ]
        bypasses = self.repository.find_entities("interlock_bypass", "change_id", change_id)
        return {
            "change_id": change_id,
            "change_status": change["status"],
            "blocked": bool(unresolved or bypass_blockers(bypasses)),
            "blockers": unresolved + bypass_blockers(bypasses),
        }

    def get(self, entity_id):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        return entity

    def list(self, kind=None, status=None):
        if kind:
            kind = self.rules.normalize_kind(kind)
        return self.repository.list_entities(kind=kind, status=status)

    def audit_log(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)
