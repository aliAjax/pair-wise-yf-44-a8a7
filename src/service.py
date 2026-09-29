from datetime import datetime
from uuid import uuid4

from .audit import AuditTrail
from .domain import Actor, ConflictError, NotFoundError, ValidationError
from .repository import utcnow
from .rules import (
    BYPASS_OPEN_STATUSES,
    CHANGE_TERMINAL_STATUSES,
    RuleEngine,
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

    def create(self, actor, kind, data, idempotency_key=None):
        kind = self.rules.normalize_kind(kind)
        payload = dict(data or {})
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return entity
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
        self._sweep_expired_bypasses()
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
        self._after_transition(actor, updated, action)
        return updated

    def get(self, entity_id):
        self._sweep_expired_bypasses()
        return self._get_required(entity_id)

    def list(self, kind=None, status=None):
        if kind and self.rules.normalize_kind(kind) == "interlock_bypass":
            self._sweep_expired_bypasses()
        if kind is None:
            self._sweep_expired_bypasses()
        normalized = self.rules.normalize_kind(kind) if kind else None
        return self.repository.list_entities(kind=normalized, status=status)

    def audit_log(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)

    def commission_blockers(self, change_id):
        self._sweep_expired_bypasses()
        change = self._get_required(change_id)
        if change["kind"] != "change":
            raise ValidationError("entity is not a change: " + change_id)
        blockers = self.rules.commission_blockers(change, self._lookup)
        return {"change_id": change_id, "status": change["status"], "blockers": blockers}

    # ----- internals -----

    def _get_required(self, entity_id):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        return entity

    def _after_transition(self, actor, entity, action):
        kind = entity["kind"]
        if kind == "change":
            if entity["status"] in CHANGE_TERMINAL_STATUSES:
                self._invalidate_change_bypasses(
                    entity["id"], "change_" + entity["status"]
                )
            elif action == "escalate_risk" and entity["data"].get("risk_level"):
                self._require_bypass_reconfirm(
                    change_id=entity["id"],
                    reason="risk_escalated",
                    actor=actor,
                    detail={"risk_level": entity["data"]["risk_level"]},
                )
        elif kind == "unit" and action == "shutdown":
            self._require_bypass_reconfirm(
                unit_id=entity["id"],
                reason="unit_shutdown",
                actor=actor,
                detail={"unit_id": entity["id"]},
            )
        elif kind == "interlock_bypass" and action == "reassign_owner":
            if entity["status"] == "reconfirm_required":
                self.audit.record(
                    entity["id"],
                    actor,
                    "require_reconfirm",
                    "active",
                    "reconfirm_required",
                    {"reasons": entity["data"].get("reconfirm_reasons") or [],
                     "trigger": "owner_changed",
                     "new_owner": entity["data"].get("recovery_owner")},
                )

    def _invalidate_change_bypasses(self, change_id, reason):
        bypasses = self.repository.find_entities("interlock_bypass", "change_id", change_id)
        for bypass in bypasses:
            if bypass["status"] not in BYPASS_OPEN_STATUSES:
                continue
            patch = {"invalid_reason": reason, "invalidated_at": utcnow()}
            data = dict(bypass["data"])
            data.update(patch)
            self.repository.update_entity(bypass["id"], bypass["version"], "invalidated", data)
            self.audit.record(
                bypass["id"],
                SYSTEM_ACTOR,
                "auto_invalidate",
                bypass["status"],
                "invalidated",
                {"trigger": reason, "change_id": change_id},
            )

    def _require_bypass_reconfirm(self, reason, actor, change_id=None, unit_id=None, detail=None):
        if change_id:
            bypasses = self.repository.find_entities("interlock_bypass", "change_id", change_id)
        else:
            bypasses = self.repository.list_entities(kind="interlock_bypass")
            bypasses = [b for b in bypasses if b["data"].get("unit_id") == unit_id]
        for bypass in bypasses:
            if bypass["status"] not in ("active", "reconfirm_required"):
                continue
            reasons = list(bypass["data"].get("reconfirm_reasons") or [])
            added = reason not in reasons
            if added:
                reasons.append(reason)
            if not added and bypass["status"] == "reconfirm_required":
                continue
            data = dict(bypass["data"])
            data["reconfirm_reasons"] = reasons
            previous = bypass["status"]
            self.repository.update_entity(bypass["id"], bypass["version"], "reconfirm_required", data)
            self.audit.record(
                bypass["id"],
                actor,
                "require_reconfirm",
                previous,
                "reconfirm_required",
                {"reasons": reasons, "trigger": reason, "detail": detail or {}},
            )

    def _sweep_expired_bypasses(self):
        today = self.rules.current_day()
        for bypass in self.repository.list_entities(kind="interlock_bypass"):
            if bypass["status"] not in BYPASS_OPEN_STATUSES:
                continue
            deadline = str(bypass["data"].get("recovery_deadline", ""))
            try:
                due = datetime.strptime(deadline, "%Y-%m-%d").date()
            except ValueError:
                continue
            if due < today:
                data = dict(bypass["data"])
                data["invalid_reason"] = "deadline_expired"
                data["invalidated_at"] = utcnow()
                self.repository.update_entity(bypass["id"], bypass["version"], "invalidated", data)
                self.audit.record(
                    bypass["id"],
                    SYSTEM_ACTOR,
                    "auto_expire",
                    bypass["status"],
                    "invalidated",
                    {"trigger": "deadline_expired", "recovery_deadline": deadline},
                )
