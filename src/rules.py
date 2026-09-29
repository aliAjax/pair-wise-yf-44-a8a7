from datetime import date, datetime

from .domain import (
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)


RISK_ORDER = ("low", "medium", "high", "critical")
RISK_RANK = {level: index for index, level in enumerate(RISK_ORDER)}

# 旁路尚未恢复（仍可能遗留）的状态：投产时必须逐一列出
BYPASS_LIVE_STATUSES = ("pending_review", "active", "pending_resign")
BYPASS_BLOCK_STATUSES = BYPASS_LIVE_STATUSES + ("expired", "auto_invalidated")
BYPASS_TERMINAL_STATUSES = ("recovered", "rejected", "cancelled", "expired", "auto_invalidated")

BYPASS_STATUS_TEXT = {
    "pending_review": "待安全员复核",
    "active": "旁路生效中",
    "pending_resign": "待重新签认",
    "recovered": "已恢复",
    "rejected": "复核被拒绝",
    "cancelled": "已撤回",
    "expired": "到期自动失效",
    "auto_invalidated": "随变更自动失效",
}

RESIGN_REASONS = ("risk_upgraded", "unit_shutdown", "owner_changed")
RESIGN_REASON_TEXT = {
    "risk_upgraded": "变更风险升级",
    "unit_shutdown": "影响装置停机",
    "owner_changed": "恢复责任人更换",
}

# 变更进入这些状态时，其下未恢复旁路自动失效
CHANGE_TERMINAL_STATUSES = ("rejected", "withdrawn", "closed")


def required_approval_level(risk_level):
    levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return levels.get(str(risk_level).lower(), 4)


def _find_one(lookup, kind, field, value):
    if lookup is None:
        return None
    rows = lookup(kind, field, value) or []
    return rows[0] if rows else None


def _parse_date(value, field):
    text = str(value or "").strip()
    if not text:
        raise ValidationError("missing required field: " + field)
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        raise ValidationError(field + " must be an ISO date (YYYY-MM-DD)")


def _risk_rank(value):
    return RISK_RANK.get(str(value or "").strip().lower())


def _validate_change(actor, data, lookup, now):
    unit = _find_one(lookup, "unit", "id", data.get("unit_id"))
    if not unit:
        raise ValidationError("unit does not exist")
    if not data.get("description", "").strip():
        raise ValidationError("change description is required")


def _validate_assess(actor, entity, data, lookup, now):
    risk_level = str(data.get("risk_level") or "").strip().lower()
    if _risk_rank(risk_level) is None:
        raise ValidationError("risk_level must be one of: " + ", ".join(RISK_ORDER))
    return {
        "risk_level": risk_level,
        "required_approvals": required_approval_level(risk_level),
    }


def _validate_approve(actor, entity, data, lookup, now):
    required = int(entity["data"].get("required_approvals", 1))
    approvals = data.get("approvals") or []
    if len(set(approvals)) < required:
        raise ValidationError("not enough distinct approvals")
    return {"approved_by": actor.user_id}


def _validate_commission(actor, entity, data, lookup, now):
    items = lookup("action_item", "change_id", entity["id"]) or [] if lookup else []
    unresolved = [item["id"] for item in items if item["status"] != "verified"]
    bypasses = lookup("interlock_bypass", "change_id", entity["id"]) or [] if lookup else []
    blockers = bypass_blockers(bypasses)
    problems = []
    if unresolved:
        problems.append("unresolved action items: " + ", ".join(unresolved))
    # 存在未恢复的联锁旁路时，列出具体阻塞项
    problems.extend(block["reason"] for block in blockers)
    if problems:
        raise ValidationError("; ".join(problems))
    return {"commissioned_by": actor.user_id}


def _validate_bypass(actor, data, lookup, now):
    """操作员提出旁路：装置、变更、联锁位号、恢复期限。"""
    unit = _find_one(lookup, "unit", "id", data.get("unit_id"))
    if not unit:
        raise ValidationError("unit does not exist")
    change = _find_one(lookup, "change", "id", data.get("change_id"))
    if not change:
        raise ValidationError("change does not exist")
    if change["status"] in CHANGE_TERMINAL_STATUSES:
        raise ValidationError("change is %s; bypass cannot be opened" % change["status"])
    tag = str(data.get("interlock_tag") or "").strip()
    if not tag:
        raise ValidationError("missing required field: interlock_tag")
    data["interlock_tag"] = tag
    deadline = _parse_date(data.get("restore_deadline"), "restore_deadline")
    if deadline < now.date():
        raise ValidationError("restore_deadline cannot be in the past")
    # 同一变更下同一联锁位号只允许存在一个未了结的旁路，防止重复/遗留旁路被掩盖
    existing = lookup("interlock_bypass", "change_id", change["id"]) or []
    for item in existing:
        if (
            item["data"].get("interlock_tag") == tag
            and item["status"] not in BYPASS_TERMINAL_STATUSES
        ):
            raise ConflictError(
                "an open bypass for interlock %s already exists: %s" % (tag, item["id"])
            )
    data["risk_review"] = None
    data["resign_reason"] = None
    data["resign_history"] = []
    data["last_reconfirmed_by"] = None


def _validate_bypass_approve(actor, entity, data, lookup, now):
    """安全员复核风险后方可生效。"""
    review = str(data.get("risk_review") or "").strip()
    if not review:
        raise ValidationError("missing required field: risk_review")
    change = _find_one(lookup, "change", "id", entity["data"].get("change_id"))
    risk_level = change["data"].get("risk_level") if change else None
    return {
        "risk_review": review,
        "risk_level_at_bypass": risk_level,
        "approved_by": actor.user_id,
        "approved_at": now.isoformat(),
    }


def _validate_bypass_reject(actor, entity, data, lookup, now):
    return {"rejected_by": actor.user_id, "rejected_at": now.isoformat()}


def _validate_report_event(actor, entity, data, lookup, now):
    """生效期间发生风险升级/装置停机/责任人更换，旁路挂起并要求重新签认。"""
    reason = str(data.get("resign_reason") or "").strip()
    if reason not in RESIGN_REASONS:
        raise ValidationError("resign_reason must be one of: " + ", ".join(RESIGN_REASONS))
    patch = {"resign_reason": reason}
    if reason == "risk_upgraded":
        new_level = str(data.get("new_risk_level") or "").strip().lower()
        if _risk_rank(new_level) is None:
            raise ValidationError("new_risk_level must be one of: " + ", ".join(RISK_ORDER))
        old_level = entity["data"].get("risk_level_at_bypass")
        if old_level and _risk_rank(new_level) <= _risk_rank(old_level):
            raise ValidationError("new_risk_level must be higher than the risk at approval")
        patch["new_risk_level"] = new_level
    elif reason == "unit_shutdown":
        note = str(data.get("note") or "").strip()
        if not note:
            raise ValidationError("missing required field: note")
        patch["shutdown_note"] = note
    elif reason == "owner_changed":
        new_owner = str(data.get("new_owner") or "").strip()
        if not new_owner:
            raise ValidationError("missing required field: new_owner")
        if new_owner == entity["data"].get("restore_owner"):
            raise ValidationError("new_owner must differ from the current restore owner")
        patch["restore_owner"] = new_owner
    patch["resign_requested_by"] = actor.user_id
    patch["resign_requested_at"] = now.isoformat()
    return patch


def _validate_change_owner(actor, entity, data, lookup, now):
    """恢复责任人更换本身触发重新签认。"""
    new_owner = str(data.get("new_owner") or "").strip()
    if not new_owner:
        raise ValidationError("missing required field: new_owner")
    if new_owner == entity["data"].get("restore_owner"):
        raise ValidationError("new_owner must differ from the current restore owner")
    return {
        "restore_owner": new_owner,
        "resign_reason": "owner_changed",
        "resign_requested_by": actor.user_id,
        "resign_requested_at": now.isoformat(),
    }


def _validate_resign(actor, entity, data, lookup, now):
    """安全员对升级情形重新签认后，旁路恢复生效。"""
    review = str(data.get("risk_review") or "").strip()
    if not review:
        raise ValidationError("missing required field: risk_review")
    entry = {
        "reason": entity["data"].get("resign_reason"),
        "risk_review": review,
        "by": actor.user_id,
        "at": now.isoformat(),
    }
    history = list(entity["data"].get("resign_history") or [])
    history.append(entry)
    return {
        "risk_review": review,
        "resign_history": history,
        "resign_reason": None,
        "resign_requested_by": None,
        "resign_requested_at": None,
        "last_reconfirmed_by": actor.user_id,
        "last_reconfirmed_at": now.isoformat(),
    }


def _validate_recover(actor, entity, data, lookup, now):
    return {"recovered_by": actor.user_id, "recovered_at": now.isoformat()}


CUSTOM_CREATE = {"change": _validate_change, "interlock_bypass": _validate_bypass}
CUSTOM_TRANSITIONS = {
    ("change", "assess"): _validate_assess,
    ("change", "approve"): _validate_approve,
    ("change", "commission"): _validate_commission,
    ("interlock_bypass", "approve_bypass"): _validate_bypass_approve,
    ("interlock_bypass", "reject_bypass"): _validate_bypass_reject,
    ("interlock_bypass", "report_event"): _validate_report_event,
    ("interlock_bypass", "change_owner"): _validate_change_owner,
    ("interlock_bypass", "resign"): _validate_resign,
    ("interlock_bypass", "recover"): _validate_recover,
}


def bypass_blockers(bypasses):
    """投产前未恢复旁路的具体阻塞项，按位号排序。"""
    blockers = []
    for item in bypasses:
        status = item["status"]
        if status not in BYPASS_BLOCK_STATUSES:
            continue
        tag = item["data"].get("interlock_tag", "?")
        if status == "active":
            reason = "interlock %s bypass is still active (restore by %s)" % (
                tag,
                item["data"].get("restore_deadline"),
            )
        elif status == "pending_resign":
            reason = "interlock %s bypass awaits re-confirmation (%s)" % (
                tag,
                RESIGN_REASON_TEXT.get(item["data"].get("resign_reason"), "condition changed"),
            )
        elif status == "expired":
            reason = "interlock %s bypass expired on %s and was never recovered" % (
                tag,
                item["data"].get("restore_deadline"),
            )
        elif status == "auto_invalidated":
            reason = (
                "interlock %s bypass was voided with the change on %s and was never recovered"
                % (tag, item["updated_at"][:10])
            )
        else:  # pending_review
            reason = "interlock %s bypass is pending safety review" % tag
        blockers.append({
            "bypass_id": item["id"],
            "interlock_tag": tag,
            "status": status,
            "reason": reason,
        })
    blockers.sort(key=lambda block: (block["interlock_tag"], block["bypass_id"]))
    return blockers


class RuleEngine:
    ALIASES = {
        "units": "unit",
        "changes": "change",
        "action_items": "action_item",
        "bypasses": "interlock_bypass",
        "interlock_bypasses": "interlock_bypass",
    }
    INITIAL_STATUS = {
        "unit": "operating",
        "change": "draft",
        "action_item": "open",
        "interlock_bypass": "pending_review",
    }
    TRANSITIONS = {
        "unit": {
            "shutdown": (("operating",), "shutdown"),
            "startup": (("shutdown",), "operating"),
            "freeze": (("operating",), "frozen"),
            "unfreeze": (("frozen",), "operating"),
        },
        "change": {
            "assess": (("draft",), "assessed"),
            "approve": (("assessed",), "approved"),
            "reject": (("assessed",), "rejected"),
            "withdraw": (("draft", "assessed", "approved"), "withdrawn"),
            "implement": (("approved",), "implemented"),
            "commission": (("implemented",), "commissioned"),
            "rollback": (("implemented", "commissioned"), "rolled_back"),
            "close": (("rolled_back", "commissioned"), "closed"),
        },
        "action_item": {
            "complete": (("open",), "completed"),
            "verify": (("completed",), "verified"),
            "reopen": (("verified",), "open"),
        },
        "interlock_bypass": {
            # 安全员复核风险后才能生效
            "approve_bypass": (("pending_review",), "active"),
            "reject_bypass": (("pending_review",), "rejected"),
            "cancel": (("pending_review",), "cancelled"),
            # 生效期间风险升级/装置停机/责任人更换 -> 待重新签认
            "report_event": (("active",), "pending_resign"),
            "change_owner": (("active",), "pending_resign"),
            "resign": (("pending_resign",), "active"),
            # 到期前恢复；记录保留
            "recover": (("active", "expired"), "recovered"),
        },
    }
    CREATE_REQUIRED = {
        "unit": ("name", "location"),
        "change": ("unit_id", "description"),
        "action_item": ("change_id", "description", "owner"),
        "interlock_bypass": (
            "unit_id",
            "change_id",
            "interlock_tag",
            "restore_deadline",
            "restore_owner",
        ),
    }
    ACTION_REQUIRED = {
        ("unit", "shutdown"): ("reason",),
        ("unit", "freeze"): ("reason",),
        ("change", "assess"): ("risk_level", "analyst"),
        ("change", "approve"): ("approvals", "permit_id"),
        ("change", "reject"): ("reason",),
        ("change", "withdraw"): ("reason",),
        ("change", "implement"): ("procedure_version",),
        ("change", "commission"): ("tests_passed",),
        ("change", "rollback"): ("reason",),
        ("change", "close"): ("outcome",),
        ("action_item", "complete"): ("completed_by", "evidence"),
        ("action_item", "verify"): ("verifier",),
        ("action_item", "reopen"): ("reason",),
        ("interlock_bypass", "approve_bypass"): ("risk_review",),
        ("interlock_bypass", "reject_bypass"): ("reason",),
        ("interlock_bypass", "cancel"): ("reason",),
        ("interlock_bypass", "report_event"): ("resign_reason",),
        ("interlock_bypass", "change_owner"): ("new_owner",),
        ("interlock_bypass", "resign"): ("risk_review",),
        ("interlock_bypass", "recover"): ("evidence",),
    }
    CREATE_ROLES = {
        "unit": ("admin", "engineer"),
        "change": ("admin", "engineer"),
        "action_item": ("admin", "safety"),
        # 旁路由操作员提出
        "interlock_bypass": ("admin", "operator"),
    }
    ROLE_ACTIONS = {
        "shutdown": ("admin", "operator"),
        "startup": ("admin", "operator"),
        "freeze": ("admin", "operator"),
        "unfreeze": ("admin", "operator"),
        "assess": ("admin", "engineer"),
        "approve": ("admin", "safety"),
        "reject": ("admin", "safety"),
        "withdraw": ("admin", "engineer", "operator"),
        "implement": ("admin", "engineer"),
        "commission": ("admin", "engineer"),
        "rollback": ("admin", "engineer"),
        "close": ("admin", "safety"),
        "complete": ("admin", "engineer"),
        "verify": ("admin", "verifier"),
        "reopen": ("admin", "verifier"),
        # 安全员复核与重新签认
        "approve_bypass": ("admin", "safety"),
        "reject_bypass": ("admin", "safety"),
        "cancel": ("admin", "operator"),
        "report_event": ("admin", "operator", "engineer", "safety"),
        "change_owner": ("admin", "operator", "engineer"),
        "resign": ("admin", "safety"),
        "recover": ("admin", "operator", "engineer"),
    }

    def __init__(self, clock=None):
        # 可注入时钟，便于测试恢复期限
        self.clock = clock or datetime.utcnow

    def now(self):
        return self.clock()

    def normalize_kind(self, kind):
        return self.ALIASES.get(kind, kind)

    def initial_status(self, kind):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        return self.INITIAL_STATUS[kind]

    @staticmethod
    def _ensure_role(actor, allowed):
        if "*" not in allowed and actor.role not in allowed:
            raise PermissionDenied("role %s is not allowed here" % actor.role)

    @staticmethod
    def _require(data, fields):
        for field in fields:
            value = data.get(field)
            if value is None or value == "" or value == [] or value == {}:
                raise ValidationError("missing required field: " + field)

    def validate_create(self, actor, kind, data, lookup=None):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        self._ensure_role(actor, self.CREATE_ROLES.get(kind, ("admin",)))
        self._require(data, self.CREATE_REQUIRED.get(kind, ()))
        custom = CUSTOM_CREATE.get(kind)
        if custom:
            custom(actor, data, lookup, self.now())
        return dict(data)

    def validate_transition(self, actor, entity, action, data, lookup=None):
        kind = self.normalize_kind(entity["kind"])
        transition = self.TRANSITIONS.get(kind, {}).get(action)
        if not transition:
            raise InvalidTransition("unknown action %s for %s" % (action, kind))
        allowed_statuses, next_status = transition
        if entity["status"] not in allowed_statuses:
            raise InvalidTransition(
                "cannot %s from status %s" % (action, entity["status"])
            )
        allowed_roles = self.ROLE_ACTIONS.get(
            (kind, action), self.ROLE_ACTIONS.get(action, ("admin",))
        )
        self._ensure_role(actor, allowed_roles)
        self._require(data, self.ACTION_REQUIRED.get((kind, action), ()))
        custom = CUSTOM_TRANSITIONS.get((kind, action))
        extra = custom(actor, entity, data, lookup, self.now()) if custom else {}
        patch = dict(data)
        if extra:
            patch.update(extra)
        return next_status, patch
