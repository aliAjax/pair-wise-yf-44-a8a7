from datetime import datetime, timezone

from .domain import (
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)


RISK_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

BYPASS_OPEN_STATUSES = ("pending_review", "active", "reconfirm_required")
BYPASS_TERMINAL_STATUSES = ("recovered", "invalidated")
BYPASS_BLOCKER_REASONS = {
    "pending_review": "bypass_pending_review",
    "active": "bypass_active",
    "reconfirm_required": "bypass_reconfirm_required",
    "invalidated": "bypass_invalidated",
}
BYPASS_CHANGE_STATUSES = ("draft", "assessed", "approved", "implemented")
CHANGE_TERMINAL_STATUSES = ("rejected", "withdrawn", "closed")


def required_approval_level(risk_level):
    return RISK_ORDER.get(str(risk_level).lower(), 4)


def _find_one(lookup, kind, field, value):
    if lookup is None:
        return None
    rows = lookup(kind, field, value) or []
    return rows[0] if rows else None


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_day(value):
    try:
        return datetime.strptime(str(value), "%Y-%m-%d").date()
    except (ValueError, TypeError):
        raise ValidationError("recovery_deadline must use YYYY-MM-DD")


class RuleEngine:
    ALIASES = {
        'units': 'unit',
        'changes': 'change',
        'action_items': 'action_item',
        'interlock_bypasses': 'interlock_bypass',
    }
    INITIAL_STATUS = {
        'unit': 'operating',
        'change': 'draft',
        'action_item': 'open',
        'interlock_bypass': 'pending_review',
    }
    TRANSITIONS = {
        'unit': {
            'shutdown': (('operating',), 'shutdown'),
            'startup': (('shutdown',), 'operating'),
            'freeze': (('operating',), 'frozen'),
            'unfreeze': (('frozen',), 'operating'),
        },
        'change': {
            'assess': (('draft',), 'assessed'),
            'approve': (('assessed',), 'approved'),
            'implement': (('approved',), 'implemented'),
            'commission': (('implemented',), 'commissioned'),
            'rollback': (('implemented', 'commissioned'), 'rolled_back'),
            'close': (('rolled_back',), 'closed'),
            'reject': (('draft', 'assessed', 'approved'), 'rejected'),
            'withdraw': (('draft', 'assessed', 'approved', 'implemented'), 'withdrawn'),
            'escalate_risk': (('assessed', 'approved', 'implemented'), None),
        },
        'action_item': {
            'complete': (('open',), 'completed'),
            'verify': (('completed',), 'verified'),
            'reopen': (('verified',), 'open'),
        },
        'interlock_bypass': {
            'review': (('pending_review',), 'active'),
            'reconfirm': (('reconfirm_required',), 'active'),
            'recover': (('active', 'reconfirm_required'), 'recovered'),
            'reassign_owner': (('pending_review', 'active', 'reconfirm_required'), None),
        },
    }
    CREATE_REQUIRED = {
        'unit': ('name', 'location'),
        'change': ('unit_id', 'description'),
        'action_item': ('change_id', 'description', 'owner'),
        'interlock_bypass': (
            'change_id',
            'unit_id',
            'interlock_tag',
            'recovery_deadline',
            'recovery_owner',
        ),
    }
    ACTION_REQUIRED = {
        ('unit', 'shutdown'): ('reason',),
        ('unit', 'freeze'): ('reason',),
        ('change', 'assess'): ('risk_level', 'analyst'),
        ('change', 'approve'): ('approvals', 'permit_id'),
        ('change', 'implement'): ('procedure_version',),
        ('change', 'commission'): ('tests_passed',),
        ('change', 'rollback'): ('reason',),
        ('change', 'close'): ('outcome',),
        ('change', 'reject'): ('reason',),
        ('change', 'withdraw'): ('reason',),
        ('change', 'escalate_risk'): ('risk_level', 'reason'),
        ('action_item', 'complete'): ('completed_by', 'evidence'),
        ('action_item', 'verify'): ('verifier',),
        ('action_item', 'reopen'): ('reason',),
        ('interlock_bypass', 'review'): ('review_note',),
        ('interlock_bypass', 'reconfirm'): ('signoff_note',),
        ('interlock_bypass', 'recover'): ('restored_by',),
        ('interlock_bypass', 'reassign_owner'): ('recovery_owner',),
    }
    CREATE_ROLES = {
        'unit': ('admin', 'engineer'),
        'change': ('admin', 'engineer'),
        'action_item': ('admin', 'safety'),
        'interlock_bypass': ('admin', 'operator'),
    }
    ROLE_ACTIONS = {
        'shutdown': ('admin', 'operator'),
        'startup': ('admin', 'operator'),
        'freeze': ('admin', 'operator'),
        'unfreeze': ('admin', 'operator'),
        'assess': ('admin', 'engineer'),
        'approve': ('admin', 'safety'),
        'implement': ('admin', 'engineer'),
        'commission': ('admin', 'engineer'),
        'rollback': ('admin', 'engineer'),
        'close': ('admin', 'safety'),
        'reject': ('admin', 'safety'),
        'withdraw': ('admin', 'engineer'),
        'escalate_risk': ('admin', 'engineer', 'safety'),
        'complete': ('admin', 'engineer'),
        'verify': ('admin', 'verifier'),
        'reopen': ('admin', 'verifier'),
        ('interlock_bypass', 'review'): ('admin', 'safety'),
        ('interlock_bypass', 'reconfirm'): ('admin', 'safety'),
        ('interlock_bypass', 'recover'): ('admin', 'operator', 'safety'),
        ('interlock_bypass', 'reassign_owner'): ('admin', 'operator', 'safety'),
    }

    def __init__(self, today=None):
        self.today_fn = today or (lambda: datetime.now(timezone.utc).date())

    def current_day(self):
        return self.today_fn()

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

    # ----- custom create validation -----

    def _validate_change_create(self, actor, data, lookup):
        unit = _find_one(lookup, "unit", "id", data.get("unit_id"))
        if not unit:
            raise ValidationError("unit does not exist")
        if not data.get("description", "").strip():
            raise ValidationError("change description is required")

    def _validate_bypass_create(self, actor, data, lookup):
        change = _find_one(lookup, "change", "id", data.get("change_id"))
        if not change:
            raise ValidationError("change does not exist")
        unit = _find_one(lookup, "unit", "id", data.get("unit_id"))
        if not unit:
            raise ValidationError("unit does not exist")
        if change["data"].get("unit_id") != unit["id"]:
            raise ValidationError("unit does not match the change unit")
        if change["status"] not in BYPASS_CHANGE_STATUSES:
            raise ValidationError(
                "change status %s does not allow interlock bypass" % change["status"]
            )
        deadline = _parse_day(data.get("recovery_deadline"))
        if deadline < self.current_day():
            raise ValidationError("recovery_deadline must be today or a future date")
        if not str(data.get("interlock_tag", "")).strip():
            raise ValidationError("interlock_tag is required")
        if not str(data.get("recovery_owner", "")).strip():
            raise ValidationError("recovery_owner is required")

    def _custom_create(self, kind):
        return {
            'change': self._validate_change_create,
            'interlock_bypass': self._validate_bypass_create,
        }.get(kind)

    # ----- custom transition validation -----

    @staticmethod
    def _validate_assess(actor, entity, data, lookup):
        level = str(data.get("risk_level", "")).lower()
        if level not in RISK_ORDER:
            raise ValidationError("invalid risk_level")
        return {
            "risk_level": level,
            "required_approvals": required_approval_level(level),
        }

    @staticmethod
    def _validate_approve(actor, entity, data, lookup):
        required = int(entity["data"].get("required_approvals", 1))
        approvals = data.get("approvals") or []
        if len(set(approvals)) < required:
            raise ValidationError("not enough distinct approvals")
        return {"approved_by": actor.user_id}

    def commission_blockers(self, entity, lookup):
        """Concrete items that block commissioning a change."""
        blockers = []
        items = (lookup("action_item", "change_id", entity["id"]) or []) if lookup else []
        for item in items:
            if item["status"] != "verified":
                blockers.append({
                    "type": "action_item",
                    "id": item["id"],
                    "reason": "action_item_unverified",
                    "detail": {"status": item["status"]},
                })
        if lookup:
            bypasses = lookup("interlock_bypass", "change_id", entity["id"]) or []
            for bypass in bypasses:
                if bypass["status"] == "recovered":
                    continue
                reason = BYPASS_BLOCKER_REASONS.get(bypass["status"])
                if not reason:
                    continue
                blockers.append({
                    "type": "interlock_bypass",
                    "id": bypass["id"],
                    "reason": reason,
                    "detail": {
                        "interlock_tag": bypass["data"].get("interlock_tag"),
                        "recovery_deadline": bypass["data"].get("recovery_deadline"),
                        "invalid_reason": bypass["data"].get("invalid_reason"),
                        "reconfirm_reasons": bypass["data"].get("reconfirm_reasons") or [],
                        "status": bypass["status"],
                    },
                })
        return blockers

    def _validate_commission(self, actor, entity, data, lookup):
        blockers = self.commission_blockers(entity, lookup)
        if blockers:
            summary = "; ".join(
                "%s %s %s" % (item["type"], item["id"], item["reason"]) for item in blockers
            )
            raise ValidationError("commission blocked by: " + summary)
        return {"commissioned_by": actor.user_id}

    @staticmethod
    def _validate_bypass_review(actor, entity, data, lookup):
        return {"reviewed_by": actor.user_id, "reviewed_at": _utc_now()}

    @staticmethod
    def _validate_bypass_reconfirm(actor, entity, data, lookup):
        signoffs = list(entity["data"].get("signoffs") or [])
        signoffs.append({
            "by": actor.user_id,
            "at": _utc_now(),
            "reasons": list(entity["data"].get("reconfirm_reasons") or []),
            "note": data.get("signoff_note"),
        })
        return {"signoffs": signoffs, "reconfirm_reasons": []}

    @staticmethod
    def _validate_bypass_recover(actor, entity, data, lookup):
        return {"restored_by": data.get("restored_by"), "recovered_at": _utc_now()}

    @staticmethod
    def _validate_bypass_reassign(actor, entity, data, lookup):
        new_owner = str(data.get("recovery_owner", "")).strip()
        current_owner = entity["data"].get("recovery_owner")
        if new_owner == str(current_owner or ""):
            raise ValidationError("recovery owner is unchanged")
        patch = {
            "next_status": entity["status"],
            "recovery_owner": new_owner,
            "owner_changed_at": _utc_now(),
        }
        # A new restoration owner while the bypass is effective forces re-signoff.
        if entity["status"] == "active":
            reasons = list(entity["data"].get("reconfirm_reasons") or [])
            if "owner_changed" not in reasons:
                reasons.append("owner_changed")
            patch["next_status"] = "reconfirm_required"
            patch["reconfirm_reasons"] = reasons
        return patch

    @staticmethod
    def _validate_escalate_risk(actor, entity, data, lookup):
        new_level = str(data.get("risk_level", "")).lower()
        if new_level not in RISK_ORDER:
            raise ValidationError("invalid risk_level")
        current_level = str(entity["data"].get("risk_level", "")).lower()
        if RISK_ORDER[new_level] <= RISK_ORDER.get(current_level, 0):
            raise ValidationError(
                "risk_level must be higher than current level %s" % current_level
            )
        return {
            "next_status": entity["status"],
            "risk_level": new_level,
            "risk_escalation_reason": data.get("reason"),
            "required_approvals": required_approval_level(new_level),
        }

    def _custom_transition(self, kind, action):
        return {
            ('change', 'assess'): self._validate_assess,
            ('change', 'approve'): self._validate_approve,
            ('change', 'commission'): self._validate_commission,
            ('change', 'escalate_risk'): self._validate_escalate_risk,
            ('interlock_bypass', 'review'): self._validate_bypass_review,
            ('interlock_bypass', 'reconfirm'): self._validate_bypass_reconfirm,
            ('interlock_bypass', 'recover'): self._validate_bypass_recover,
            ('interlock_bypass', 'reassign_owner'): self._validate_bypass_reassign,
        }.get((kind, action))

    # ----- engine entry points -----

    def validate_create(self, actor, kind, data, lookup=None):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        self._ensure_role(actor, self.CREATE_ROLES.get(kind, ("admin",)))
        self._require(data, self.CREATE_REQUIRED.get(kind, ()))
        custom = self._custom_create(kind)
        if custom:
            custom(actor, data, lookup)
        return dict(data)

    def validate_transition(self, actor, entity, action, data, lookup=None):
        kind = self.normalize_kind(entity["kind"])
        transition = self.TRANSITIONS.get(kind, {}).get(action)
        if not transition:
            raise InvalidTransition("unknown action %s for %s" % (action, kind))
        allowed_statuses, declared_next = transition
        if entity["status"] not in allowed_statuses:
            raise InvalidTransition(
                "cannot %s from status %s" % (action, entity["status"])
            )
        allowed_roles = self.ROLE_ACTIONS.get(
            (kind, action), self.ROLE_ACTIONS.get(action, ("admin",))
        )
        self._ensure_role(actor, allowed_roles)
        self._require(data, self.ACTION_REQUIRED.get((kind, action), ()))
        custom = self._custom_transition(kind, action)
        extra = dict(custom(actor, entity, data, lookup)) if custom else {}
        next_status = extra.pop("next_status", None) or declared_next
        if not next_status:
            raise InvalidTransition("action %s did not resolve a next status" % action)
        patch = dict(data)
        if extra:
            patch.update(extra)
        return next_status, patch
