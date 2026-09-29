import tempfile
import unittest
from datetime import date
from pathlib import Path

from src.domain import (
    Actor,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


class InterlockBypassTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.today = date(2026, 9, 29)
        self.deadline = "2026-10-05"
        self._build_service()
        self.admin = Actor("admin", "admin")
        self.operator = Actor("op-1", "operator")
        self.safety = Actor("safety-1", "safety")
        self.engineer = Actor("eng-1", "engineer")
        self.unit = self.service.create(
            self.admin, "unit", {"name": "Reactor-1", "location": "Plant-A"}
        )
        self.change = self.service.create(
            self.engineer,
            "change",
            {"unit_id": self.unit["id"], "description": "modify feed control"},
        )

    def _build_service(self, today=None):
        day = today or self.today
        self.rules = RuleEngine(today=lambda: day)
        self.service = DomainService(self.repo, self.rules)

    def tearDown(self):
        self.tmp.cleanup()

    def _bypass(self, **overrides):
        data = {
            "change_id": self.change["id"],
            "unit_id": self.unit["id"],
            "interlock_tag": "I-1001",
            "recovery_deadline": self.deadline,
            "recovery_owner": "owner-1",
        }
        data.update(overrides)
        return self.service.create(self.operator, "interlock_bypass", data)

    def _activate(self, bypass):
        return self.service.transition(
            self.safety,
            bypass["id"],
            "review",
            {"review_note": "mitigations in place"},
        )

    def test_bypass_is_pending_until_safety_review(self):
        bypass = self._bypass()
        self.assertEqual(bypass["status"], "pending_review")
        with self.assertRaises(PermissionDenied):
            self.service.transition(
                self.operator,
                bypass["id"],
                "review",
                {"review_note": "self approval"},
            )
        active = self._activate(bypass)
        self.assertEqual(active["status"], "active")
        self.assertEqual(active["data"]["reviewed_by"], "safety-1")

    def test_create_requires_future_deadline_and_matching_unit(self):
        with self.assertRaises(ValidationError):
            self._bypass(recovery_deadline="2026-09-01")
        other_unit = self.service.create(
            self.admin, "unit", {"name": "Reactor-2", "location": "Plant-B"}
        )
        with self.assertRaises(ValidationError):
            self._bypass(unit_id=other_unit["id"])
        with self.assertRaises(ValidationError):
            self._bypass(interlock_tag="  ")

    def test_review_requires_note(self):
        bypass = self._bypass()
        with self.assertRaises(ValidationError):
            self.service.transition(self.safety, bypass["id"], "review", {})

    def test_risk_escalation_forces_resignoff(self):
        bypass = self._activate(self._bypass())
        self.service.transition(
            self.engineer,
            self.change["id"],
            "assess",
            {"risk_level": "medium", "analyst": "eng-1"},
        )
        with self.assertRaises(ValidationError):
            self.service.transition(
                self.engineer,
                self.change["id"],
                "escalate_risk",
                {"risk_level": "low", "reason": "not higher"},
            )
        self.service.transition(
            self.engineer,
            self.change["id"],
            "escalate_risk",
            {"risk_level": "high", "reason": "new failure mode found"},
        )
        bypass = self.service.get(bypass["id"])
        self.assertEqual(bypass["status"], "reconfirm_required")
        self.assertIn("risk_escalated", bypass["data"]["reconfirm_reasons"])
        with self.assertRaises(PermissionDenied):
            self.service.transition(
                self.operator, bypass["id"], "reconfirm", {"signoff_note": "ok"}
            )
        active = self.service.transition(
            self.safety, bypass["id"], "reconfirm", {"signoff_note": "re-checked"}
        )
        self.assertEqual(active["status"], "active")
        self.assertEqual(active["data"]["reconfirm_reasons"], [])
        self.assertEqual(len(active["data"]["signoffs"]), 1)

    def test_unit_shutdown_forces_resignoff(self):
        bypass = self._activate(self._bypass())
        self.service.transition(
            self.operator, self.unit["id"], "shutdown", {"reason": "repair"}
        )
        bypass = self.service.get(bypass["id"])
        self.assertEqual(bypass["status"], "reconfirm_required")
        self.assertEqual(bypass["data"]["reconfirm_reasons"], ["unit_shutdown"])

    def test_recovery_owner_change_forces_resignoff_when_active(self):
        bypass = self._bypass()
        still_pending = self.service.transition(
            self.operator,
            bypass["id"],
            "reassign_owner",
            {"recovery_owner": "owner-2"},
        )
        self.assertEqual(still_pending["status"], "pending_review")
        self.assertEqual(still_pending["data"]["recovery_owner"], "owner-2")

        self._activate(bypass)
        with self.assertRaises(ValidationError):
            self.service.transition(
                self.operator,
                bypass["id"],
                "reassign_owner",
                {"recovery_owner": "owner-2"},
            )
        flagged = self.service.transition(
            self.operator,
            bypass["id"],
            "reassign_owner",
            {"recovery_owner": "owner-3"},
        )
        self.assertEqual(flagged["status"], "reconfirm_required")
        self.assertEqual(flagged["data"]["recovery_owner"], "owner-3")
        self.assertIn("owner_changed", flagged["data"]["reconfirm_reasons"])

    def _implemented_change(self, level="low", approvals=None):
        self.service.transition(
            self.engineer,
            self.change["id"],
            "assess",
            {"risk_level": level, "analyst": "eng-1"},
        )
        self.service.transition(
            self.safety,
            self.change["id"],
            "approve",
            {"approvals": approvals or ["safety-1"], "permit_id": "MOC-1"},
        )
        self.service.transition(
            self.engineer,
            self.change["id"],
            "implement",
            {"procedure_version": "v2"},
        )

    def test_commission_returns_concrete_blockers_and_recovery_clears_them(self):
        bypass = self._activate(self._bypass())
        item = self.service.create(
            self.safety,
            "action_item",
            {
                "change_id": self.change["id"],
                "description": "update SOP",
                "owner": "owner-1",
            },
        )
        self._implemented_change()

        blockers = self.service.commission_blockers(self.change["id"])["blockers"]
        reasons = {(b["type"], b["reason"]) for b in blockers}
        self.assertIn(("interlock_bypass", "bypass_active"), reasons)
        self.assertIn(("action_item", "action_item_unverified"), reasons)
        active_blocker = next(b for b in blockers if b["type"] == "interlock_bypass")
        self.assertEqual(active_blocker["detail"]["interlock_tag"], "I-1001")
        self.assertEqual(active_blocker["id"], bypass["id"])

        with self.assertRaises(ValidationError) as ctx:
            self.service.transition(
                self.engineer,
                self.change["id"],
                "commission",
                {"tests_passed": True},
            )
        self.assertIn(bypass["id"], str(ctx.exception))

        self.service.transition(
            self.admin,
            item["id"],
            "complete",
            {"completed_by": "owner-1", "evidence": "sop-v2"},
        )
        self.service.transition(
            Actor("v-1", "verifier"), item["id"], "verify", {"verifier": "v-1"}
        )
        with self.assertRaises(ValidationError):
            self.service.transition(
                self.engineer,
                self.change["id"],
                "commission",
                {"tests_passed": True},
            )

        recovered = self.service.transition(
            self.operator,
            bypass["id"],
            "recover",
            {"restored_by": "op-1"},
        )
        self.assertEqual(recovered["status"], "recovered")
        self.assertEqual(
            self.service.commission_blockers(self.change["id"])["blockers"], []
        )
        commissioned = self.service.transition(
            self.engineer,
            self.change["id"],
            "commission",
            {"tests_passed": True},
        )
        self.assertEqual(commissioned["status"], "commissioned")

    def test_resignoff_required_is_also_a_blocker(self):
        bypass = self._activate(self._bypass())
        self._implemented_change()
        self.service.transition(
            self.operator, self.unit["id"], "shutdown", {"reason": "repair"}
        )
        blockers = self.service.commission_blockers(self.change["id"])["blockers"]
        self.assertEqual(
            [(b["type"], b["reason"]) for b in blockers],
            [("interlock_bypass", "bypass_reconfirm_required")],
        )
        self.service.transition(
            self.safety, bypass["id"], "reconfirm", {"signoff_note": "ok"}
        )
        self.assertEqual(
            [b["reason"] for b in self.service.commission_blockers(self.change["id"])["blockers"]],
            ["bypass_active"],
        )

    def test_reject_withdraw_close_invalidate_bypass_but_keep_records(self):
        bypass = self._bypass()
        self.service.transition(
            self.safety, self.change["id"], "reject", {"reason": "out of scope"}
        )
        invalidated = self.service.get(bypass["id"])
        self.assertEqual(invalidated["status"], "invalidated")
        self.assertEqual(invalidated["data"]["invalid_reason"], "change_rejected")
        with self.assertRaises(InvalidTransition):
            self.service.transition(
                self.operator,
                bypass["id"],
                "recover",
                {"restored_by": "op-1"},
            )
        audit = self.service.audit_log(bypass["id"])
        self.assertTrue(any(row["action"] == "auto_invalidate" for row in audit))

        # Withdraw cascade on a second change.
        change2 = self.service.create(
            self.engineer,
            "change",
            {"unit_id": self.unit["id"], "description": "second"},
        )
        bypass2 = self._bypass(change_id=change2["id"])
        self._activate(bypass2)
        self.service.transition(
            self.engineer, change2["id"], "withdraw", {"reason": "cancel by owner"}
        )
        self.assertEqual(self.service.get(bypass2["id"])["status"], "invalidated")
        self.assertEqual(
            self.service.get(bypass2["id"])["data"]["invalid_reason"],
            "change_withdrawn",
        )

        # Close cascade after rollback on a third change.
        change3 = self.service.create(
            self.engineer,
            "change",
            {"unit_id": self.unit["id"], "description": "third"},
        )
        bypass3 = self._bypass(change_id=change3["id"])
        self._activate(bypass3)
        self.service.transition(
            self.engineer,
            change3["id"],
            "assess",
            {"risk_level": "low", "analyst": "eng-1"},
        )
        self.service.transition(
            self.safety,
            change3["id"],
            "approve",
            {"approvals": ["safety-1"], "permit_id": "MOC-3"},
        )
        self.service.transition(
            self.engineer,
            change3["id"],
            "implement",
            {"procedure_version": "v1"},
        )
        self.service.transition(
            self.operator,
            bypass3["id"],
            "recover",
            {"restored_by": "op-1"},
        )
        self.service.transition(
            self.engineer,
            change3["id"],
            "rollback",
            {"reason": "failed trial"},
        )
        self.service.transition(
            self.safety, change3["id"], "close", {"outcome": "rolled back safely"}
        )
        self.assertEqual(self.service.get(bypass3["id"])["status"], "recovered")

    def test_bypass_cannot_be_added_to_terminal_change(self):
        self.service.transition(
            self.safety, self.change["id"], "reject", {"reason": "no"}
        )
        with self.assertRaises(ValidationError):
            self._bypass()

    def test_deadline_expiry_auto_invalidates_and_keeps_record(self):
        bypass = self._activate(self._bypass())
        # Advance the domain clock past the recovery deadline.
        self._build_service(today=date(2026, 10, 6))
        expired = self.service.get(bypass["id"])
        self.assertEqual(expired["status"], "invalidated")
        self.assertEqual(expired["data"]["invalid_reason"], "deadline_expired")
        blockers = self.service.commission_blockers(self.change["id"])["blockers"]
        self.assertEqual(blockers[0]["reason"], "bypass_invalidated")
        audit = self.service.audit_log(bypass["id"])
        self.assertTrue(any(row["action"] == "auto_expire" for row in audit))

    def test_deadline_day_stays_active(self):
        bypass = self._activate(self._bypass())
        self._build_service(today=date(2026, 10, 5))
        self.assertEqual(self.service.get(bypass["id"])["status"], "active")

    def test_operator_can_propose_admin_can_review(self):
        bypass = self._bypass()
        active = self.service.transition(
            self.admin, bypass["id"], "review", {"review_note": "ok"}
        )
        self.assertEqual(active["status"], "active")


if __name__ == "__main__":
    unittest.main()
