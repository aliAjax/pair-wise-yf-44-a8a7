import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from src.domain import (
    Actor,
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


class FrozenClock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value

    def set(self, value):
        self.value = value


def bypass_steps(service, deadline, risk_level="medium", approvals=None, owner="O-1"):
    """创建 装置+变更，并走到 implemented，再提交并复核通过一个旁路。"""
    unit = service.create(
        Actor("admin", "admin"), "unit", {"name": "Reactor-1", "location": "Plant-A"}
    )
    change = service.create(
        Actor("eng", "engineer"),
        "change",
        {"unit_id": unit["id"], "description": "alter trip logic"},
    )
    service.transition(
        Actor("eng", "engineer"),
        change["id"],
        "assess",
        {"risk_level": risk_level, "analyst": "E-1"},
    )
    service.transition(
        Actor("safe", "safety"),
        change["id"],
        "approve",
        {"approvals": approvals or ["S-1", "S-2"], "permit_id": "MOC-1"},
    )
    service.transition(
        Actor("eng", "engineer"),
        change["id"],
        "implement",
        {"procedure_version": "v2"},
    )
    bypass = service.create(
        Actor("op", "operator"),
        "interlock_bypass",
        {
            "unit_id": unit["id"],
            "change_id": change["id"],
            "interlock_tag": "PSHH-101",
            "restore_deadline": deadline,
            "restore_owner": owner,
            "reason": "replace sensor",
        },
    )
    return unit, change, bypass


class InterlockBypassTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = FrozenClock(datetime(2026, 10, 1, 9, 0, 0))
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(self.repo, RuleEngine(self.clock))

    def tearDown(self):
        self.tmp.cleanup()

    def _approve(self, bypass):
        return self.service.transition(
            Actor("safe", "safety"),
            bypass["id"],
            "approve_bypass",
            {"risk_review": "compensating watch in place"},
        )

    def test_operator_request_requires_safety_review_before_active(self):
        unit, change, bypass = bypass_steps(self.service, "2026-10-10")
        self.assertEqual(bypass["status"], "pending_review")
        # 工程师无权复核
        with self.assertRaises(PermissionDenied):
            self.service.transition(
                Actor("eng", "engineer"),
                bypass["id"],
                "approve_bypass",
                {"risk_review": "x"},
            )
        active = self._approve(bypass)
        self.assertEqual(active["status"], "active")
        self.assertEqual(active["data"]["risk_level_at_bypass"], "medium")

    def test_viewer_cannot_request_bypass(self):
        unit, change, _ = bypass_steps(self.service, "2026-10-10")
        with self.assertRaises(PermissionDenied):
            self.service.create(
                Actor("v", "viewer"),
                "interlock_bypass",
                {
                    "unit_id": unit["id"],
                    "change_id": change["id"],
                    "interlock_tag": "PSHH-101",
                    "restore_deadline": "2026-10-10",
                    "restore_owner": "O-1",
                },
            )

    def test_bypass_requires_fields_and_future_deadline(self):
        unit, change, _ = bypass_steps(self.service, "2026-10-10")
        base = {
            "unit_id": unit["id"],
            "change_id": change["id"],
            "interlock_tag": "PSHH-102",
            "restore_deadline": "2026-10-10",
            "restore_owner": "O-1",
        }
        for missing in ("unit_id", "change_id", "interlock_tag", "restore_deadline", "restore_owner"):
            payload = dict(base)
            payload.pop(missing)
            with self.assertRaises(ValidationError):
                self.service.create(Actor("op", "operator"), "interlock_bypass", payload)
        payload = dict(base, restore_deadline="2026-09-01")  # 过去的恢复期限
        with self.assertRaises(ValidationError):
            self.service.create(Actor("op", "operator"), "interlock_bypass", payload)
        payload = dict(base, restore_deadline="not-a-date")
        with self.assertRaises(ValidationError):
            self.service.create(Actor("op", "operator"), "interlock_bypass", payload)

    def test_duplicate_open_bypass_for_same_tag_rejected(self):
        unit, change, bypass = bypass_steps(self.service, "2026-10-10")
        self._approve(bypass)
        payload = {
            "unit_id": unit["id"],
            "change_id": change["id"],
            "interlock_tag": "PSHH-101",
            "restore_deadline": "2026-10-12",
            "restore_owner": "O-2",
        }
        with self.assertRaises(ConflictError):
            self.service.create(Actor("op2", "operator"), "interlock_bypass", payload)

    def test_safety_can_reject_request(self):
        unit, change, bypass = bypass_steps(self.service, "2026-10-10")
        rejected = self.service.transition(
            Actor("safe", "safety"),
            bypass["id"],
            "reject_bypass",
            {"reason": "no compensating measure"},
        )
        self.assertEqual(rejected["status"], "rejected")
        # 被拒绝的旁路不阻塞投产
        blockers = self.service.commission_blockers(change["id"])
        self.assertFalse(blockers["blocked"])

    def test_risk_upgrade_requires_reconfirmation(self):
        unit, change, bypass = bypass_steps(self.service, "2026-10-10")
        self._approve(bypass)
        # 同级或更低不算升级
        with self.assertRaises(ValidationError):
            self.service.transition(
                Actor("op", "operator"),
                bypass["id"],
                "report_event",
                {"resign_reason": "risk_upgraded", "new_risk_level": "medium"},
            )
        pending = self.service.transition(
            Actor("op", "operator"),
            bypass["id"],
            "report_event",
            {"resign_reason": "risk_upgraded", "new_risk_level": "critical"},
        )
        self.assertEqual(pending["status"], "pending_resign")
        # 未重新签认不能恢复
        with self.assertRaises(InvalidTransition):
            self.service.transition(
                Actor("op", "operator"),
                bypass["id"],
                "recover",
                {"evidence": "loop test ok"},
            )
        # 操作员不能自己签认
        with self.assertRaises(PermissionDenied):
            self.service.transition(
                Actor("op", "operator"),
                bypass["id"],
                "resign",
                {"risk_review": "ok"},
            )
        active = self.service.transition(
            Actor("safe", "safety"),
            bypass["id"],
            "resign",
            {"risk_review": "extra mitigation added"},
        )
        self.assertEqual(active["status"], "active")
        self.assertEqual(len(active["data"]["resign_history"]), 1)
        self.assertEqual(active["data"]["last_reconfirmed_by"], "safe")

    def test_owner_change_requires_reconfirmation(self):
        unit, change, bypass = bypass_steps(self.service, "2026-10-10")
        self._approve(bypass)
        pending = self.service.transition(
            Actor("op", "operator"),
            bypass["id"],
            "change_owner",
            {"new_owner": "O-9"},
        )
        self.assertEqual(pending["status"], "pending_resign")
        self.assertEqual(pending["data"]["resign_reason"], "owner_changed")
        self.assertEqual(pending["data"]["restore_owner"], "O-9")
        # 待重新签认期间不能再次更换责任人，必须先签认
        with self.assertRaises(InvalidTransition):
            self.service.transition(
                Actor("op", "operator"),
                bypass["id"],
                "change_owner",
                {"new_owner": "O-10"},
            )
        self.service.transition(
            Actor("safe", "safety"),
            bypass["id"],
            "resign",
            {"risk_review": "new owner briefed"},
        )
        recovered = self.service.transition(
            Actor("op", "operator"),
            bypass["id"],
            "recover",
            {"evidence": "function test passed"},
        )
        self.assertEqual(recovered["status"], "recovered")
        self.assertEqual(recovered["data"]["recovered_by"], "op")
        # 记录仍可读取
        self.assertEqual(recovered["data"]["interlock_tag"], "PSHH-101")

    def test_unit_shutdown_auto_flags_active_bypass(self):
        unit, change, bypass = bypass_steps(self.service, "2026-10-10")
        self._approve(bypass)
        self.service.transition(
            Actor("op", "operator"), unit["id"], "shutdown", {"reason": "maintenance"}
        )
        flagged = self.service.get(bypass["id"])
        self.assertEqual(flagged["status"], "pending_resign")
        self.assertEqual(flagged["data"]["resign_reason"], "unit_shutdown")

    def test_deadline_expires_bypass_lazily(self):
        unit, change, bypass = bypass_steps(self.service, "2026-10-10")
        self._approve(bypass)
        # 期限当天仍有效
        self.clock.set(datetime(2026, 10, 10, 23, 0, 0))
        self.service.sweep_expired_bypasses()
        self.assertEqual(self.service.get(bypass["id"])["status"], "active")
        # 次日懒失效
        self.clock.set(datetime(2026, 10, 11, 8, 0, 0))
        swept = self.service.sweep_expired_bypasses()
        self.assertEqual(len(swept), 1)
        self.assertEqual(swept[0]["status"], "expired")
        # 到期未恢复仍可补恢复，记录保留
        recovered = self.service.transition(
            Actor("op", "operator"),
            bypass["id"],
            "recover",
            {"evidence": "late restore"},
        )
        self.assertEqual(recovered["status"], "recovered")

    def test_pending_review_bypass_also_expires(self):
        unit, change, bypass = bypass_steps(self.service, "2026-10-10")
        self.clock.set(datetime(2026, 10, 11, 8, 0, 0))
        self.service.sweep_expired_bypasses()
        self.assertEqual(self.service.get(bypass["id"])["status"], "expired")

    def test_change_rejected_voids_bypass_and_keeps_record(self):
        unit = self.service.create(
            Actor("admin", "admin"), "unit", {"name": "U", "location": "L"}
        )
        change = self.service.create(
            Actor("eng", "engineer"),
            "change",
            {"unit_id": unit["id"], "description": "d"},
        )
        self.service.transition(
            Actor("eng", "engineer"),
            change["id"],
            "assess",
            {"risk_level": "low", "analyst": "E-1"},
        )
        bypass = self.service.create(
            Actor("op", "operator"),
            "interlock_bypass",
            {
                "unit_id": unit["id"],
                "change_id": change["id"],
                "interlock_tag": "LSL-2",
                "restore_deadline": "2026-10-10",
                "restore_owner": "O-1",
            },
        )
        self._approve(bypass)
        self.service.transition(
            Actor("safe", "safety"), change["id"], "reject", {"reason": "unsafe"}
        )
        self.assertEqual(self.service.get(bypass["id"])["status"], "auto_invalidated")
        self.assertEqual(self.service.get(change["id"])["status"], "rejected")

    def test_change_withdrawn_and_closed_void_bypass(self):
        unit = self.service.create(
            Actor("admin", "admin"), "unit", {"name": "U2", "location": "L"}
        )
        change = self.service.create(
            Actor("eng", "engineer"),
            "change",
            {"unit_id": unit["id"], "description": "d2"},
        )
        self.service.transition(
            Actor("eng", "engineer"),
            change["id"],
            "assess",
            {"risk_level": "low", "analyst": "E-1"},
        )
        bypass = self.service.create(
            Actor("op", "operator"),
            "interlock_bypass",
            {
                "unit_id": unit["id"],
                "change_id": change["id"],
                "interlock_tag": "LSL-3",
                "restore_deadline": "2026-10-10",
                "restore_owner": "O-1",
            },
        )
        self._approve(bypass)
        # 实施前撤回（draft/assessed/approved），旁路自动失效
        self.service.transition(
            Actor("eng", "engineer"), change["id"], "withdraw", {"reason": "scope cut"}
        )
        self.assertEqual(self.service.get(bypass["id"])["status"], "auto_invalidated")
        self.assertEqual(self.service.get(change["id"])["status"], "withdrawn")

        # 另一条变更走关闭：rollback -> close
        unit2, change2, bypass2 = bypass_steps(
            self.service, "2026-10-20", risk_level="low", approvals=["S-1"]
        )
        self._approve(bypass2)
        self.service.transition(
            Actor("eng", "engineer"),
            change2["id"],
            "rollback",
            {"reason": "drift"},
        )
        self.service.transition(
            Actor("safe", "safety"), change2["id"], "close", {"outcome": "abandoned"}
        )
        self.assertEqual(self.service.get(bypass2["id"])["status"], "auto_invalidated")

    def test_commission_blocked_with_specific_items(self):
        unit, change, bypass = bypass_steps(self.service, "2026-10-10")
        self._approve(bypass)
        item = self.service.create(
            Actor("safe", "safety"),
            "action_item",
            {"change_id": change["id"], "description": "train crew", "owner": "O-1"},
        )
        report = self.service.commission_blockers(change["id"])
        self.assertTrue(report["blocked"])
        reasons = [block["reason"] for block in report["blockers"]]
        self.assertTrue(any("PSHH-101" in reason and "active" in reason for reason in reasons))
        self.assertTrue(any(item["id"] in reason for reason in reasons))

        with self.assertRaises(ValidationError) as ctx:
            self.service.transition(
                Actor("eng", "engineer"),
                change["id"],
                "commission",
                {"tests_passed": True},
            )
        self.assertIn("PSHH-101", str(ctx.exception))

        # 行动项闭环后仍被旁路阻塞
        self.service.transition(
            Actor("eng", "engineer"),
            item["id"],
            "complete",
            {"completed_by": "O-1", "evidence": "log"},
        )
        self.service.transition(
            Actor("v", "verifier"), item["id"], "verify", {"verifier": "V-1"}
        )
        report = self.service.commission_blockers(change["id"])
        self.assertTrue(report["blocked"])
        self.assertEqual(len(report["blockers"]), 1)

        # 恢复旁路后放行投产
        self.service.transition(
            Actor("op", "operator"),
            bypass["id"],
            "recover",
            {"evidence": "ok"},
        )
        report = self.service.commission_blockers(change["id"])
        self.assertFalse(report["blocked"])
        commissioned = self.service.transition(
            Actor("eng", "engineer"),
            change["id"],
            "commission",
            {"tests_passed": True},
        )
        self.assertEqual(commissioned["status"], "commissioned")

    def test_expired_and_pending_resign_are_listed_as_blockers(self):
        unit, change, bypass = bypass_steps(self.service, "2026-10-10")
        self._approve(bypass)
        self.clock.set(datetime(2026, 10, 11, 8, 0, 0))
        report = self.service.commission_blockers(change["id"])
        self.assertTrue(report["blocked"])
        self.assertIn("expired", report["blockers"][0]["reason"])

        unit2, change2, bypass2 = bypass_steps(
            self.service, "2026-10-20", risk_level="low", approvals=["S-1"]
        )
        self._approve(bypass2)
        self.service.transition(
            Actor("op", "operator"),
            bypass2["id"],
            "report_event",
            {"resign_reason": "risk_upgraded", "new_risk_level": "high"},
        )
        report = self.service.commission_blockers(change2["id"])
        self.assertIn("re-confirmation", report["blockers"][0]["reason"])

    def test_audit_trail_records_lifecycle(self):
        unit, change, bypass = bypass_steps(self.service, "2026-10-10")
        self._approve(bypass)
        self.service.transition(
            Actor("op", "operator"),
            bypass["id"],
            "recover",
            {"evidence": "ok"},
        )
        actions = [row["action"] for row in self.service.audit_log(bypass["id"])]
        self.assertEqual(
            actions, ["create", "approve_bypass", "recover"]
        )


if __name__ == "__main__":
    unittest.main()
