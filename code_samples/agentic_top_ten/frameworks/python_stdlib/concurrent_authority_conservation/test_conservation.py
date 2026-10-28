"""Unit tests for ASI03 Concurrent Delegated-Authority Conservation (DA-01..DA-06)."""

from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor

from main import AuthorityViolationError, DelegationLedger, run_demo


class TestConcurrentAuthorityConservation(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = DelegationLedger(
            secret=b"test-secret-key",
            origin_ceiling=frozenset({"payments.refund", "orders.read", "email.send"}),
            origin_max_budget=100,
        )
        self.root = self.ledger.issue_root_grant(
            grant_id="root",
            principal="human:alice",
            delegatee="agent:orchestrator",
            capabilities={"payments.refund", "orders.read"},
            budget=100,
            expires_at=500.0,
        )

    def test_da01_origin_non_escalation(self) -> None:
        with self.assertRaises(AuthorityViolationError) as ctx:
            self.ledger.issue_root_grant(
                grant_id="root-bad",
                principal="human:alice",
                delegatee="agent:rogue",
                capabilities={"admin.drop_db"},
                budget=50,
                expires_at=500.0,
            )
        self.assertEqual(ctx.exception.invariant, "DA-01")

    def test_da02_monotonic_attenuation_enforced(self) -> None:
        with self.assertRaises(AuthorityViolationError) as ctx:
            self.ledger.delegate(
                parent_id="root",
                grant_id="child-escalated",
                delegatee="agent:worker",
                capabilities={"payments.refund", "email.send"},
                budget=50,
                expires_at=400.0,
                now=100.0,
            )
        self.assertEqual(ctx.exception.invariant, "DA-02")

        with self.assertRaises(AuthorityViolationError) as ctx_exp:
            self.ledger.delegate(
                parent_id="root",
                grant_id="child-late",
                delegatee="agent:worker",
                capabilities={"orders.read"},
                budget=50,
                expires_at=600.0,
                now=100.0,
            )
        self.assertEqual(ctx_exp.exception.invariant, "DA-02")

    def test_da03_transitive_revocation_cascade_blocks_grandchild_at_commit(self) -> None:
        self.ledger.delegate(
            parent_id="root",
            grant_id="child-1",
            delegatee="agent:planner",
            capabilities={"payments.refund"},
            budget=60,
            expires_at=400.0,
            now=100.0,
        )
        self.ledger.delegate(
            parent_id="child-1",
            grant_id="grandchild-1",
            delegatee="agent:executor",
            capabilities={"payments.refund"},
            budget=30,
            expires_at=300.0,
            now=110.0,
        )
        revoked = self.ledger.revoke("child-1")
        self.assertEqual(set(revoked), {"child-1", "grandchild-1"})

        with self.assertRaises(AuthorityViolationError) as ctx:
            self.ledger.commit_action(
                grant_id="grandchild-1",
                capability="payments.refund",
                cost=10,
                now=120.0,
            )
        self.assertEqual(ctx.exception.invariant, "DA-03")

    def test_da04_concurrent_sibling_budget_conservation(self) -> None:
        """16 concurrent workers requesting 20 each from a 100 budget never exceed 100."""

        def attempt(idx: int) -> int:
            try:
                child = self.ledger.delegate(
                    parent_id="root",
                    grant_id=f"sub-{idx}",
                    delegatee=f"agent:sub-{idx}",
                    capabilities={"payments.refund"},
                    budget=20,
                    expires_at=400.0,
                    now=100.0,
                )
                result = self.ledger.commit_action(
                    grant_id=child.grant_id,
                    capability="payments.refund",
                    cost=20,
                    now=105.0,
                )
                return int(result["cost"])
            except AuthorityViolationError as exc:
                self.assertEqual(exc.invariant, "DA-04")
                return 0

        with ThreadPoolExecutor(max_workers=16) as pool:
            spends = list(pool.map(attempt, range(16)))

        self.assertEqual(sum(spends), 100)
        self.assertEqual(spends.count(20), 5)
        self.assertEqual(spends.count(0), 11)

    def test_da05_commit_point_expiry_and_capability_reverification(self) -> None:
        self.ledger.delegate(
            parent_id="root",
            grant_id="child-exp",
            delegatee="agent:worker",
            capabilities={"orders.read"},
            budget=20,
            expires_at=200.0,
            now=100.0,
        )
        with self.assertRaises(AuthorityViolationError) as ctx_exp:
            self.ledger.commit_action(
                grant_id="child-exp",
                capability="orders.read",
                cost=5,
                now=250.0,
            )
        self.assertEqual(ctx_exp.exception.invariant, "DA-05")

    def test_da06_cryptographic_lineage_tamper_detected(self) -> None:
        child = self.ledger.delegate(
            parent_id="root",
            grant_id="child-tamper",
            delegatee="agent:worker",
            capabilities={"orders.read"},
            budget=20,
            expires_at=300.0,
            now=100.0,
        )
        # Simulate in-memory tampering with budget after issuance
        child.budget = 90
        with self.assertRaises(AuthorityViolationError) as ctx:
            self.ledger.commit_action(
                grant_id="child-tamper",
                capability="orders.read",
                cost=10,
                now=110.0,
            )
        self.assertEqual(ctx.exception.invariant, "DA-06")

    def test_run_demo_contrasts_insecure_and_hardened_fan_out(self) -> None:
        summary = run_demo()
        self.assertEqual(summary["parent_budget"], 100)
        self.assertEqual(summary["insecure_concurrent_spend"], 200)
        self.assertEqual(summary["hardened_concurrent_spend"], 80)
        self.assertEqual(summary["hardened_approved_workers"], 2)
        self.assertEqual(summary["hardened_rejected_workers"], 3)


if __name__ == "__main__":
    unittest.main()
