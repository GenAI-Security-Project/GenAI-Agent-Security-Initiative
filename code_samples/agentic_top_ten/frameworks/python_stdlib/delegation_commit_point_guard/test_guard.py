"""Unit tests for the ASI03 & ASI09 delegation and commit-point guard sample."""

from __future__ import annotations

import unittest

from main import args_digest, evaluate_call, evaluate_delegation, run_demo


class DelegationCommitPointGuardTests(unittest.TestCase):
    def test_demo_shows_insecure_allows_and_mitigated_blocks(self) -> None:
        summary = run_demo()
        self.assertTrue(summary["asi03_hop_scope_restoration"]["insecure_allowed"])
        self.assertFalse(summary["asi03_hop_scope_restoration"]["mitigated_allowed"])
        self.assertIn(
            "tool_in_scope",
            summary["asi03_hop_scope_restoration"]["mitigated_failed_checks"],
        )

        self.assertTrue(summary["asi09_commit_point_argument_mutation"]["insecure_allowed"])
        self.assertFalse(summary["asi09_commit_point_argument_mutation"]["mitigated_allowed"])
        self.assertIn(
            "approval_args_bound",
            summary["asi09_commit_point_argument_mutation"]["mitigated_failed_checks"],
        )

    def test_widened_child_grant_is_rejected(self) -> None:
        root = {
            "grant_id": "g0",
            "issuer": "control-plane",
            "hop": 0,
            "max_hop": 2,
            "tools": ["read_document"],
            "resources": ["workspace/docs/*"],
            "purpose": "summarize_document",
            "policy_epoch": "e1",
            "issued_at": 10,
            "expires_at": 100,
        }
        widened_child = {
            "grant_id": "g1",
            "issuer": "control-plane",
            "parent_grant_id": "g0",
            "hop": 1,
            "max_hop": 1,
            "tools": ["read_document", "send_email"],
            "resources": ["workspace/docs/a.md"],
            "purpose": "summarize_document",
            "policy_epoch": "e1",
            "issued_at": 20,
            "expires_at": 80,
        }
        res = evaluate_delegation(root, widened_child, trusted_issuers={"control-plane"})
        self.assertFalse(res.allowed)
        self.assertIn("tools_attenuated", res.failed)

    def test_replayed_approval_is_denied(self) -> None:
        now = 100
        args = {"to": "owner@example.invalid", "body": "ok"}
        root = {
            "grant_id": "g0",
            "issuer": "control-plane",
            "hop": 0,
            "max_hop": 1,
            "tools": ["send_email"],
            "resources": ["owner@example.invalid"],
            "purpose": "notify",
            "policy_epoch": "e1",
            "issued_at": 50,
            "expires_at": 200,
        }
        approval = {
            "approval_id": "a1",
            "trusted": True,
            "source_trust": "trusted",
            "action": "send_email",
            "decision": "approved",
            "target": "owner@example.invalid",
            "args_digest": args_digest(args),
            "grant_id": "g0",
            "purpose": "notify",
            "policy_epoch": "e1",
            "state_epoch": "s1",
            "issued_at": 90,
            "expires_at": 150,
            "consumed": False,
        }
        call = {
            "grant_id": "g0",
            "tool": "send_email",
            "target": "owner@example.invalid",
            "arguments": args,
            "purpose": "notify",
            "instruction_trust": "trusted_user",
            "state_epoch": "s1",
            "approval_id": "a1",
        }
        first = evaluate_call(
            call, grants=[root], approvals=[approval], policy_epoch="e1", state_epoch="s1", now=now
        )
        self.assertTrue(first.allowed)
        second = evaluate_call(
            call,
            grants=[root],
            approvals=[approval],
            policy_epoch="e1",
            state_epoch="s1",
            now=now,
            consumed_approval_ids={"a1"},
        )
        self.assertFalse(second.allowed)
        self.assertIn("approval_single_use", second.failed)


if __name__ == "__main__":
    unittest.main()
