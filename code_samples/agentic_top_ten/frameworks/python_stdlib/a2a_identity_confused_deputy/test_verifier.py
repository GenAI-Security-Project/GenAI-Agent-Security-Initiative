"""Tests for A2A identity binding and confused-deputy denial."""

from __future__ import annotations

import unittest

from verifier import sign_card, sign_delegation, verify_tool_call

ISSUER = b"test-issuer-key"
NOW = 1_700_000_000


def card(**overrides):
    body = {
        "agent_id": "agent-alice",
        "key_id": "key-alice",
        "audience": "files",
        "capabilities": ["files.read", "files.list"],
        "issued_at": NOW - 10,
        "expires_at": NOW + 60,
        "nonce": "nonce-card-1",
    }
    body.update(overrides)
    return sign_card(body, ISSUER)


def delegation(**overrides):
    body = {
        "subject": "agent-alice",
        "audience": "files",
        "tool": "files.read",
        "expires_at": NOW + 30,
        "nonce": "nonce-deleg-1",
    }
    body.update(overrides)
    return sign_delegation(body, ISSUER)


def decide(presented, **overrides):
    args = {
        "issuer_key": ISSUER,
        "key_bindings": {"key-alice": "agent-alice", "key-bob": "agent-bob"},
        "channel_key_id": "key-alice",
        "audience": "files",
        "tool": "files.read",
        "now": NOW,
        "seen_nonces": set(),
        "delegation": None,
    }
    args.update(overrides)
    return verify_tool_call(presented, **args)


class VerifierTest(unittest.TestCase):
    def test_bound_card_is_allowed(self) -> None:
        decision = decide(card())
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "ok")

    def test_other_channel_cannot_present_a_valid_card(self) -> None:
        decision = decide(card(), channel_key_id="key-bob")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "channel key does not match card")

    def test_card_for_another_audience_is_a_confused_deputy(self) -> None:
        presented = card(audience="payments", nonce="nonce-pay")
        decision = decide(presented)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "card audience does not match this tool server")

    def test_key_binding_rejects_mismatched_agent_id(self) -> None:
        decision = decide(card(), key_bindings={"key-alice": "agent-bob"})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "key is not bound to agent_id")

    def test_expired_card_and_replay_are_rejected(self) -> None:
        presented = card(nonce="nonce-exp")
        expired = decide(presented, now=presented["expires_at"])
        self.assertEqual(expired.reason, "card is not valid at now")
        seen: set[str] = set()
        first = decide(card(nonce="nonce-replay"), seen_nonces=seen)
        second = decide(card(nonce="nonce-replay"), seen_nonces=seen)
        self.assertTrue(first.allowed)
        self.assertEqual(second.reason, "card nonce replay")

    def test_tampered_capability_breaks_the_signature(self) -> None:
        presented = card()
        presented["capabilities"] = ["files.read", "files.write"]
        decision = decide(presented)
        self.assertEqual(decision.reason, "card signature mismatch")

    def test_tool_outside_capabilities_is_denied(self) -> None:
        decision = decide(card(nonce="nonce-tool"), tool="files.write")
        self.assertEqual(decision.reason, "tool is outside card capabilities")

    def test_delegation_subject_must_match_the_card(self) -> None:
        presented = card(nonce="nonce-deleg")
        stolen = delegation(subject="agent-bob", nonce="nonce-stolen")
        decision = decide(presented, delegation=stolen)
        self.assertEqual(decision.reason, "delegation subject does not match card agent")

    def test_matching_delegation_is_allowed_once(self) -> None:
        seen: set[str] = set()
        first = decide(card(nonce="nonce-ok-deleg"), delegation=delegation(), seen_nonces=seen)
        second = decide(
            card(nonce="nonce-ok-deleg-2"),
            delegation=delegation(),
            seen_nonces=seen,
        )
        self.assertTrue(first.allowed)
        self.assertEqual(second.reason, "delegation nonce replay")

    def test_malformed_inputs_fail_closed(self) -> None:
        self.assertEqual(decide([]).reason, "card must be an object")
        self.assertEqual(decide(card(), issuer_key=b"").reason, "verifier misconfigured")
        self.assertEqual(decide(card(), now=True).reason, "invalid now")
        bad = card()
        bad["signature"] = "0" * 64
        self.assertEqual(decide(bad).reason, "card signature mismatch")


if __name__ == "__main__":
    unittest.main()
