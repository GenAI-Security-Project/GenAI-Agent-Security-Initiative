"""Demonstrate A2A identity spoofing and confused-deputy denials."""

from __future__ import annotations

from verifier import sign_card, verify_tool_call

ISSUER = b"demo-issuer-key"
NOW = 1_700_000_000
BINDINGS = {"key-alice": "agent-alice", "key-mallory": "agent-mallory"}


def _card(audience: str, nonce: str) -> dict:
    return sign_card(
        {
            "agent_id": "agent-alice",
            "key_id": "key-alice",
            "audience": audience,
            "capabilities": ["files.read"],
            "issued_at": NOW - 5,
            "expires_at": NOW + 60,
            "nonce": nonce,
        },
        ISSUER,
    )


def main() -> int:
    seen: set[str] = set()
    allowed = verify_tool_call(
        _card("files", "nonce-allow"),
        issuer_key=ISSUER,
        key_bindings=BINDINGS,
        channel_key_id="key-alice",
        audience="files",
        tool="files.read",
        now=NOW,
        seen_nonces=seen,
    )
    spoofed = verify_tool_call(
        _card("files", "nonce-spoof"),
        issuer_key=ISSUER,
        key_bindings=BINDINGS,
        channel_key_id="key-mallory",
        audience="files",
        tool="files.read",
        now=NOW,
        seen_nonces=seen,
    )
    deputy = verify_tool_call(
        _card("payments", "nonce-deputy"),
        issuer_key=ISSUER,
        key_bindings=BINDINGS,
        channel_key_id="key-alice",
        audience="files",
        tool="files.read",
        now=NOW,
        seen_nonces=seen,
    )
    print(f"bound call: {allowed.reason}")
    print(f"spoofed channel: {spoofed.reason}")
    print(f"wrong audience: {deputy.reason}")
    if not allowed.allowed or spoofed.allowed or deputy.allowed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
