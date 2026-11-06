"""A2A agent-card identity binding and confused-deputy verifier.

A tool server must not honor a call because some other party presented a
still-valid card. The card has to be signed, unexpired, unused, bound to the
key authenticated on this channel, bound to the claimed agent id, and minted
for this server's audience. A delegation, when presented, has to name that
same agent, audience, and tool.

This is a reference control, not a vulnerable sample. It uses only the
Python standard library.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_UNIX = 4_000_000_000


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def deny(reason: str) -> Decision:
    return Decision(False, reason)


def allow() -> Decision:
    return Decision(True, "ok")


def _id(value: object) -> str | None:
    if isinstance(value, str) and _ID_RE.fullmatch(value):
        return value
    return None


def _unix(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0 or value > _MAX_UNIX:
        return None
    return value


def _capabilities(value: object) -> list[str] | None:
    if not isinstance(value, list) or not value:
        return None
    names = []
    for item in value:
        parsed = _id(item)
        if parsed is None:
            return None
        names.append(parsed)
    if len(set(names)) != len(names):
        return None
    return sorted(names)


def canonical_card(card: dict) -> bytes:
    payload = {
        "v": 1,
        "agent_id": card["agent_id"],
        "key_id": card["key_id"],
        "audience": card["audience"],
        "capabilities": card["capabilities"],
        "issued_at": card["issued_at"],
        "expires_at": card["expires_at"],
        "nonce": card["nonce"],
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def canonical_delegation(delegation: dict) -> bytes:
    payload = {
        "v": 1,
        "subject": delegation["subject"],
        "audience": delegation["audience"],
        "tool": delegation["tool"],
        "expires_at": delegation["expires_at"],
        "nonce": delegation["nonce"],
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sign(payload: bytes, issuer_key: bytes) -> str:
    return hmac.new(issuer_key, payload, hashlib.sha256).hexdigest()


def sign_card(card: dict, issuer_key: bytes) -> dict:
    """Return a copy of ``card`` with a canonical capability list and signature."""
    if not isinstance(issuer_key, bytes) or not issuer_key:
        raise ValueError("issuer_key must be non-empty bytes")
    capabilities = _capabilities(card.get("capabilities"))
    if capabilities is None:
        raise ValueError("capabilities must be a non-empty list of unique ids")
    signed = {
        "agent_id": card["agent_id"],
        "key_id": card["key_id"],
        "audience": card["audience"],
        "capabilities": capabilities,
        "issued_at": card["issued_at"],
        "expires_at": card["expires_at"],
        "nonce": card["nonce"],
    }
    signed["signature"] = _sign(canonical_card(signed), issuer_key)
    return signed


def sign_delegation(delegation: dict, issuer_key: bytes) -> dict:
    if not isinstance(issuer_key, bytes) or not issuer_key:
        raise ValueError("issuer_key must be non-empty bytes")
    signed = {
        "subject": delegation["subject"],
        "audience": delegation["audience"],
        "tool": delegation["tool"],
        "expires_at": delegation["expires_at"],
        "nonce": delegation["nonce"],
    }
    signed["signature"] = _sign(canonical_delegation(signed), issuer_key)
    return signed


def _signature_ok(payload: bytes, signature: object, issuer_key: bytes) -> bool:
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
        return False
    expected = _sign(payload, issuer_key)
    return hmac.compare_digest(expected, signature)


def verify_tool_call(
    card: object,
    *,
    issuer_key: bytes,
    key_bindings: dict[str, str],
    channel_key_id: str,
    audience: str,
    tool: str,
    now: int,
    seen_nonces: set[str],
    delegation: object | None = None,
) -> Decision:
    """Fail closed. Nonces are consumed only after the matching signature verifies."""
    if not isinstance(issuer_key, bytes) or not issuer_key:
        return deny("verifier misconfigured")
    if not isinstance(key_bindings, dict) or not isinstance(seen_nonces, set):
        return deny("verifier misconfigured")
    if _unix(now) is None:
        return deny("invalid now")
    if _id(channel_key_id) is None or _id(audience) is None or _id(tool) is None:
        return deny("invalid verifier audience or tool")
    if not isinstance(card, dict):
        return deny("card must be an object")

    agent_id = _id(card.get("agent_id"))
    key_id = _id(card.get("key_id"))
    card_audience = _id(card.get("audience"))
    nonce = _id(card.get("nonce"))
    capabilities = _capabilities(card.get("capabilities"))
    issued_at = _unix(card.get("issued_at"))
    expires_at = _unix(card.get("expires_at"))
    if None in (agent_id, key_id, card_audience, nonce, capabilities, issued_at, expires_at):
        return deny("card fields are missing or invalid")
    if issued_at > expires_at:
        return deny("card validity window is inverted")

    canonical = {
        "agent_id": agent_id,
        "key_id": key_id,
        "audience": card_audience,
        "capabilities": capabilities,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce,
    }
    if not _signature_ok(canonical_card(canonical), card.get("signature"), issuer_key):
        return deny("card signature mismatch")
    if nonce in seen_nonces:
        return deny("card nonce replay")
    seen_nonces.add(nonce)

    if now < issued_at or now >= expires_at:
        return deny("card is not valid at now")
    if channel_key_id != key_id:
        return deny("channel key does not match card")
    bound_agent = key_bindings.get(key_id)
    if not isinstance(bound_agent, str) or bound_agent != agent_id:
        return deny("key is not bound to agent_id")
    if card_audience != audience:
        return deny("card audience does not match this tool server")
    if tool not in capabilities:
        return deny("tool is outside card capabilities")

    if delegation is None:
        return allow()
    if not isinstance(delegation, dict):
        return deny("delegation must be an object")
    subject = _id(delegation.get("subject"))
    deleg_audience = _id(delegation.get("audience"))
    deleg_tool = _id(delegation.get("tool"))
    deleg_nonce = _id(delegation.get("nonce"))
    deleg_exp = _unix(delegation.get("expires_at"))
    if None in (subject, deleg_audience, deleg_tool, deleg_nonce, deleg_exp):
        return deny("delegation fields are missing or invalid")
    deleg_canonical = {
        "subject": subject,
        "audience": deleg_audience,
        "tool": deleg_tool,
        "expires_at": deleg_exp,
        "nonce": deleg_nonce,
    }
    if not _signature_ok(
        canonical_delegation(deleg_canonical), delegation.get("signature"), issuer_key
    ):
        return deny("delegation signature mismatch")
    if deleg_nonce in seen_nonces:
        return deny("delegation nonce replay")
    seen_nonces.add(deleg_nonce)
    if now >= deleg_exp:
        return deny("delegation is expired")
    if subject != agent_id:
        return deny("delegation subject does not match card agent")
    if deleg_audience != audience or deleg_tool != tool:
        return deny("delegation does not authorize this call")
    return allow()
