"""ASI08/ASI10: shared budgets, retry dampening, drift monitoring, and revocation."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import threading
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, replace
from typing import Callable


class Denied(PermissionError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


@dataclass(frozen=True)
class Token:
    token_id: str
    agent: str
    parent: str | None
    scope: tuple[str, ...]
    purpose: str
    target: str
    expires_at: float
    epoch: int
    signature: str = ""


@dataclass(frozen=True)
class KillCommand:
    agent: str
    epoch: int
    expires_at: float
    nonce: str
    signature: str = ""


@dataclass(frozen=True)
class Operation:
    tool: str
    target: str
    purpose: str
    payload: str
    idempotency: str


def unsigned(record: Token | KillCommand) -> dict:
    result = asdict(record)
    result.pop("signature")
    return result


class ControlAuthority:
    """Issuance and kill methods belong to the trusted out-of-band harness."""

    def __init__(self, key: bytes, clock: Callable[[], float]) -> None:
        if len(key) < 32:
            raise ValueError("control key must contain at least 32 bytes")
        self.__key = key
        self.clock = clock

    def _mac(self, record: Token | KillCommand) -> str:
        message = type(record).__name__.encode() + b":" + canonical(unsigned(record))
        return hmac.new(self.__key, message, hashlib.sha256).hexdigest()

    def verify(self, record: Token | KillCommand) -> bool:
        return hmac.compare_digest(self._mac(record), record.signature)

    def grant(self, agent: str, scope: tuple[str, ...], *, parent: str | None = None,
              purpose: str = "summarize", target: str = "mock://workspace",
              expires_at: float = 1300.0, epoch: int = 1) -> Token:
        token = Token(secrets.token_hex(16), agent, parent, tuple(sorted(set(scope))),
                      purpose, target, expires_at, epoch)
        return replace(token, signature=self._mac(token))

    def kill(self, agent: str, *, epoch: int = 1, ttl: float = 30) -> KillCommand:
        if not math.isfinite(ttl) or not 0 < ttl <= 60:
            raise Denied("kill command validity must be bounded")
        command = KillCommand(agent, epoch, self.clock() + ttl, secrets.token_hex(16))
        return replace(command, signature=self._mac(command))


class SwarmBreaker:
    def __init__(self, verify: Callable[[Token | KillCommand], bool],
                 clock: Callable[[], float], *, effect_budget: int = 8,
                 attempt_budget: int = 24, fanout: int = 2, max_hops: int = 3,
                 retries: int = 3, error_limit: int = 3) -> None:
        if any(type(v) is not int or v < 1 for v in
               (effect_budget, attempt_budget, fanout, max_hops, retries, error_limit)):
            raise ValueError("all runtime budgets must be positive integers")
        self.verify, self.clock = verify, clock
        self.effect_budget, self.attempt_budget = effect_budget, attempt_budget
        self.fanout, self.max_hops = fanout, max_hops
        self.retries, self.error_limit = retries, error_limit
        self.epoch = 1
        self._tokens: dict[str, Token] = {}
        self._agents: dict[str, str] = {}
        self._children: dict[str, set[str]] = defaultdict(set)
        self._revoked: set[str] = set()
        self._circuits: set[str] = set()
        self._kill_nonces: set[str] = set()
        self._attempts = 0
        self._retry_counts: dict[tuple[str, str], int] = defaultdict(int)
        self._errors: dict[str, int] = defaultdict(int)
        self._cooldown: dict[str, float] = defaultdict(float)
        self._faults: dict[str, int] = defaultdict(int)
        self._behavior: dict[str, deque[tuple[bool, bool]]] = defaultdict(
            lambda: deque(maxlen=4))
        self._idempotency: dict[str, tuple[str, bool]] = {}
        self._effects: list[tuple[str, Operation]] = []
        self._lock = threading.RLock()

    def _chain(self, token: Token, *, check_cooldown: bool = True) -> list[Token]:
        chain, seen = [], set()
        current = token
        now = self.clock()
        while True:
            if (current.token_id in seen or not self.verify(current)
                    or self._tokens.get(current.token_id) != current
                    or current.token_id in self._revoked or current.token_id in self._circuits
                    or current.epoch != self.epoch or now >= current.expires_at):
                raise Denied("unknown, expired, tampered, revoked, or open-circuit lineage")
            if check_cooldown and now < self._cooldown[current.token_id]:
                raise Denied("per-hop retry cooldown active")
            seen.add(current.token_id)
            chain.append(current)
            if current.parent is None:
                return chain
            parent = self._tokens.get(current.parent)
            if parent is None:
                raise Denied("missing delegation parent")
            current = parent

    def register(self, token: Token) -> None:
        with self._lock:
            if (not self.verify(token) or token.token_id in self._tokens
                    or not token.agent or token.epoch != self.epoch
                    or not math.isfinite(token.expires_at)
                    or not self.clock() < token.expires_at <= self.clock() + 300
                    or not token.scope or not set(token.scope) <= {"summarize", "save_draft"}
                    or token.target != "mock://workspace" or token.purpose != "summarize"):
                raise Denied("invalid token registration")
            if token.parent is not None:
                parent = self._tokens.get(token.parent)
                if parent is None:
                    raise Denied("missing delegation parent")
                ancestors = self._chain(parent)
                if (token.agent in {ancestor.agent for ancestor in ancestors}
                        or len(ancestors) > self.max_hops
                        or len(self._children[parent.token_id]) >= self.fanout):
                    self._circuits.add(parent.token_id)
                    raise Denied("cycle, hop, or fan-out circuit breaker")
                if (not set(token.scope) <= set(parent.scope)
                        or token.expires_at > parent.expires_at
                        or token.purpose != parent.purpose or token.target != parent.target):
                    raise Denied("delegated token must attenuate its parent")
            if token.agent in self._agents:
                raise Denied("peer identity already enrolled")
            self._tokens[token.token_id] = token
            self._agents[token.agent] = token.token_id
            if token.parent:
                self._children[token.parent].add(token.token_id)

    def _revoke_subtree(self, token_id: str) -> tuple[str, ...]:
        pending, revoked = [token_id], []
        while pending:
            current = pending.pop()
            if current in self._revoked:
                continue
            self._revoked.add(current)
            revoked.append(self._tokens[current].agent)
            pending.extend(self._children[current])
        return tuple(sorted(revoked))

    def quarantine(self, command: KillCommand) -> tuple[str, ...]:
        with self._lock:
            if (not self.verify(command) or command.epoch != self.epoch
                    or not math.isfinite(command.expires_at)
                    or self.clock() >= command.expires_at
                    or command.nonce in self._kill_nonces or command.agent not in self._agents):
                raise Denied("invalid, stale, or replayed kill command")
            self._kill_nonces.add(command.nonce)
            return self._revoke_subtree(self._agents[command.agent])

    def inject_failures(self, token: Token, count: int) -> None:
        """Trusted harness simulates unavailable downstream services without real I/O."""
        with self._lock:
            self._chain(token)
            if type(count) is not int or not 0 <= count <= 16:
                raise ValueError("invalid simulated failure count")
            self._faults[token.token_id] = count

    def _observe(self, token: Token, out_of_policy: bool, drift: bool) -> None:
        window = self._behavior[token.token_id]
        window.append((out_of_policy, drift))
        if len(window) >= 3:
            policy_rate = sum(item[0] for item in window) / len(window)
            drift_rate = sum(item[1] for item in window) / len(window)
            if policy_rate >= 0.5 or drift_rate >= 0.5:
                self._revoke_subtree(token.token_id)

    def dispatch(self, token: Token, operation: Operation) -> str:
        with self._lock:
            chain = self._chain(token)
            out_of_policy = operation.tool not in token.scope
            drift = operation.purpose != token.purpose or operation.target != token.target
            self._observe(token, out_of_policy, drift)
            if out_of_policy or drift:
                raise Denied("out-of-policy action or behavioral drift")
            self._chain(token)
            if (type(operation.idempotency) is not str
                    or not 0 < len(operation.idempotency) <= 128
                    or type(operation.payload) is not str or len(operation.payload) > 512):
                raise Denied("bounded payload and idempotency token are required")
            fingerprint = hashlib.sha256(canonical({
                "root": chain[-1].token_id, "tool": operation.tool,
                "target": operation.target, "purpose": operation.purpose,
                "payload": operation.payload,
            })).hexdigest()
            prior = self._idempotency.get(operation.idempotency)
            if prior:
                if prior[0] != fingerprint:
                    raise Denied("idempotency token reused with different parameters")
                if prior[1]:
                    return "duplicate suppressed"
            if self._attempts >= self.attempt_budget or len(self._effects) >= self.effect_budget:
                raise Denied("shared blast-radius budget exhausted")
            retry_key = (token.token_id, operation.idempotency)
            if self._retry_counts[retry_key] >= self.retries:
                raise Denied("per-hop retry budget exhausted")
            self._attempts += 1
            self._retry_counts[retry_key] += 1
            self._idempotency[operation.idempotency] = (fingerprint, False)
            if self._faults[token.token_id]:
                self._faults[token.token_id] -= 1
                self._errors[token.token_id] += 1
                self._cooldown[token.token_id] = self.clock() + 2 ** min(
                    self._errors[token.token_id], 6)
                if self._errors[token.token_id] >= self.error_limit:
                    self._circuits.add(token.token_id)
                raise Denied("downstream failure dampened before propagation")
            self._errors[token.token_id] = 0
            self._idempotency[operation.idempotency] = (fingerprint, True)
            self._effects.append((token.agent, operation))
            return "committed"

    def effect_snapshot(self) -> tuple[tuple[str, Operation], ...]:
        with self._lock:
            return tuple(self._effects)

    def revoked_agents(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._tokens[token_id].agent for token_id in self._revoked))


def run_demo() -> dict:
    clock = lambda: 1000.0
    authority = ControlAuthority(secrets.token_bytes(32), clock)
    breaker = SwarmBreaker(authority.verify, clock)
    root = authority.grant("planner", ("summarize", "save_draft"))
    worker = authority.grant("worker", ("save_draft",), parent=root.token_id)
    peer = authority.grant("peer", ("save_draft",), parent=worker.token_id)
    for token in (root, worker, peer):
        breaker.register(token)
    operation = Operation("save_draft", "mock://workspace", "summarize", "draft", "task-1")
    results = {"first": breaker.dispatch(peer, operation),
               "retry": breaker.dispatch(worker, operation)}
    results["quarantined"] = breaker.quarantine(authority.kill("worker"))
    try:
        breaker.dispatch(peer, replace(operation, idempotency="task-2"))
    except Denied as exc:
        results["peer_after_kill"] = str(exc)
    results["protected_effects"] = len(breaker.effect_snapshot())
    return results


if __name__ == "__main__":
    print(json.dumps(run_demo(), indent=2, sort_keys=True))
