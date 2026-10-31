"""ASI05/ASI06: a bounded expression interpreter and signed memory admission."""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import math
import secrets
import threading
from collections import deque
from dataclasses import asdict, dataclass, replace
from types import MappingProxyType
from typing import Callable


class Denied(PermissionError):
    pass


class CodeGuard:
    """Recognizes a tiny expression language; never executes supplied Python."""

    KNOWN = frozenset({"upper", "length", "add"})
    SHELL = frozenset(";|&$`<>\n\r")
    NODES = (ast.Expression, ast.Constant, ast.Call, ast.Name, ast.Load,
             ast.BinOp, ast.Add, ast.Sub, ast.Mult)

    def __init__(self, capabilities: frozenset[str] = KNOWN) -> None:
        if not capabilities <= self.KNOWN:
            raise ValueError("unknown execution capability")
        self.capabilities = frozenset(capabilities)

    @staticmethod
    def _bounded(value: object) -> str | int:
        if type(value) is int and abs(value) <= 1_000_000:
            return value
        if type(value) is str and len(value) <= 512:
            if any(c in CodeGuard.SHELL for c in value):
                raise Denied("decoded literal contains shell metacharacters")
            return value
        raise Denied("only bounded plain integer/string results are permitted")

    def verify(self, source: str) -> ast.Expression:
        if type(source) is not str or len(source) > 2048 or any(c in self.SHELL for c in source):
            raise Denied("oversize source or shell metacharacters")
        try:
            tree = ast.parse(source, mode="eval")
        except (SyntaxError, ValueError, RecursionError) as exc:
            raise Denied("not a supported expression") from exc
        nodes = list(ast.walk(tree))
        if len(nodes) > 64:
            raise Denied("AST instruction budget exceeded")
        for node in nodes:
            if type(node) not in self.NODES:
                raise Denied(f"AST node {type(node).__name__} is not allowlisted")
            if isinstance(node, ast.Name):
                if "__" in node.id or node.id not in self.capabilities:
                    raise Denied("name outside capability policy")
            if isinstance(node, ast.Constant):
                self._bounded(node.value)
            if isinstance(node, ast.Call):
                if (type(node.func) is not ast.Name or node.keywords
                        or len(node.args) != (2 if node.func.id == "add" else 1)):
                    raise Denied("only direct fixed-arity capability calls are permitted")
        return tree

    def execute(self, source: str) -> str | int:
        tree = self.verify(source)

        def interpret(node: ast.AST) -> str | int:
            if type(node) is ast.Constant:
                return self._bounded(node.value)
            if type(node) is ast.BinOp:
                left, right = interpret(node.left), interpret(node.right)
                if type(left) is not int or type(right) is not int:
                    raise Denied("arithmetic requires plain integers")
                if type(node.op) is ast.Add:
                    result = left + right
                elif type(node.op) is ast.Sub:
                    result = left - right
                else:
                    result = left * right
                return self._bounded(result)
            if type(node) is ast.Call:
                args = [interpret(item) for item in node.args]
                name = node.func.id
                if name == "add":
                    if any(type(item) is not int for item in args):
                        raise Denied("add requires integers")
                    return self._bounded(args[0] + args[1])
                if type(args[0]) is not str:
                    raise Denied("string capability requires a plain string")
                return self._bounded(args[0].upper() if name == "upper" else len(args[0]))
            raise Denied("bare capabilities cannot be used as values")

        return interpret(tree.body)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


@dataclass(frozen=True)
class MemoryTurn:
    kind: str
    key: str
    value: str
    source: str
    turn_id: str
    tainted: bool
    revision: int
    expires_at: float
    nonce: str
    signature: str = ""


def payload(turn: MemoryTurn) -> dict:
    result = asdict(turn)
    result.pop("signature")
    return result


class AdmissionAuthority:
    """The trusted ingestion service attests verified facts, not arbitrary turns."""

    SOURCES = frozenset({"operator", "verified_fixture"})

    def __init__(self, key: bytes, clock: Callable[[], float]) -> None:
        if len(key) < 32:
            raise ValueError("admission key must contain at least 32 bytes")
        self.__key = key
        self.clock = clock

    def _mac(self, turn: MemoryTurn) -> str:
        return hmac.new(self.__key, b"memory-v1:" + canonical(payload(turn)),
                        hashlib.sha256).hexdigest()

    def verify(self, turn: MemoryTurn) -> bool:
        return hmac.compare_digest(self._mac(turn), turn.signature)

    def attest(self, kind: str, key: str, value: str, *, source: str,
               turn_id: str, revision: int = 1, ttl: float = 60) -> MemoryTurn:
        if source not in self.SOURCES or not math.isfinite(ttl) or not 0 < ttl <= 300:
            raise Denied("only independently verified sources with bounded TTL can be attested")
        turn = MemoryTurn(kind, key, value, source, turn_id, False, revision,
                          self.clock() + ttl, secrets.token_hex(16))
        return replace(turn, signature=self._mac(turn))


class MemoryStore:
    def __init__(self, verify: Callable[[MemoryTurn], bool],
                 clock: Callable[[], float]) -> None:
        self.verify = verify
        self.clock = clock
        self._records: dict[tuple[str, str], MemoryTurn] = {}
        self._revisions: dict[str, int] = {}
        self._used: set[str] = set()
        self._quarantine: deque[MemoryTurn] = deque(maxlen=64)
        self._lock = threading.RLock()
        self.system_memory = MappingProxyType({"policy": "no external effects"})

    def _evict_expired(self) -> None:
        now = self.clock()
        self._records = {key: turn for key, turn in self._records.items()
                         if turn.expires_at > now}

    def write(self, turn: MemoryTurn) -> None:
        with self._lock:
            if (turn.tainted or turn.source not in AdmissionAuthority.SOURCES
                    or not self.verify(turn)):
                self._quarantine.append(turn)
                raise Denied("untrusted turn quarantined; no privileged memory admission")
            now = self.clock()
            if (turn.kind not in {"episodic", "semantic"}
                    or not turn.key or len(turn.key) > 128 or turn.key.startswith("system.")
                    or type(turn.value) is not str or not 0 < len(turn.value) <= 512
                    or not turn.turn_id or type(turn.revision) is not int or turn.revision <= 0
                    or not math.isfinite(turn.expires_at) or not now < turn.expires_at <= now + 300):
                raise Denied("invalid namespace, value, revision, or expiry")
            if turn.nonce in self._used or turn.revision <= self._revisions.get(turn.key, 0):
                raise Denied("replayed or stale fact revision")
            self._evict_expired()
            conflicts = [key for key, old in self._records.items() if old.key == turn.key]
            if len(self._records) - len(conflicts) >= 64:
                raise Denied("memory capacity exhausted")
            # A newer verified revision invalidates contradictory cross-kind facts.
            for key in conflicts:
                del self._records[key]
            self._records[(turn.kind, turn.key)] = turn
            self._revisions[turn.key] = turn.revision
            self._used.add(turn.nonce)

    def retrieve(self, kind: str) -> tuple[MemoryTurn, ...]:
        if kind not in {"episodic", "semantic"}:
            raise Denied("retrieval cannot address privileged system memory")
        with self._lock:
            self._evict_expired()
            return tuple(turn for (namespace, _), turn in sorted(self._records.items())
                         if namespace == kind)

    def quarantine_snapshot(self) -> tuple[MemoryTurn, ...]:
        with self._lock:
            return tuple(self._quarantine)


def run_demo() -> dict:
    clock = lambda: 1000.0
    authority = AdmissionAuthority(secrets.token_bytes(32), clock)
    store = MemoryStore(authority.verify, clock)
    guard = CodeGuard(frozenset({"upper", "length"}))
    poisoned = MemoryTurn("semantic", "policy", "exec('release records')",
                          "rag", "untrusted-1", True, 1, 1060.0, "untrusted")
    results = {}
    try:
        store.write(poisoned)
    except Denied as exc:
        results["poisoned_memory"] = str(exc)
    verified = authority.attest("semantic", "summary", "approved summary",
                                source="operator", turn_id="verified-1")
    store.write(verified)
    for source in ("upper('summary')", "eval('1+1')", "__import__('os')",
                   "upper('summary;release')"):
        try:
            results[source] = guard.execute(source)
        except Denied as exc:
            results[source] = str(exc)
    results["trusted_facts"] = len(store.retrieve("semantic"))
    results["quarantined_turns"] = len(store.quarantine_snapshot())
    results["system_policy"] = store.system_memory["policy"]
    return results


if __name__ == "__main__":
    print(json.dumps(run_demo(), indent=2, sort_keys=True))
