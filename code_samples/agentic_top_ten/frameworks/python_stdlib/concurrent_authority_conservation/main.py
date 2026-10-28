"""ASI03 Reference Sample: Concurrent Delegated-Authority Conservation (DA-01..DA-06).

Demonstrates executable enforcement of the six formal delegated-authority
boundary invariants (see GenAI-Agent-Security-Initiative#19):
  - DA-01 Origin Non-Escalation
  - DA-02 Monotonic Attenuation (capabilities, expiry, budget)
  - DA-03 Transitive Revocation Cascade
  - DA-04 Concurrent Sibling Budget Conservation (atomic under fan-out)
  - DA-05 Commit-Point Ancestor Re-Verification (closing TOCTOU windows)
  - DA-06 Cryptographic Lineage Binding (HMAC-SHA256 chain digest)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any


class AuthorityViolationError(PermissionError):
    """Raised when a delegation or commit-point operation violates DA-01..DA-06."""

    def __init__(self, invariant: str, message: str) -> None:
        super().__init__(f"[{invariant}] {message}")
        self.invariant = invariant


@dataclass
class DelegationGrant:
    """Immutable-lineage capability and budget grant in a delegation tree."""

    grant_id: str
    parent_id: str | None
    delegator: str
    delegatee: str
    capabilities: frozenset[str]
    budget: int
    expires_at: float
    lineage_digest: str
    consumed_budget: int = 0
    allocated_child_budget: int = 0
    revoked: bool = False
    children: list[str] = field(default_factory=list)

    @property
    def remaining_budget(self) -> int:
        return self.budget - self.consumed_budget - self.allocated_child_budget


def _compute_lineage_digest(
    secret: bytes,
    *,
    grant_id: str,
    parent_id: str | None,
    delegator: str,
    delegatee: str,
    capabilities: frozenset[str],
    budget: int,
    expires_at: float,
    parent_digest: str,
) -> str:
    payload = json.dumps(
        {
            "budget": budget,
            "capabilities": sorted(capabilities),
            "delegatee": delegatee,
            "delegator": delegator,
            "expires_at": expires_at,
            "grant_id": grant_id,
            "parent_digest": parent_digest,
            "parent_id": parent_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


class DelegationLedger:
    """Thread-safe authority ledger enforcing invariants DA-01 through DA-06."""

    def __init__(
        self,
        *,
        secret: bytes,
        origin_ceiling: frozenset[str],
        origin_max_budget: int,
    ) -> None:
        self._secret = secret
        self._origin_ceiling = frozenset(origin_ceiling)
        self._origin_max_budget = origin_max_budget
        self._grants: dict[str, DelegationGrant] = {}
        self._lock = threading.RLock()

    def issue_root_grant(
        self,
        *,
        grant_id: str,
        principal: str,
        delegatee: str,
        capabilities: set[str] | frozenset[str],
        budget: int,
        expires_at: float,
    ) -> DelegationGrant:
        """Issue a root grant subject to DA-01 (Origin Non-Escalation)."""
        caps = frozenset(capabilities)
        with self._lock:
            if grant_id in self._grants:
                raise AuthorityViolationError("DA-01", f"duplicate grant_id: {grant_id}")
            if not caps.issubset(self._origin_ceiling):
                extra = sorted(caps - self._origin_ceiling)
                raise AuthorityViolationError(
                    "DA-01",
                    f"root grant exceeds origin capability ceiling: {extra}",
                )
            if budget < 0 or budget > self._origin_max_budget:
                raise AuthorityViolationError(
                    "DA-01",
                    f"root grant budget {budget} exceeds origin ceiling {self._origin_max_budget}",
                )

            digest = _compute_lineage_digest(
                self._secret,
                grant_id=grant_id,
                parent_id=None,
                delegator=principal,
                delegatee=delegatee,
                capabilities=caps,
                budget=budget,
                expires_at=expires_at,
                parent_digest="ROOT",
            )
            grant = DelegationGrant(
                grant_id=grant_id,
                parent_id=None,
                delegator=principal,
                delegatee=delegatee,
                capabilities=caps,
                budget=budget,
                expires_at=expires_at,
                lineage_digest=digest,
            )
            self._grants[grant_id] = grant
            return grant

    def delegate(
        self,
        *,
        parent_id: str,
        grant_id: str,
        delegatee: str,
        capabilities: set[str] | frozenset[str],
        budget: int,
        expires_at: float,
        now: float,
    ) -> DelegationGrant:
        """Mint a child grant enforcing DA-02, DA-03, DA-04, and DA-06 atomically."""
        caps = frozenset(capabilities)
        with self._lock:
            if grant_id in self._grants:
                raise AuthorityViolationError("DA-02", f"duplicate grant_id: {grant_id}")
            parent = self._grants.get(parent_id)
            if parent is None:
                raise AuthorityViolationError("DA-06", f"unknown parent grant: {parent_id}")

            self._verify_chain_locked(parent, now=now)

            if not caps.issubset(parent.capabilities):
                escalated = sorted(caps - parent.capabilities)
                raise AuthorityViolationError(
                    "DA-02",
                    f"child capabilities {escalated} exceed parent {parent.grant_id}",
                )
            if expires_at > parent.expires_at:
                raise AuthorityViolationError(
                    "DA-02",
                    f"child expiry {expires_at} exceeds parent expiry {parent.expires_at}",
                )
            if budget < 0 or budget > parent.budget:
                raise AuthorityViolationError(
                    "DA-02",
                    f"child budget {budget} exceeds parent budget {parent.budget}",
                )
            if budget > parent.remaining_budget:
                raise AuthorityViolationError(
                    "DA-04",
                    f"sibling budget conservation violated on {parent.grant_id}: "
                    f"requested {budget}, remaining {parent.remaining_budget}",
                )

            parent.allocated_child_budget += budget
            digest = _compute_lineage_digest(
                self._secret,
                grant_id=grant_id,
                parent_id=parent.grant_id,
                delegator=parent.delegatee,
                delegatee=delegatee,
                capabilities=caps,
                budget=budget,
                expires_at=expires_at,
                parent_digest=parent.lineage_digest,
            )
            child = DelegationGrant(
                grant_id=grant_id,
                parent_id=parent.grant_id,
                delegator=parent.delegatee,
                delegatee=delegatee,
                capabilities=caps,
                budget=budget,
                expires_at=expires_at,
                lineage_digest=digest,
            )
            parent.children.append(grant_id)
            self._grants[grant_id] = child
            return child

    def revoke(self, grant_id: str) -> list[str]:
        """Cascade revocation across grant_id and all transitive descendants (DA-03)."""
        with self._lock:
            if grant_id not in self._grants:
                raise AuthorityViolationError("DA-03", f"unknown grant_id: {grant_id}")
            revoked_ids: list[str] = []
            stack = [grant_id]
            while stack:
                current_id = stack.pop()
                grant = self._grants[current_id]
                if not grant.revoked:
                    grant.revoked = True
                    revoked_ids.append(current_id)
                stack.extend(grant.children)
            return revoked_ids

    def commit_action(
        self,
        *,
        grant_id: str,
        capability: str,
        cost: int,
        now: float,
    ) -> dict[str, Any]:
        """Re-verify full lineage and atomically deduct cost at commit point (DA-05)."""
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None:
                raise AuthorityViolationError("DA-05", f"unknown grant_id: {grant_id}")

            self._verify_chain_locked(grant, now=now)

            if capability not in grant.capabilities:
                raise AuthorityViolationError(
                    "DA-05",
                    f"grant {grant_id} lacks capability {capability!r} at commit point",
                )
            if cost < 0 or cost > grant.remaining_budget:
                raise AuthorityViolationError(
                    "DA-04",
                    f"grant {grant_id} cost {cost} exceeds remaining budget {grant.remaining_budget}",
                )

            grant.consumed_budget += cost
            return {
                "grant_id": grant.grant_id,
                "delegatee": grant.delegatee,
                "capability": capability,
                "cost": cost,
                "remaining_budget": grant.remaining_budget,
            }

    def _verify_chain_locked(self, grant: DelegationGrant, *, now: float) -> None:
        chain: list[DelegationGrant] = []
        cursor: DelegationGrant | None = grant
        while cursor is not None:
            chain.append(cursor)
            if cursor.parent_id is None:
                break
            parent = self._grants.get(cursor.parent_id)
            if parent is None:
                raise AuthorityViolationError(
                    "DA-06",
                    f"broken parent link {cursor.parent_id!r} on {cursor.grant_id}",
                )
            cursor = parent

        chain.reverse()
        parent_digest = "ROOT"
        for node in chain:
            expected_digest = _compute_lineage_digest(
                self._secret,
                grant_id=node.grant_id,
                parent_id=node.parent_id,
                delegator=node.delegator,
                delegatee=node.delegatee,
                capabilities=node.capabilities,
                budget=node.budget,
                expires_at=node.expires_at,
                parent_digest=parent_digest,
            )
            if not hmac.compare_digest(node.lineage_digest, expected_digest):
                raise AuthorityViolationError(
                    "DA-06",
                    f"lineage digest mismatch on grant {node.grant_id}",
                )
            if node.revoked:
                raise AuthorityViolationError(
                    "DA-03",
                    f"ancestor or leaf grant {node.grant_id} has been revoked",
                )
            if now > node.expires_at:
                raise AuthorityViolationError(
                    "DA-05",
                    f"grant {node.grant_id} expired at {node.expires_at} (now={now})",
                )
            parent_digest = node.lineage_digest


def run_demo() -> dict[str, Any]:
    """Compare insecure fan-out double-spending against hardened DA-01..DA-06 enforcement."""
    # 1. Insecure fan-out: 5 workers each check parent_budget >= 40 without atomic reservation
    insecure_parent_budget = 100
    insecure_spent = 0
    for _ in range(5):
        if 40 <= insecure_parent_budget:
            insecure_spent += 40

    # 2. Hardened ledger under concurrent 5-worker fan-out (each requesting 40 from a 100 budget)
    ledger = DelegationLedger(
        secret=b"owasp-asi03-demo-secret",
        origin_ceiling=frozenset({"payments.refund", "orders.read"}),
        origin_max_budget=100,
    )
    ledger.issue_root_grant(
        grant_id="root-1",
        principal="human:treasurer",
        delegatee="agent:planner",
        capabilities={"payments.refund", "orders.read"},
        budget=100,
        expires_at=2000.0,
    )

    def spawn_and_spend(idx: int) -> int:
        try:
            child = ledger.delegate(
                parent_id="root-1",
                grant_id=f"worker-{idx}",
                delegatee=f"agent:worker-{idx}",
                capabilities={"payments.refund"},
                budget=40,
                expires_at=1500.0,
                now=1000.0,
            )
            res = ledger.commit_action(
                grant_id=child.grant_id,
                capability="payments.refund",
                cost=40,
                now=1001.0,
            )
            return int(res["cost"])
        except AuthorityViolationError:
            return 0

    with ThreadPoolExecutor(max_workers=5) as pool:
        outcomes = list(pool.map(spawn_and_spend, range(5)))

    summary = {
        "parent_budget": 100,
        "insecure_concurrent_spend": insecure_spent,
        "hardened_concurrent_spend": sum(outcomes),
        "hardened_approved_workers": sum(1 for x in outcomes if x > 0),
        "hardened_rejected_workers": sum(1 for x in outcomes if x == 0),
    }
    return summary


if __name__ == "__main__":
    print(json.dumps(run_demo(), indent=2))
