"""Runnable demonstration of ASI03 & ASI09 insecure vs mitigated runtime gates."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

EFFECT_READ_ONLY = "read_only"
EFFECT_REVERSIBLE = "reversible"
EFFECT_EXTERNAL = "external_reversible"
EFFECT_IRREVERSIBLE = "irreversible"

MUTATING_EFFECTS = frozenset({EFFECT_REVERSIBLE, EFFECT_EXTERNAL, EFFECT_IRREVERSIBLE})
APPROVAL_EFFECTS = frozenset({EFFECT_EXTERNAL, EFFECT_IRREVERSIBLE})

DEFAULT_CATALOG: dict[str, str] = {
    "read_document": EFFECT_READ_ONLY,
    "draft_comment": EFFECT_REVERSIBLE,
    "update_ticket": EFFECT_EXTERNAL,
    "send_email": EFFECT_IRREVERSIBLE,
    "change_user_role": EFFECT_IRREVERSIBLE,
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def args_digest(arguments: Mapping[str, Any]) -> str:
    payload = canonical_json(dict(arguments))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def pattern_within(child: str, parent: str) -> bool:
    if child == parent:
        return True
    if parent.endswith("/*"):
        prefix = parent[:-1]
        bare = parent[:-2]
        return child == bare or child.startswith(prefix)
    return False


def resources_within(child: set[str], parent: set[str]) -> bool:
    if not child:
        return True
    return all(any(pattern_within(item, allowed) for allowed in parent) for item in child)


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


@dataclass
class Evaluation:
    allowed: bool
    checks: list[Check] = field(default_factory=list)

    @property
    def failed(self) -> list[str]:
        return [item.name for item in self.checks if not item.passed]


def _require(checks: list[Check], name: str, passed: bool, detail: str) -> None:
    checks.append(Check(name=name, passed=passed, detail=detail))


def insecure_evaluate_call(
    call: Mapping[str, Any],
    *,
    workflow_allowed_tools: set[str],
    approvals: list[Mapping[str, Any]],
) -> bool:
    """Deliberately insecure baseline: checks only coarse tool allowlist and action-name approval."""
    tool = str(call.get("tool", ""))
    if tool not in workflow_allowed_tools:
        return False
    if DEFAULT_CATALOG.get(tool) in APPROVAL_EFFECTS:
        return any(a.get("action") == tool and a.get("decision") == "approved" for a in approvals)
    return True


def evaluate_delegation(
    parent: Mapping[str, Any] | None,
    child: Mapping[str, Any],
    *,
    trusted_issuers: set[str],
) -> Evaluation:
    """Mitigated check: reject any child grant that is missing, expired, or wider than its parent."""
    checks: list[Check] = []
    hop = int(child.get("hop", 0))
    issuer = str(child.get("issuer", ""))
    child_tools = set(child.get("tools", []))
    child_resources = set(child.get("resources", []))
    child_expiry = int(child.get("expires_at", 0))
    child_issued = int(child.get("issued_at", 0))
    child_max_hop = int(child.get("max_hop", hop))
    child_purpose = str(child.get("purpose", ""))
    child_epoch = child.get("policy_epoch")

    _require(checks, "issuer_trusted", issuer in trusted_issuers, "issuer must be trusted control plane")
    _require(checks, "grant_window", child_issued < child_expiry, "issued_at must be before expires_at")
    _require(checks, "hop_within_max", 0 <= hop <= child_max_hop, "hop must be within max_hop")
    _require(checks, "purpose_present", bool(child_purpose), "grant must declare a purpose")

    if hop == 0:
        _require(checks, "root_has_no_parent", parent is None, "root grant must not cite a parent")
    elif parent is None:
        _require(checks, "parent_present", False, "delegated grant is missing its parent")
    else:
        parent_tools = set(parent.get("tools", []))
        parent_resources = set(parent.get("resources", []))
        parent_expiry = int(parent.get("expires_at", 0))
        parent_max_hop = int(parent.get("max_hop", 0))
        parent_purpose = str(parent.get("purpose", ""))
        allowed_subpurposes = set(parent.get("subpurposes", []))
        _require(checks, "parent_present", True, "parent grant resolved")
        _require(checks, "hop_increments", hop == int(parent.get("hop", -1)) + 1, "hop must increment by 1")
        _require(checks, "tools_attenuated", child_tools <= parent_tools, "child tools must be subset of parent")
        _require(
            checks,
            "resources_attenuated",
            resources_within(child_resources, parent_resources),
            "child resources must be within parent resources",
        )
        _require(checks, "expiry_attenuated", child_expiry <= parent_expiry, "child expiry must not exceed parent")
        _require(checks, "max_hop_attenuated", child_max_hop <= parent_max_hop, "child max_hop must not exceed parent")
        _require(
            checks,
            "purpose_attenuated",
            child_purpose == parent_purpose or child_purpose in allowed_subpurposes,
            "child purpose must match parent or declared subpurpose",
        )
        _require(checks, "epoch_preserved", child_epoch == parent.get("policy_epoch"), "policy_epoch must match")

    return Evaluation(allowed=all(item.passed for item in checks), checks=checks)


def evaluate_call(
    call: Mapping[str, Any],
    *,
    grants: list[Mapping[str, Any]],
    approvals: list[Mapping[str, Any]],
    policy_epoch: str,
    state_epoch: str,
    now: int,
    consumed_approval_ids: set[str] | None = None,
) -> Evaluation:
    """Mitigated commit-point check for one proposed tool call."""
    checks: list[Check] = []
    consumed = consumed_approval_ids if consumed_approval_ids is not None else set()
    grant_id = str(call.get("grant_id", ""))
    grant = next((item for item in grants if item.get("grant_id") == grant_id), None)
    tool = str(call.get("tool", ""))
    target = str(call.get("target", ""))
    arguments = call.get("arguments", {})
    if not isinstance(arguments, Mapping):
        arguments = {}
    effect = DEFAULT_CATALOG.get(tool)
    call_purpose = str(call.get("purpose", ""))
    instruction_trust = str(call.get("instruction_trust", "untrusted"))

    _require(checks, "grant_present", grant is not None, "call must cite a known grant")
    _require(checks, "tool_in_catalog", effect is not None, "unknown tools are denied")
    if grant is None or effect is None:
        return Evaluation(allowed=False, checks=checks)

    _require(
        checks,
        "grant_unexpired",
        int(grant.get("issued_at", 0)) <= now < int(grant.get("expires_at", 0)),
        "grant must be inside validity window",
    )
    _require(checks, "policy_epoch_current", grant.get("policy_epoch") == policy_epoch, "policy_epoch must be current")
    _require(checks, "tool_in_scope", tool in set(grant.get("tools", [])), "tool must be in grant tools")
    _require(
        checks,
        "target_in_scope",
        any(pattern_within(target, allowed) for allowed in set(grant.get("resources", []))),
        "target must match grant resources",
    )
    _require(checks, "purpose_matches_grant", call_purpose == str(grant.get("purpose", "")), "purpose must match grant")

    if effect in MUTATING_EFFECTS:
        _require(checks, "state_epoch_current", str(call.get("state_epoch", "")) == state_epoch, "state_epoch current")
        _require(
            checks,
            "untrusted_instruction_cannot_mutate",
            instruction_trust == "trusted_user",
            "untrusted context cannot authorize mutation",
        )

    if effect in APPROVAL_EFFECTS:
        approval_id = call.get("approval_id")
        approval = next((a for a in approvals if a.get("approval_id") == approval_id), None) if approval_id else None
        _require(checks, "approval_present", approval is not None, "irreversible effect requires approval")
        if approval is None:
            return Evaluation(allowed=False, checks=checks)
        aid = str(approval.get("approval_id", ""))
        _require(
            checks,
            "approval_trusted",
            bool(approval.get("trusted")) and str(approval.get("source_trust", "")) == "trusted",
            "approval must come from trusted source",
        )
        _require(
            checks,
            "approval_action_bound",
            approval.get("action") == tool and approval.get("target") == target,
            "approval must bind tool and target",
        )
        _require(
            checks,
            "approval_args_bound",
            approval.get("args_digest") == args_digest(arguments),
            "approval must bind canonical argument digest",
        )
        _require(
            checks,
            "approval_grant_bound",
            approval.get("grant_id") == grant_id and approval.get("purpose") == call_purpose,
            "approval must bind grant_id and purpose",
        )
        _require(
            checks,
            "approval_epoch_bound",
            approval.get("policy_epoch") == policy_epoch and approval.get("state_epoch") == state_epoch,
            "approval must bind current policy and state epochs",
        )
        _require(
            checks,
            "approval_window",
            int(approval.get("issued_at", 0)) <= now < int(approval.get("expires_at", 0)),
            "approval must be unexpired",
        )
        _require(
            checks,
            "approval_single_use",
            aid not in consumed and not bool(approval.get("consumed")),
            "approval is single-use",
        )

    return Evaluation(allowed=all(item.passed for item in checks), checks=checks)


def run_demo() -> dict[str, Any]:
    now = 1_700_000_100
    epoch = "policy-2026-10-27"
    state = "state-7"
    root = {
        "grant_id": "g0",
        "issuer": "control-plane",
        "hop": 0,
        "max_hop": 2,
        "tools": ["read_document", "send_email"],
        "resources": ["workspace/docs/*", "owner@example.invalid"],
        "purpose": "summarize_document",
        "subpurposes": ["draft_summary"],
        "policy_epoch": epoch,
        "issued_at": now - 50,
        "expires_at": now + 500,
    }
    child = {
        "grant_id": "g1",
        "issuer": "control-plane",
        "parent_grant_id": "g0",
        "hop": 1,
        "max_hop": 1,
        "tools": ["read_document"],
        "resources": ["workspace/docs/report.md"],
        "purpose": "draft_summary",
        "policy_epoch": epoch,
        "issued_at": now - 40,
        "expires_at": now + 200,
    }
    approved_args = {"to": "owner@example.invalid", "body": "summary ready"}
    mutated_args = {"to": "owner@example.invalid", "body": "exfiltrated secret"}
    approval = {
        "approval_id": "a1",
        "trusted": True,
        "source_trust": "trusted",
        "action": "send_email",
        "decision": "approved",
        "target": "owner@example.invalid",
        "args_digest": args_digest(approved_args),
        "grant_id": "g0",
        "purpose": "summarize_document",
        "policy_epoch": epoch,
        "state_epoch": state,
        "issued_at": now - 5,
        "expires_at": now + 30,
        "consumed": False,
    }

    hop_escape_call = {
        "grant_id": "g1",
        "tool": "send_email",
        "target": "owner@example.invalid",
        "arguments": approved_args,
        "purpose": "draft_summary",
        "instruction_trust": "trusted_user",
        "state_epoch": state,
        "approval_id": "a1",
    }
    mutated_call = {
        "grant_id": "g0",
        "tool": "send_email",
        "target": "owner@example.invalid",
        "arguments": mutated_args,
        "purpose": "summarize_document",
        "instruction_trust": "trusted_user",
        "state_epoch": state,
        "approval_id": "a1",
    }

    workflow_tools = {"read_document", "send_email"}
    return {
        "asi03_hop_scope_restoration": {
            "insecure_allowed": insecure_evaluate_call(
                hop_escape_call, workflow_allowed_tools=workflow_tools, approvals=[approval]
            ),
            "mitigated_allowed": evaluate_call(
                hop_escape_call,
                grants=[root, child],
                approvals=[approval],
                policy_epoch=epoch,
                state_epoch=state,
                now=now,
            ).allowed,
            "mitigated_failed_checks": evaluate_call(
                hop_escape_call,
                grants=[root, child],
                approvals=[approval],
                policy_epoch=epoch,
                state_epoch=state,
                now=now,
            ).failed,
        },
        "asi09_commit_point_argument_mutation": {
            "insecure_allowed": insecure_evaluate_call(
                mutated_call, workflow_allowed_tools=workflow_tools, approvals=[approval]
            ),
            "mitigated_allowed": evaluate_call(
                mutated_call,
                grants=[root, child],
                approvals=[approval],
                policy_epoch=epoch,
                state_epoch=state,
                now=now,
            ).allowed,
            "mitigated_failed_checks": evaluate_call(
                mutated_call,
                grants=[root, child],
                approvals=[approval],
                policy_epoch=epoch,
                state_epoch=state,
                now=now,
            ).failed,
        },
    }


if __name__ == "__main__":
    print(json.dumps(run_demo(), indent=2))
