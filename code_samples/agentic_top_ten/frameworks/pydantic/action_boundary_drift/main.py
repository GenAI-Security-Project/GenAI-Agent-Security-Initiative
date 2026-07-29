"""Deliberately vulnerable approval/execution drift demo.

The insecure executor checks that an approval ticket exists, but it does not
check whether the approved action and the executed action are still identical.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal, Optional
from uuid import uuid4

from pydantic import BaseModel


Effect = Literal["read", "data_export", "financial", "deployment"]
Destination = Literal["internal", "external", "public"]


class Action(BaseModel):
    actor: str
    operation: str
    resource: str
    destination: Destination
    effect: Effect
    side_effect: bool
    policy_version: str


class ApprovalTicket(BaseModel):
    ticket_id: str
    approved: bool
    reviewer: str
    approved_summary: str
    approved_action_fingerprint: Optional[str] = None


class ExecutionResult(BaseModel):
    executed: bool
    reason: str
    action_fingerprint: str


def canonical_fingerprint(action: Action) -> str:
    """Create a stable digest over the fields that define action identity."""

    stable = action.model_dump()
    encoded = json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def request_insecure_approval(action: Action) -> ApprovalTicket:
    return ApprovalTicket(
        ticket_id=f"ticket-{uuid4()}",
        approved=True,
        reviewer="finance-ops",
        approved_summary=(
            f"Approve {action.operation} on {action.resource} "
            f"for {action.destination} use."
        ),
    )


def request_bound_approval(action: Action) -> ApprovalTicket:
    return ApprovalTicket(
        ticket_id=f"ticket-{uuid4()}",
        approved=True,
        reviewer="finance-ops",
        approved_summary=(
            f"Approve {action.operation} on {action.resource} "
            f"for {action.destination} use."
        ),
        approved_action_fingerprint=canonical_fingerprint(action),
    )


def insecure_execute(ticket: ApprovalTicket, action: Action) -> ExecutionResult:
    if not ticket.approved:
        return ExecutionResult(
            executed=False,
            reason="ticket was not approved",
            action_fingerprint=canonical_fingerprint(action),
        )

    return ExecutionResult(
        executed=True,
        reason="executed because approval ticket was present",
        action_fingerprint=canonical_fingerprint(action),
    )


def secure_execute(ticket: ApprovalTicket, action: Action) -> ExecutionResult:
    fingerprint = canonical_fingerprint(action)
    if not ticket.approved:
        return ExecutionResult(
            executed=False,
            reason="ticket was not approved",
            action_fingerprint=fingerprint,
        )

    if ticket.approved_action_fingerprint != fingerprint:
        return ExecutionResult(
            executed=False,
            reason="rejected approval/execution drift",
            action_fingerprint=fingerprint,
        )

    return ExecutionResult(
        executed=True,
        reason="executed because approval matched this exact action",
        action_fingerprint=fingerprint,
    )


def main() -> None:
    approved_action = Action(
        actor="support-agent",
        operation="read_support_ticket",
        resource="ticket-1042",
        destination="internal",
        effect="read",
        side_effect=False,
        policy_version="support-policy-v1",
    )

    mutated_action = Action(
        actor="support-agent",
        operation="export_customer_records",
        resource="customer-table",
        destination="public",
        effect="data_export",
        side_effect=True,
        policy_version="support-policy-v1",
    )

    insecure_ticket = request_insecure_approval(approved_action)
    insecure_result = insecure_execute(insecure_ticket, mutated_action)

    bound_ticket = request_bound_approval(approved_action)
    secure_result = secure_execute(bound_ticket, mutated_action)

    print("Approved action fingerprint:")
    print(canonical_fingerprint(approved_action))
    print()
    print("Mutated action fingerprint:")
    print(canonical_fingerprint(mutated_action))
    print()
    print("INSECURE EXECUTOR:")
    print(insecure_result.model_dump_json(indent=2))
    print()
    print("SECURE EXECUTOR:")
    print(secure_result.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
