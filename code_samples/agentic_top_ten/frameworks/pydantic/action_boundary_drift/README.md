# Pydantic action boundary drift sample

This deliberately vulnerable sample demonstrates an approval/execution drift issue in an agent workflow.

The agent asks for approval to perform one action, receives an approval ticket, and then executes a different action under the same ticket. The insecure path checks only that an approval exists. The secure path binds the approval to a canonical action fingerprint and rejects the drift.

## Vulnerability

Many human-in-the-loop agent designs treat approval as a session flag or approval ID:

1. Agent proposes a low-risk action.
2. Human approves the proposal.
3. Agent or runtime later changes the target, destination, effect, or side-effect profile.
4. Executor sees an approved ticket and runs the changed action.

That creates a gap between what was approved and what actually happened. The audit trail may show that a human approved the session, but it cannot prove that the executed action still matched the approved action.

## Mapped risks

- ASI02 Tool Misuse and Exploitation: the tool call changes from read-only analysis to data export.
- ASI08 Repudiation and Untraceability: the approval record is not bound to the executed action.
- ASI10 Overwhelming Human-in-the-Loop: the reviewer is shown reassuring text instead of an enforceable action boundary.
- LLM06 Excessive Agency: the agent can convert a benign approval into a higher-impact tool action.

## Run locally

With Python:

```bash
python -m pip install -r requirements.txt
python main.py
```

With Docker:

```bash
docker build -t action-boundary-drift .
docker run --rm action-boundary-drift
```

Expected output:

- The insecure executor accepts the mutated action because the ticket is approved.
- The secure executor rejects the mutated action because the canonical action fingerprint changed.

## Mitigation pattern

Approval should be bound to the action object, not just to a session, ticket, prompt, or natural-language summary. At minimum, bind:

- actor or agent identity
- operation
- resource or target
- destination boundary
- intended effect
- side-effect class
- policy version
- approval decision

Then recompute the fingerprint immediately before execution. If any of the fields changed, the approval should not be reusable.
