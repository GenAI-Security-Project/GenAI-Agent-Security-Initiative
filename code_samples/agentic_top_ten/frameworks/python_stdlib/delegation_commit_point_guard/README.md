# ASI03 & ASI09 — Multi-Hop Delegation Scope Restoration & Commit-Point Approval Bypass

## Functionality of the Example

This self-contained, zero-credential Python sample demonstrates two runtime authorization vulnerabilities in multi-agent tool chains alongside their deterministic mitigations:

1. **Delegation Hop Scope Restoration (`ASI03: Identity & Privilege Abuse` / `LLM06: Excessive Agency`)**:
   - A root planner (`hop=0`) holds permissions for `read_document` and `send_email`, and delegates a narrowed child grant (`hop=1`, `tools=["read_document"]`) to a summarization worker.
   - Untrusted handoff content instructs the worker to call `send_email`.
   - **Insecure path**: checks only the root/session allowlist (`send_email` is allowed for the workflow) and executes the dropped tool.
   - **Mitigated path**: enforces monotonic `scope_attenuation` across parent/child grants (`child.tools <= parent.tools`, `child.resources <= parent.resources`, `child.expires_at <= parent.expires_at`, `child.hop == parent.hop + 1`, `child.policy_epoch == parent.policy_epoch`) and binds each tool call to its active hop grant.

2. **Commit-Point Argument Mutation & Approval Replay (`ASI09: Human-Agent Trust Exploitation` / `ASI03: Identity & Privilege Abuse`)**:
   - A human/approval service approves `send_email(to="owner@example.invalid", body="summary ready")`.
   - Before execution, injected tool output mutates `body` or replays the same approval a second time (or under a stale `policy_epoch` / `state_epoch`).
   - **Insecure path**: checks only that a prior approval event exists for `action="send_email"` and allows both the mutated call and the replayed call.
   - **Mitigated path**: enforces `commit_point_approval` — requiring a single-use trusted approval bound to `action`, `target`, canonical SHA-256 `args_digest`, `grant_id`, `purpose`, `policy_epoch`, and `state_epoch`.

## OWASP References

- **OWASP Top 10 for Agentic Applications**:
  - `ASI01`: Agent Behaviour Hijack (intent/purpose drift)
  - `ASI02`: Tool Misuse and Exploitation
  - `ASI03`: Identity & Privilege Abuse (delegation scope escalation, concurrent/replay double-spend)
  - `ASI09`: Human-Agent Trust Exploitation (commit-point argument mutation after approval)
- **OWASP Top 10 for LLM Applications 2025**:
  - `LLM01`: Prompt Injection
  - `LLM06`: Excessive Agency

## Prerequisites & Running Locally

Requires only Python 3.11+ standard library (no API keys or external packages required).

```bash
python main.py
python -m unittest discover -v
```

### Run with Docker

```bash
docker build -t asi-delegation-commit-point-guard .
docker run --rm asi-delegation-commit-point-guard
```
