# ASI01 Goal Hijacking and Reversibility-Graded Commit-Point Gate

## Functionality and threat

Untrusted retrieved RAG, web, or email text can try to replace a legitimate goal
or turn a read into an external release. This zero-dependency Python 3.11+
reference separates a data-only ingestion interface from signed instruction
plans. It makes no attempt to decide whether text "looks malicious": retrieved
text has no control-plane authority in the first place.

The trusted catalog, not caller-supplied labels, determines the authority matrix:

| Grade | Example | Gate |
| --- | --- | --- |
| `R0_READ_ONLY` | Read a local synthetic document | Autonomous, audited |
| `R1_REVERSIBLE_INTERNAL` | Save a local draft | Autonomous, audited |
| `R2_BOUNDED_EXTERNAL` | Append a synthetic notice | One trusted reviewer |
| `R3_IRREVERSIBLE_EXTERNAL` | Append a synthetic release | Two distinct reviewers and two evidence digests |

Every step, including a read-only prefix, is gated at the least-reversible
(highest numbered) action anywhere in the signed chain. Approvals bind the
complete canonical action chain, goal, requester, tenant/environment context,
policy and state epochs, step, reviewers, evidence, expiry, and unique nonce.
The final gate rechecks all bindings and revocation under one lock; approvals
and steps are consumed once. Internal draft undo is bound to its original plan
and step. No denied call reaches the synthetic effect store.

## Audit, design, and adversarial verification

The tests cover role-spoofing data in all three ingestion channels, plan and
parameter mutation, caller-claimed grade reduction, cross-plan approval reuse,
worst-case prefix gating, stale policy/state, exact expiry, revocation, duplicate
JSON keys, irreversible evidence thresholds, and 32 competing commits. Matched
positive controls verify that approved effects remain reachable; independent
effect snapshots verify absence after denial.

## Run locally

From this directory, with Python 3.11+ and no credentials or packages:

```powershell
python -B main.py
python -B -m unittest discover -v
```

```powershell
docker build -t asi01-goal-gate .
docker run --rm asi01-goal-gate
```

## Scope and integration

All `mock://` destinations are inert labels; no network, mail, or real release
occurs. Draft reversibility and irreversible-release semantics are catalog
assumptions, not claims about a real destination. Production adapters must
classify true undo guarantees and enforce the gate inside the accepting service.
The trusted harness authenticates instruction authors and reviewers before
calling `instruct`/`approve`; these methods are not exposed to the data plane.
This is an in-process HMAC illustration, **not a sandbox or isolated approval
service**. Deploy issuer keys and reviewer authentication outside the agent
process; use durable transactional consume-once state, bounded retention,
backend policy/state versions, and an outbox/idempotent sink for crash recovery.
The local lock only provides atomicity inside one process. Evidence digests
bind reviewed artifacts; their substantive sufficiency is a trusted-review task.

## References

- [ASI01 and Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026)
- [LLM01 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [LLM06 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- [Reversibility proposal #13](https://github.com/GenAI-Security-Project/GenAI-Agent-Security-Initiative/issues/13)
- [Commit-point pattern #14](https://github.com/GenAI-Security-Project/GenAI-Agent-Security-Initiative/issues/14)
- [AISVS 1.0 C9.2.3, C9.2.4, C9.2.8, C9.2.10](https://github.com/OWASP/AISVS/blob/8906b2be8341abbf4dc43411374681fb81e6ddc6/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md)
