# ASI08 Cascading Failures and ASI10 Rogue Agents

## Functionality and threat

Retry storms, cyclic delegation, excessive fan-out, or a drifting worker can
turn one local failure into a swarm-wide impact. This Python 3.11+
standard-library sample uses a shared authoritative breaker at every peer's
synthetic effect boundary, not a cooperative instruction to "stop".

- **ASI08:** shared effect and attempt budgets cap blast radius across roots and
  siblings; per-hop retry counts survive cooldown; downstream errors receive
  exponential cooldown and open a circuit after repeated failure. Cyclic peer
  identities, excessive hop depth, and fan-out open the offending parent's
  circuit. Descendants recheck every ancestor at each dispatch. Idempotency
  binds the root execution and complete operation; retries across peers cannot
  duplicate an effect or substitute new parameters.
- **ASI10:** a bounded sliding window tracks action-scope violations separately
  from purpose/target drift. Every anomalous request is denied before impact;
  at least three observations and an anomaly rate of 50% quarantine that
  agent's entire delegated subtree. Signed, fresh, epoch-bound, single-use
  out-of-band kill commands use the same transitive revocation mechanism.
  Killing a root halts the whole swarm, including prior duplicate paths.

## Run locally

From this directory, with no dependencies or credentials:

```powershell
python -B main.py
python -B -m unittest discover -v
```

```powershell
docker build -t asi08-asi10-swarm-breaker .
docker run --rm asi08-asi10-swarm-breaker
```

## Audit and adversarial verification

The suite checks cross-peer duplicate suppression and parameter mutation,
32 competing sibling effects against a budget of eight, concurrent replay,
cycle/fan-out/depth breakers, per-hop cooldown and permanent retry limits,
failed-attempt accounting, drift and policy-rate quarantine, signed-kill
tampering/replay/exact expiry, token mutation, ancestor expiry, root shutdown,
and survival of unrelated siblings. Effect snapshots, not exception messages
alone, establish absence after blocked work. Positive controls establish
normal reachability.

## Scope and integration

All destinations are inert `mock://` labels. A committed operation is a local
synthetic event, not a tool or network call. Failure injection is a trusted
test-harness API, not an agent-controlled outcome. Cryptographic issuance and
kill APIs belong to the operator/control plane; this in-process HMAC model
does **not** provide isolated key custody or a real out-of-band transport.
Production peers must authenticate control commands independently, consult
shared durable revocation state at the accepting service, and perform budget,
nonce, and effect commits transactionally. The lock protects one process only.
Revocation cannot undo already committed effects. Circuits require trusted
re-enrollment rather than automatic agent recovery. Drift is deterministic
purpose/target deviation, not a semantic intent classifier. Trusted root
enrollment and denied-request traffic also require admission/rate limits.
The small ledger retains nonce and retry tombstones; production retention must
be bounded without shortening replay windows. Long-running sessions must
revalidate backend policy epochs.

## References

- [Agentic Top 10: ASI08 and ASI10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026)
- [LLM06 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- [LLM10 Unbounded Consumption](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/)
- [AISVS 1.0 C9.1.1-C9.1.3, C9.5.5-C9.5.6, C9.6.3](https://github.com/OWASP/AISVS/blob/8906b2be8341abbf4dc43411374681fb81e6ddc6/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md)
