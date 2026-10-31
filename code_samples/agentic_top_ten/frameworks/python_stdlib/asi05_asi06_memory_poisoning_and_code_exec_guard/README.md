# ASI05 Unexpected Code Execution and ASI06 Memory & Context Poisoning

## Functionality and threat

A retrieved turn can suggest executable code or persist fabricated "system"
instructions for later privileged use. This Python 3.11+ standard-library sample
guards both architectural boundaries, using no credentials or third-party code.

- **ASI05:** `CodeGuard` parses a small Python-shaped expression language and
  statically allowlists every AST node. A bounded recursive interpreter supports
  plain strings/integers, integer arithmetic, and explicitly granted `upper`,
  `length`, and `add` capabilities. It never calls `eval`, `exec`, a shell,
  subprocess, an import loader, or a supplied callable. Attribute access,
  dunder gadgets, lambdas, comprehensions, keywords, imports, dynamic execution,
  and shell metacharacters (even inside strings) are denied. Source size, AST
  nodes, constant types, integer magnitude, and intermediate result lengths are
  bounded. This is capability restriction by non-existence of effectful APIs,
  not a blacklist around unrestricted Python execution.
- **ASI06:** HMAC-tagged writes bind namespace, fact key/value, source, turn ID,
  taint, revision, expiry, and a single-use nonce. Untrusted or tampered turns go
  to a bounded quarantine, never into trusted episodic/semantic retrieval.
  Exact TTL eviction removes expired facts. Newer independently verified
  revisions evict contradictory facts across both memory kinds. Revision
  tombstones and nonce consumption prevent reintroducing stale facts.
  Immutable system memory is never merged with retrieved turns.

## Run locally

From this directory:

```powershell
python -B main.py
python -B -m unittest discover -v
```

```powershell
docker build -t asi05-asi06-memory-code-guard .
docker run --rm asi05-asi06-memory-code-guard
```

## Audit and adversarial verification

Tests include approved expressions, capability attenuation, dynamic execution,
subprocess/import and object-graph gadgets, shell injection, parser/AST/result
budgets, self-asserted provenance, taint clearing, forged TTLs, exact expiry,
cross-kind contradictions, replay after eviction, forbidden system writes, and
memory/quarantine capacity. Negative tests observe trusted retrieval and the
system-memory surface independently; positive controls admit verified facts.

## Scope and integration

No arbitrary Python or real external action runs. The expression language is
deliberately narrow and is not a general-purpose Python sandbox. Admission
methods are trusted-service APIs: authenticating operators and independently
verifying external facts happens before attestation, not by trusting a `source`
string supplied by a retrieval caller. Production systems must isolate issuer
keys, attach provenance at ingestion, and maintain durable admission/revision
state. This in-process HMAC model does not provide OS isolation or key custody.
Contradictions mean a newer verified value for the same explicit fact key, not
semantic natural-language contradiction detection. Quarantine is diagnostic
only and must never be concatenated into instruction context. Tombstones and
consumed nonces deliberately persist in this small demo; a service needs bounded
durable retention that outlives all replay windows. Trusted producers must also
be rate-limited. Even signed facts remain data, not instructions.

## References

- [Agentic Top 10: ASI05 and ASI06](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026)
- [LLM01 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [LLM04 Data and Model Poisoning](https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/)
- [LLM05 Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)
- [AISVS 1.0 C9.2.5 and C9.3.5-C9.3.6](https://github.com/OWASP/AISVS/blob/8906b2be8341abbf4dc43411374681fb81e6ddc6/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md)
