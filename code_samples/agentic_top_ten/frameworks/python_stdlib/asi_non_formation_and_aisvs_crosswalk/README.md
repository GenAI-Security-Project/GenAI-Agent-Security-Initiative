# ASI01-ASI10 Non-Formation Companions and AISVS C9.2 Crosswalk

## Functionality

This independent Python 3.11+ standard-library reference pairs machine-readable
requirement mappings with ten harmless architectural-boundary exercises:

| Category | Protected boundary |
| --- | --- |
| ASI01 Goal Hijacking | Retrieved content cannot replace the trusted goal |
| ASI02 Tool Misuse | Unregistered effectful tool has no catalog authority |
| ASI03 Identity & Privilege Abuse | A narrowed child cannot restore parent scope |
| ASI04 Supply Chain | A pinned tool manifest cannot change after registration |
| ASI05 Unexpected Code Execution | Dynamic execution cannot enter the tiny expression class |
| ASI06 Memory Poisoning | Unsigned/tainted provenance cannot enter persistent context |
| ASI07 Inter-Agent Communication | Changed peer handoff fails its cryptographic binding |
| ASI08 Cascading Failures | Fan-out budget and worst-case chain class hold at admission |
| ASI09 Human-Agent Trust | Final recipient must match complete approved parameters |
| ASI10 Rogue Agents | Live revocation stops even a previously approved peer |

`crosswalk.json` enumerates AISVS **1.0**, **C9.2.1-C9.2.10**, pinned to
source commit `8906b2be8341abbf4dc43411374681fb81e6ddc6`. Each ASI entry has
requirement IDs, rationale, fixture linkage, contextual controls, and limitations.
`boundary_subset` is a narrow executable analogue, **not verification of the
entire requirement**. `context_only` is a related control, not demonstrated
coverage. C9.2.6, C9.2.7, and C9.2.9 are explicitly **not demonstrated**:
this sample has no auxiliary review mechanism or isolated approval-key service.
The human approval and canonical display are trusted fixture stubs, not a
production authentication/UI implementation. This is not an official mapping
or a certification claim.

## Incident derivation

`fixtures.json` contains original sanitized analogues inspired by two primary
public incident accounts, with source URL, section locator, and per-fixture
derivation rationale:

- [AISI's July 2026 incident account](https://www.aisi.gov.uk/blog/incident-report-unsanctioned-agent-behaviour-during-cyber-testing):
  external actions, planted instructions, public artifacts reused across agents,
  attempted reviewer deception, and eventual containment.
- [July 2026 evaluation incident account](https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals):
  package publication/automatic installation and out-of-scope target expansion.

All ten are labeled **analogous**, not exact incident reproductions. The
classification is this companion's interpretation, not the source authors'
taxonomy assignment. No malicious package, real target, campaign payload, real
credential, network call, or third-party source code is included.

## Non-formation instrument

A policy-free `EffectPort` can change local synthetic `release`, `code`,
`memory`, `handoff`, and alternate `shadow` surfaces. The adapter returns a
decision separately. The observer snapshots **all** surfaces before and after;
it never infers an effect result from `ALLOW` or `DENY`.

Every category must pass:

1. Protected negative: `DENY`, surface unchanged.
2. Matched positive: `ALLOW`, exactly one event on the declared surface.
3. Permissive negative baseline: `ALLOW`, effect forms, proving reachability.

The tests also reach and reject both divergent cells: leaky `DENY` with an
effect, and dead-end `ALLOW` without an effect. Alternate-surface effects,
duplicate effects, adapter exceptions, invalid decisions, missing/duplicate ASI
entries, unknown requirements, source/edition drift, incorrect assurance levels,
overclaimed key isolation, boolean schema/grade confusion, non-finite expiry,
and malformed fixture linkage fail verification. New or removed surface keys
and same-count content replacement are detected, not only appended events.

## Run locally

From this directory, with no credentials or dependencies:

```powershell
python -B main.py
python -B -m unittest discover -v
```

`main.py` validates both JSON documents and reports 20 protected cases and ten
permissive reachability cases. JSON files are resolved relative to the module,
not the shell's working directory. Non-formation is limited to the modeled
protected surfaces and effect paths; it is not a universal benchmark.

```powershell
docker build -t asi-non-formation-crosswalk .
docker run --rm asi-non-formation-crosswalk
```

## Scope and integration

Each guard is a small independent boundary adapter, not an import of the other
open samples or a replacement for their richer implementations. Trusted state
(goals, catalog, child scope, chain grades, reviewer evidence, revocation) is
set up by the harness, never by retrieved text. HMAC keys, signing, and
verification live in one process solely for illustration; production issuers,
reviewer identity, transport authentication, revocation, and replay stores need
separate trusted services and durable atomic commits. A no-op adapter cannot
pass by simply reporting denial. Conversely, a passing synthetic adapter says
nothing about undeclared real-world surfaces, semantic intent, or deployment
configuration. Third-party adapters are executable code and must be reviewed.

## References and companion discussions

- [AISVS pinned C9 source](https://github.com/OWASP/AISVS/blob/8906b2be8341abbf4dc43411374681fb81e6ddc6/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md)
- [Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026)
- [LLM01 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [LLM06 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- [Requirement mapping discussion #15](https://github.com/GenAI-Security-Project/GenAI-Agent-Security-Initiative/issues/15)
- [Non-formation companion discussion #17](https://github.com/GenAI-Security-Project/GenAI-Agent-Security-Initiative/issues/17)
- [AECP v0.1-rc2](https://github.com/visker83-del/aecp/releases/tag/v0.1-rc2):
  methodological context for independent decision/effect observation only;
  this sample does not implement AECP, copy its fixtures, or claim conformance.
