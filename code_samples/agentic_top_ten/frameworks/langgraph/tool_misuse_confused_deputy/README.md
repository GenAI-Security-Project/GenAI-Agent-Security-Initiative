# LangGraph — Tool Misuse via Confused Deputy (ASI02)

A deliberately vulnerable [LangGraph](https://github.com/langchain-ai/langgraph)
multi-agent system demonstrating **ASI02 – Tool Misuse and Exploitation** from the
OWASP Top 10 for Agentic Applications. Untrusted web content fetched by one agent
flows, unlabelled, through shared state and drives another agent's privileged
tools — a classic *confused-deputy* chain.

> ⚠️ **Intentionally insecure. Educational use only.** This code contains
> security flaws on purpose. Do not deploy it, expose it to a network, point it
> at systems you don't own, or reuse its patterns in production. It is the
> agentic-AI equivalent of a DVWA / Juice Shop target: attack it in an isolated
> environment to learn how to defend real systems.

## Functionality

The system is a three-node LangGraph pipeline that answers a research task:

```
START → Planner → Researcher → Executor → END
```

| Agent | Role | Capability |
|---|---|---|
| **Planner** | Decomposes the user task into steps and decides what to look up. | none |
| **Researcher** | Runs the lookup by fetching external content. | `fetch` — the **untrusted entry point** |
| **Executor** | Chooses one concrete action to complete the task. | `run_shell`, `write_file`, `search_logs` — the **dangerous capability** |

All three nodes communicate through a single shared `AgentState`. Given a benign
task ("research the latest LangGraph release and summarise it"), the pipeline
plans a lookup, fetches a page, and produces a summary — no harmful action.

Run it both ways to see the difference:

```bash
python agent.py            # benign fetch  → harmless summary
python agent.py --attack   # poisoned fetch → Executor runs an attacker's command
```

## The vulnerability

The whole system hinges on **one design flaw: `AgentState` has no trust
boundary.** Every node appends to the same `scratchpad` / `research_findings`
blob, and entries carry **no source or provenance label**. So when the
Researcher fetches an attacker-controlled page, the raw page text is concatenated
verbatim into the same `research_findings` string that the Executor treats as
trusted instruction:

```python
# researcher_node — src concatenated verbatim into shared state
findings = f"{findings}\n\n--- SOURCE CONTENT (verbatim) ---\n{fetched}"
```

```python
# executor_node — provenance is available but never checked (confused deputy)
# trigger_source is in state; the Executor acts on `research_findings` regardless
# of whether the instruction came from the user or from a fetched page.
```

Three concrete weaknesses stack up:

1. **No trust boundary in shared state** — untrusted fetched text sits next to
   genuine user instruction and is indistinguishable to downstream nodes.
2. **Confused deputy** — `trigger_source` (provenance) is recorded but never
   consulted, so an action smuggled in via fetched content runs with the
   Executor's full privilege.
3. **Unguarded tools** — `run_shell` uses `shell=True` with no allowlist or
   sandbox, and `search_logs` interpolates its `term` argument straight into a
   shell command (tool-argument injection), so a crafted search term executes
   arbitrary commands.

The attack payload (`poisoned_page.html`) hides an instruction in an HTML comment
and in white-on-white text — invisible to a human skimming the rendered page, but
pulled straight into agent context by the Researcher's naive HTML-to-text
extractor. This models real **indirect prompt injection**: the attacker never
talks to the agent directly, they only leave content the agent will later read.

### Attack walkthrough

1. The user gives a benign task; the Planner emits a `research_query`.
2. The Researcher fetches `poisoned_page.html`. The hidden payload instructs the
   Executor to "verify the runtime" by log-searching a term that contains shell
   metacharacters.
3. The poisoned text lands in `research_findings` with no trust label.
4. The Executor, reading it as legitimate research, calls `search_logs(term=...)`.
   The metacharacters break out of the intended `findstr`/`grep` command and the
   injected `echo INJECTED-ASI02-CONFUSED-DEPUTY` executes — proof that
   attacker-controlled content reached a privileged tool.

The marker string `INJECTED-ASI02-CONFUSED-DEPUTY` in the execution log is the
success signal. In a real system that command could exfiltrate data, modify
files, or pivot — here it is a harmless, greppable marker by design.

### OWASP mapping

- **Primary:** OWASP Top 10 for Agentic Applications — **ASI02 Tool Misuse and
  Exploitation** (an agent's tools invoked to serve an attacker's goal).
- **Related agentic risk:** ASI06 Memory and Context Poisoning (the vector is
  untrusted content entering the agent's context without a trust boundary).
- **OWASP Top 10 for LLM Applications (2025) crosswalk:** LLM01 Prompt Injection
  (indirect), and LLM06 Excessive Agency (unbounded tool permissions with no
  human confirmation on a state-changing action).

## Prerequisites

- Python 3.10+ (or Docker).
- An LLM API key. This sample uses OpenAI via `langchain-openai`; set
  `OPENAI_API_KEY` (and optionally `OPENAI_MODEL`, default `gpt-4o-mini`).

```bash
pip install -r requirements.txt
cp .env.example .env      # then edit .env and add your OPENAI_API_KEY
python agent.py --attack
```

Or with Docker:

```bash
docker build -t asi02-langgraph .
docker run --rm -e OPENAI_API_KEY=sk-... asi02-langgraph --attack
```

> The demonstration depends on the model following the injected instruction —
> which is the point of the vulnerability class. Because the tools themselves are
> unguarded, once the model is induced to call `search_logs` with the crafted
> term, the injected command executes regardless of model reasoning.

## Mitigating strategies

The flaws map directly to fixes:

- **Label and separate provenance.** Tag every entry written to shared state with
  its source (user vs fetched vs tool output) and never let the Executor treat
  fetched content as instruction. Keep untrusted data in a distinct channel from
  the agent's directives.
- **Enforce the confused-deputy check.** Gate privileged actions on
  `trigger_source` / an explicit authorization step; actions derived from
  untrusted content should require human confirmation or be denied.
- **Constrain tools, not just prompts.** Replace `shell=True` with an allowlisted,
  parameterised interface; pass tool arguments as argv (never string-interpolated
  into a shell); run the Executor in a least-privilege sandbox.
- **Sanitise ingested content.** Strip HTML comments and non-visible text on
  fetch, and treat all fetched text as data, not commands.
- **Least agency.** The Researcher never needs shell access; the Executor never
  needs raw fetched HTML. Scope each agent's tools to its actual job.
