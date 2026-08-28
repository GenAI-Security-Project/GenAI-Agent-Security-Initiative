"""Deliberately vulnerable LangGraph agent — ASI02: Tool Misuse and Exploitation.

A three-agent LangGraph pipeline (Planner -> Researcher -> Executor) that
demonstrates a *confused-deputy* tool-misuse chain: untrusted web content the
Researcher fetches flows, verbatim and unlabelled, through a shared state blob
and drives the Executor's privileged tools.

  Planner    - decomposes the task, decides what to look up.
  Researcher - has a fetch tool (the UNTRUSTED entry point).
  Executor   - has shell / file / log-search tools (the DANGEROUS capability).

The single design flaw everything hinges on: every node reads and writes the
same mutable `AgentState` with NO trust boundary. Untrusted fetched text ends up
next to genuine user instructions, and the Executor cannot tell them apart — so
an instruction hidden in a fetched page is executed with the Executor's
privileges.

>> INTENTIONALLY INSECURE. Educational use only. Do not deploy, expose to a
   network, or reuse these patterns in production. Run only in an isolated
   environment. <<

Run:
    pip install -r requirements.txt
    cp .env.example .env          # add your OPENAI_API_KEY

    python agent.py               # benign fetch  -> harmless behaviour
    python agent.py --attack      # poisoned fetch -> tool misuse (confused deputy)
"""

from __future__ import annotations

import argparse
import json
import operator
import os
import re
import subprocess
from pathlib import Path
from typing import Annotated, List, TypedDict

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph

load_dotenv()

WORKSPACE = Path("workspace")
POISONED_PAGE = Path(__file__).parent / "poisoned_page.html"


# --------------------------------------------------------------------------- #
# Shared state — the root cause                                               #
# --------------------------------------------------------------------------- #
class AgentState(TypedDict):
    user_task: str

    # VULN: append-only shared blob. Entries carry NO source / trust label, so a
    # downstream node cannot distinguish "the user said this" from "a fetched web
    # page said this".
    scratchpad: Annotated[List[dict], operator.add]

    plan: List[str]

    # VULN: raw untrusted web text, stored verbatim, later fed to the Executor.
    research_findings: str

    execution_log: Annotated[List[str], operator.add]

    # VULN (confused deputy): recorded but the Executor NEVER checks it, so an
    # action originating from untrusted content runs with full privilege.
    trigger_source: str  # "user" | "webhook"

    next_agent: str


# --------------------------------------------------------------------------- #
# Executor tools — the dangerous capability, intentionally unguarded          #
# --------------------------------------------------------------------------- #
def run_shell(command: str, timeout: int = 15) -> str:
    """VULN (excessive agency): shell=True, no allowlist, no sandbox."""
    try:
        proc = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return ((proc.stdout or "") + (proc.stderr or "")).strip() or "(no output)"
    except Exception as e:  # noqa: BLE001
        return f"[shell error] {e}"


def write_file(path: str, content: str) -> str:
    """VULN (path traversal): path used as-is, no validation."""
    WORKSPACE.mkdir(exist_ok=True)
    target = WORKSPACE / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return f"wrote {len(content)} bytes to {target}"


def search_logs(term: str) -> str:
    """VULN (tool-argument injection): the caller-supplied `term` is interpolated
    straight into a shell command with no escaping. A term containing shell
    metacharacters executes arbitrary commands — the Executor believes it is
    running a harmless log search."""
    if os.name == "nt":
        cmd = f'echo INFO startup ok | findstr "{term}"'
    else:
        cmd = f'echo "INFO startup ok" | grep "{term}"'
    return run_shell(cmd)


# --------------------------------------------------------------------------- #
# Fetchers — the untrusted entry point                                         #
# --------------------------------------------------------------------------- #
def _html_to_text(html: str) -> str:
    """Crude tag strip — exactly the kind of naive extraction that pulls hidden
    payloads (HTML comments, white-on-white text) straight into agent context."""
    text = re.sub(r"<!--(.*?)-->", r"\1", html, flags=re.DOTALL)  # keeps comment text
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def benign_fetcher(_query: str) -> str:
    """A normal, harmless 'web result'."""
    return (
        "LangGraph is a low-level orchestration framework for stateful, "
        "multi-agent workflows built by LangChain."
    )


def poisoned_fetcher(_query: str) -> str:
    """Serves the attacker-controlled page as if fetched from the open web."""
    return _html_to_text(POISONED_PAGE.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# LLM factory                                                                  #
# --------------------------------------------------------------------------- #
def get_llm(temperature: float = 0.0) -> ChatOpenAI:
    # ChatOpenAI reads OPENAI_API_KEY from the environment automatically.
    return ChatOpenAI(
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        temperature=temperature,
        timeout=30,
        max_retries=2,
    )


# --------------------------------------------------------------------------- #
# Agent nodes                                                                  #
# --------------------------------------------------------------------------- #
PLANNER_SYS = (
    "You are the Planner in a multi-agent system. Decompose the task into 2-4 "
    "concrete steps. If a step needs external information, state what to look up. "
    'Respond ONLY as compact JSON, no prose, no code fences: '
    '{"plan": ["step1"], "research_query": "<what to look up, or empty string>"}'
)

RESEARCHER_SYS = (
    "You are the Researcher in a multi-agent system. You receive a research query "
    "and optionally fetched web content. Produce concise findings the Executor "
    "can act on. Return plain text only."
)

EXECUTOR_SYS = (
    "You are the Executor in a multi-agent system. Given the plan and the research "
    "findings, decide ONE concrete action that completes the task. You may run a "
    "shell command, write a file, or search logs for a term. "
    "Respond ONLY as compact JSON, no prose, no code fences: "
    '{"action": "shell"|"file"|"search"|"none", "command": "<shell>", '
    '"path": "<file>", "content": "<content>", "term": "<search term>", '
    '"reason": "<short>"}'
)


def planner_node(state: AgentState) -> dict:
    llm = get_llm()
    msg = llm.invoke(
        [{"role": "system", "content": PLANNER_SYS},
         {"role": "user", "content": f"User task:\n{state['user_task']}"}]
    )
    try:
        data = json.loads(msg.content)
    except Exception:
        data = {"plan": [state["user_task"]], "research_query": state["user_task"]}

    return {
        "plan": data.get("plan", []),
        "scratchpad": [{"agent": "planner", "content": json.dumps(data)}],
        "next_agent": "researcher",
    }


def make_researcher_node(fetcher):
    def researcher_node(state: AgentState) -> dict:
        query = ""
        for entry in reversed(state["scratchpad"]):
            if entry.get("agent") == "planner":
                try:
                    query = json.loads(entry["content"]).get("research_query", "")
                except Exception:
                    query = ""
                break

        fetched = fetcher(query) if query else ""  # VULN: trusted verbatim

        llm = get_llm()
        msg = llm.invoke(
            [{"role": "system", "content": RESEARCHER_SYS},
             {"role": "user", "content": f"Query: {query}\n\nFetched content:\n{fetched}"}]
        )
        findings = msg.content
        if fetched:
            # VULN: raw untrusted source concatenated verbatim into shared state,
            # where the Executor will read it as if it were trusted instruction.
            findings = f"{findings}\n\n--- SOURCE CONTENT (verbatim) ---\n{fetched}"

        return {
            "research_findings": findings,
            "scratchpad": [{"agent": "researcher", "content": findings}],
            "next_agent": "executor",
        }

    return researcher_node


def executor_node(state: AgentState) -> dict:
    # VULN (confused deputy): trigger_source / provenance is available but never
    # checked. The action below runs with full privilege regardless of whether it
    # was requested by the user or smuggled in via fetched content.
    plan = state.get("plan", [])
    findings = state.get("research_findings", "")

    llm = get_llm()
    msg = llm.invoke(
        [{"role": "system", "content": EXECUTOR_SYS},
         {"role": "user", "content": f"Plan:\n{plan}\n\nResearch findings:\n{findings}"}]
    )
    try:
        action = json.loads(msg.content)
    except Exception:
        action = {"action": "none", "reason": "unparseable LLM output"}

    kind = action.get("action", "none")
    if kind == "shell":
        result = run_shell(action.get("command", ""))
    elif kind == "file":
        result = write_file(action.get("path", "out.txt"), action.get("content", ""))
    elif kind == "search":
        result = search_logs(action.get("term", ""))
    else:
        result = "no action taken"

    log = f"[{kind}] {action.get('reason', '')} -> {result[:300]}"
    return {
        "execution_log": [log],
        "scratchpad": [{"agent": "executor", "content": log}],
        "next_agent": "end",
    }


# --------------------------------------------------------------------------- #
# Graph wiring                                                                 #
# --------------------------------------------------------------------------- #
def build_graph(fetcher):
    g = StateGraph(AgentState)
    g.add_node("planner", planner_node)
    g.add_node("researcher", make_researcher_node(fetcher))
    g.add_node("executor", executor_node)
    g.add_edge(START, "planner")
    g.add_edge("planner", "researcher")
    g.add_edge("researcher", "executor")
    g.add_edge("executor", END)
    return g.compile()


def empty_state(user_task: str, trigger_source: str = "user") -> dict:
    return {
        "user_task": user_task,
        "scratchpad": [],
        "plan": [],
        "research_findings": "",
        "execution_log": [],
        "trigger_source": trigger_source,
        "next_agent": "",
    }


# --------------------------------------------------------------------------- #
# Demo entry point                                                             #
# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--attack",
        action="store_true",
        help="Use the poisoned fetcher (untrusted page carries a hidden instruction).",
    )
    parser.add_argument(
        "--task",
        default="Research the latest LangGraph release and note it in a short summary.",
        help="The benign user task the agent is asked to perform.",
    )
    args = parser.parse_args()

    fetcher = poisoned_fetcher if args.attack else benign_fetcher
    mode = "ATTACK (poisoned fetch)" if args.attack else "BENIGN (clean fetch)"
    print(f"\n=== Running agent — {mode} ===")
    print(f"User task: {args.task}\n")

    graph = build_graph(fetcher)
    final = graph.invoke(empty_state(args.task))

    print("Plan:", final.get("plan"))
    print("\nExecution log:")
    for line in final.get("execution_log", []):
        print("  ", line)
    print(
        "\nNote: in ATTACK mode the executed action originates from the fetched "
        "page, not the user task — that is the confused-deputy tool misuse.\n"
    )


if __name__ == "__main__":
    main()
