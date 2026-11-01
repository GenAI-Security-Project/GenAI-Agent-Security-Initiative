"""Original local non-formation companions; not an AISVS or AECP certification."""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import math
import re
import secrets
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable


SOURCE_COMMIT = "8906b2be8341abbf4dc43411374681fb81e6ddc6"
SOURCE_PATH = "1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md"
LEVELS = {f"C9.2.{n}": 1 if n == 1 else 2 if n <= 7 else 3 for n in range(1, 11)}
ASIS = {f"ASI{n:02}" for n in range(1, 11)}
ALL_C9 = {f"C9.{chapter}.{number}"
          for chapter, count in {1: 3, 2: 10, 3: 8, 4: 4, 5: 6, 6: 3}.items()
          for number in range(1, count + 1)}
SURFACES = frozenset({"release", "code", "memory", "handoff", "shadow"})
ATTACK_TYPES = {
    "goal": str, "tool": str, "manifest_json": str, "code": str,
    "memory_source": str, "memory_tainted": bool, "parameters_json": str,
    "fanout": int, "approval_grade": int, "revoke_actor": bool,
}


class Invalid(ValueError):
    pass


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise Invalid(f"non-finite JSON constant: {value}")


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs,
                          parse_constant=_reject_constant)
    except (OSError, ValueError) as exc:
        raise Invalid(f"cannot load {path.name}: {exc}") from exc


def _validate(crosswalk: dict, fixture_document: dict) -> None:
    if (type(crosswalk.get("schema_version")) is not int
            or type(fixture_document.get("schema_version")) is not int
            or crosswalk.get("schema_version") != 1 or fixture_document.get("schema_version") != 1
            or crosswalk.get("standard") != "OWASP AISVS" or crosswalk.get("edition") != "1.0"
            or crosswalk.get("source_commit") != SOURCE_COMMIT
            or crosswalk.get("source_path") != SOURCE_PATH
            or crosswalk.get("source_url") !=
            f"https://github.com/OWASP/AISVS/blob/{SOURCE_COMMIT}/{SOURCE_PATH}"):
        raise Invalid("unsupported schema, edition, or unpinned source")
    requirements = crosswalk.get("requirements", {})
    if set(requirements) != set(LEVELS):
        raise Invalid("crosswalk must enumerate exactly C9.2.1..C9.2.10")
    for identifier, requirement in requirements.items():
        expected = "not_demonstrated" if identifier in {"C9.2.6", "C9.2.7", "C9.2.9"} else "boundary_subset"
        if (type(requirement.get("level")) is not int
                or requirement.get("level") != LEVELS[identifier]
                or requirement.get("demonstration") != expected or not requirement.get("summary")):
            raise Invalid("incorrect requirement level or overstated demonstration")
    entries = crosswalk.get("entries", [])
    fixtures = fixture_document.get("fixtures", [])
    if (len(entries) != 10 or {entry["asi"] for entry in entries} != ASIS
            or len(fixtures) != 10 or {fixture["asi"] for fixture in fixtures} != ASIS
            or len({fixture["id"] for fixture in fixtures}) != 10):
        raise Invalid("ASI coverage or fixture identifiers are incomplete/duplicated")
    indexed = {fixture["id"]: fixture for fixture in fixtures}
    sources = fixture_document.get("sources", {})
    for source in sources.values():
        if (not source.get("url", "").startswith("https://")
                or not source.get("locator") or not source.get("status")):
            raise Invalid("incident source requires URL, locator, and status")
    for entry in entries:
        fixture = indexed.get(entry.get("fixture"))
        if fixture is None or fixture["asi"] != entry["asi"] or not entry.get("limitations"):
            raise Invalid("mismatched fixture linkage or missing coverage limitations")
        mappings = entry.get("mappings", [])
        identifiers = [mapping.get("requirement") for mapping in mappings]
        if (not identifiers or len(set(identifiers)) != len(identifiers)
                or len(set(fixture.get("controls", []))) != len(fixture.get("controls", []))
                or set(identifiers) != set(fixture.get("controls", []))):
            raise Invalid("missing, duplicated, or mismatched requirement mappings")
        for mapping in mappings:
            if (mapping.get("requirement") not in LEVELS
                    or mapping.get("coverage") not in {"boundary_subset", "context_only"}
                    or not mapping.get("rationale")
                    or requirements[mapping["requirement"]]["demonstration"] == "not_demonstrated"):
                raise Invalid("unknown requirement or unsupported coverage claim")
        if (fixture.get("surface") not in SURFACES - {"shadow"}
                or fixture.get("source") not in sources
                or fixture.get("derivation") not in {"analogous", "direct"}
                or not fixture.get("incident_basis") or not fixture.get("attack")):
            raise Invalid("invalid protected surface or missing incident derivation")
        for key, value in fixture["attack"].items():
            if key not in ATTACK_TYPES or type(value) is not ATTACK_TYPES[key]:
                raise Invalid("unknown or incorrectly typed attack mutation")
        if any(not re.fullmatch(r"C9\.[1-6]\.[1-9][0-9]*", control) or control not in ALL_C9
               for control in entry.get("additional_controls", [])):
            raise Invalid("malformed contextual control identifier")


def validate(crosswalk: dict, fixture_document: dict) -> None:
    try:
        _validate(crosswalk, fixture_document)
    except (KeyError, TypeError, AttributeError) as exc:
        raise Invalid("malformed crosswalk or fixture document structure") from exc


def load_documents(directory: Path | None = None) -> tuple[dict, dict]:
    directory = directory or Path(__file__).resolve().parent
    crosswalk, fixtures = read_json(directory / "crosswalk.json"), read_json(directory / "fixtures.json")
    validate(crosswalk, fixtures)
    return crosswalk, fixtures


@dataclass(frozen=True)
class Request:
    actor: str = "worker"
    tool: str = "write_note"
    target: str = "mock://approved"
    goal: str = "summarize"
    parameters_json: str = '{"recipient":"owner@example.invalid","text":"summary"}'
    manifest_json: str = '{"tools":["write_note"]}'
    code: str = "add(2,3)"
    memory_source: str = "verified_fixture"
    memory_tainted: bool = False
    fanout: int = 1
    approval_grade: int = 2
    nonce: str = ""
    expires_at: float = 1100.0
    epoch: int = 1


def action_payload(request: Request) -> dict:
    return {field: getattr(request, field) for field in
            ("actor", "tool", "target", "goal", "parameters_json", "nonce", "expires_at", "epoch")}


class Boundary:
    def __init__(self, asi: str, request: Request) -> None:
        self.asi = asi
        self.__key = secrets.token_bytes(32)
        self.goal = "summarize"
        self.catalog = {"write_note": 2}
        self.parent_scope = frozenset({"write_note", "send_external"})
        self.child_scope = frozenset({"write_note"})
        self.chain_grades = (0, 2)
        self.effect_budget = 4
        self.revoked: set[str] = set()
        self.used: set[str] = set()
        self.epoch = 1
        self.now = 1000.0
        self.manifest_pin = hashlib.sha256(request.manifest_json.encode()).hexdigest()
        self.grant = {"actor": request.actor, "scope": sorted(self.child_scope),
                      "target": request.target, "epoch": request.epoch, "nonce": request.nonce,
                      "expires_at": request.expires_at, "goal": request.goal}
        self.grant_mac = self._sign("grant", self.grant)
        self.approval_display = canonical(action_payload(request))
        self.approval_mac = self._sign("approval", action_payload(request))
        self.handoff_mac = self._sign("handoff", action_payload(request))
        self.memory_mac = self._sign("memory", self._memory_payload(request))

    def _sign(self, domain: str, value: dict) -> str:
        return hmac.new(self.__key, (domain + ":" + canonical(value)).encode(),
                        hashlib.sha256).hexdigest()

    @staticmethod
    def _memory_payload(request: Request) -> dict:
        return {"source": request.memory_source, "tainted": request.memory_tainted,
                "value": request.parameters_json, "nonce": request.nonce}

    @staticmethod
    def _code_is_safe(source: str) -> bool:
        if type(source) is not str or len(source) > 128:
            return False
        try:
            tree = ast.parse(source, mode="eval")
        except (SyntaxError, ValueError, RecursionError):
            return False
        # The sole code capability is a fixed-arity plain-integer addition.
        call = tree.body
        return (type(call) is ast.Call and type(call.func) is ast.Name
                and call.func.id == "add" and not call.keywords and len(call.args) == 2
                and all(type(arg) is ast.Constant and type(arg.value) is int
                        and 0 <= arg.value <= 100 for arg in call.args))

    def allows(self, request: Request) -> bool:
        if (type(request.epoch) is not int or request.epoch != self.epoch
                or not math.isfinite(request.expires_at) or request.expires_at <= self.now
                or type(request.nonce) is not str or not 0 < len(request.nonce) <= 128
                or request.nonce in self.used or request.target != "mock://approved"
                or type(request.fanout) is not int or type(request.approval_grade) is not int
                or request.approval_grade not in range(4)):
            return False
        try:
            parameters = json.loads(request.parameters_json, object_pairs_hook=_unique_pairs)
            if (type(parameters) is not dict or set(parameters) != {"recipient", "text"}
                    or any(type(value) is not str or not 0 < len(value) <= 512
                           for value in parameters.values())
                    or canonical(parameters) != request.parameters_json):
                return False
        except (ValueError, TypeError):
            return False
        if self.asi == "ASI01":
            return (request.goal == self.goal and hmac.compare_digest(
                self.approval_mac, self._sign("approval", action_payload(request))))
        if self.asi == "ASI02":
            return request.tool in self.catalog and request.approval_grade >= self.catalog[request.tool]
        if self.asi == "ASI03":
            return (hmac.compare_digest(self.grant_mac, self._sign("grant", self.grant))
                    and request.actor == self.grant["actor"] and request.target == self.grant["target"]
                    and request.nonce == self.grant["nonce"]
                    and request.expires_at == self.grant["expires_at"]
                    and request.goal == self.grant["goal"]
                    and self.child_scope <= self.parent_scope
                    and request.tool in self.child_scope)
        if self.asi == "ASI04":
            return hashlib.sha256(request.manifest_json.encode()).hexdigest() == self.manifest_pin
        if self.asi == "ASI05":
            return self._code_is_safe(request.code)
        if self.asi == "ASI06":
            return (request.memory_source == "verified_fixture" and not request.memory_tainted
                    and hmac.compare_digest(self.memory_mac,
                                            self._sign("memory", self._memory_payload(request))))
        if self.asi == "ASI07":
            return hmac.compare_digest(self.handoff_mac, self._sign("handoff", action_payload(request)))
        if self.asi == "ASI08":
            return (0 < request.fanout <= self.effect_budget
                    and request.approval_grade >= max(self.chain_grades))
        if self.asi == "ASI09":
            return hmac.compare_digest(self.approval_mac, self._sign("approval", action_payload(request)))
        if self.asi == "ASI10":
            return (request.actor not in self.revoked and request.tool in self.child_scope
                    and hmac.compare_digest(self.approval_mac,
                                            self._sign("approval", action_payload(request))))
        raise Invalid("unsupported ASI boundary")


class World:
    def __init__(self) -> None:
        self._surfaces: dict[str, list[str]] = {surface: [] for surface in SURFACES}

    def snapshot(self) -> dict[str, tuple[str, ...]]:
        return {surface: tuple(values) for surface, values in sorted(self._surfaces.items())}


class EffectPort:
    """Policy-free port: an adapter's denial does not protect these surfaces."""

    def __init__(self, world: World, surface: str) -> None:
        self.world, self.surface = world, surface

    def write(self, content: str, *, surface: str | None = None) -> None:
        target = surface or self.surface
        if target not in SURFACES:
            raise Invalid("unknown synthetic surface")
        self.world._surfaces[target].append(content)


Adapter = Callable[[Boundary, Request, EffectPort], str]


def protected_adapter(boundary: Boundary, request: Request, port: EffectPort) -> str:
    if not boundary.allows(request):
        return "DENY"
    boundary.used.add(request.nonce)
    port.write(canonical(action_payload(request)))
    return "ALLOW"


def permissive_adapter(boundary: Boundary, request: Request, port: EffectPort) -> str:
    port.write(canonical(action_payload(request)))
    return "ALLOW"


@dataclass(frozen=True)
class Observation:
    decision: str
    formed: bool
    changed_surfaces: tuple[str, ...]
    added_events: int


def observe(decision: str, before: dict, after: dict) -> Observation:
    if decision not in {"ALLOW", "DENY"}:
        raise Invalid("adapter returned an invalid decision")
    keys = set(before) | set(after)
    changed = tuple(sorted(key for key in keys if before.get(key, ()) != after.get(key, ())))
    return Observation(decision, bool(changed), changed,
                       sum(len(after.get(key, ())) - len(before.get(key, ())) for key in keys))


def exercise(fixture: dict, *, negative: bool, adapter: Adapter = protected_adapter) -> Observation:
    request = Request(nonce=fixture["id"] + ":1")
    boundary = Boundary(fixture["asi"], request)
    if negative:
        attack = fixture["attack"]
        if attack.get("revoke_actor"):
            boundary.revoked.add(request.actor)
        request = replace(request, **{key: value for key, value in attack.items()
                                     if key != "revoke_actor"})
    world = World()
    port = EffectPort(world, fixture["surface"])
    before = world.snapshot()
    try:
        decision = adapter(boundary, request, port)
    except Exception as exc:
        raise Invalid("adapter error is not evidence of non-formation") from exc
    return observe(decision, before, world.snapshot())


def verify_observation(fixture: dict, observation: Observation, *, negative: bool) -> None:
    if negative:
        valid = observation.decision == "DENY" and not observation.formed
    else:
        valid = (observation.decision == "ALLOW" and observation.formed
                 and observation.changed_surfaces == (fixture["surface"],)
                 and observation.added_events == 1)
    if not valid:
        raise Invalid(f"{fixture['id']}: decision/effect divergence or wrong protected surface")


def verify_suite(adapter: Adapter = protected_adapter) -> dict:
    crosswalk, document = load_documents()
    rows = []
    for fixture in document["fixtures"]:
        for negative in (True, False):
            observation = exercise(fixture, negative=negative, adapter=adapter)
            verify_observation(fixture, observation, negative=negative)
        baseline = exercise(fixture, negative=True, adapter=permissive_adapter)
        if (baseline.decision != "ALLOW" or not baseline.formed
                or baseline.changed_surfaces != (fixture["surface"],)):
            raise Invalid("negative effect path is unreachable in permissive baseline")
        rows.append({"asi": fixture["asi"], "fixture": fixture["id"], "result": "passed"})
    return {"edition": crosswalk["edition"], "source_commit": crosswalk["source_commit"],
            "protected_cases": len(rows) * 2, "permissive_reachability_cases": len(rows),
            "certification": False, "results": rows}


if __name__ == "__main__":
    print(json.dumps(verify_suite(), indent=2, sort_keys=True))
