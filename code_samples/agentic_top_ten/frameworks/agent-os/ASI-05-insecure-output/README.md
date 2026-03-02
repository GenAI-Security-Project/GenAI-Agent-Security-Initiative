# ASI-05: Insecure Output Handling

## Vulnerability

An agent that passes its outputs directly to downstream systems without validation enables injection attacks, data corruption, and privilege escalation. Unvalidated agent output can contain SQL injection, command injection, or malicious payloads.

**OWASP Reference:** [ASI-05 — Insecure Output Handling](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

## Insecure Example (`insecure.py`)

The insecure pipeline passes raw agent output to a database:
- Agent output is directly interpolated into SQL queries
- No output sanitization or validation
- Downstream system trusts agent output implicitly

## Secure Example (`secure.py`)

Agent Hypervisor execution rings validate all outputs:
- Output passes through a validation layer before reaching downstream systems
- SQL parameterization enforced automatically
- Content type verification prevents injection attacks
- All outputs are logged for audit

## Mitigation Strategy

1. Use Agent Hypervisor execution rings to enforce output validation
2. Never interpolate agent output directly into queries or commands
3. Define output schemas and validate agent responses against them
4. Log all agent outputs for forensic analysis
