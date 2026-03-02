# ASI-01: Agent Goal Hijacking

## Vulnerability

An agent without policy enforcement can have its goals modified at runtime through prompt injection or malicious instructions from upstream agents. Without governance controls, the agent blindly executes whatever goal it receives.

**OWASP Reference:** [ASI-01 — Prompt Injection / Agent Hijacking](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

## Insecure Example (`insecure.py`)

The insecure agent accepts any goal modification without validation:
- No policy checks on incoming goals
- No boundary enforcement on permitted actions
- Malicious upstream agent can redirect the agent to exfiltrate data

## Secure Example (`secure.py`)

Agent OS Policy Engine enforces runtime governance:
- Goals are validated against a declarative policy file
- Out-of-scope actions are blocked before execution
- All goal changes are logged to an audit trail

## Mitigation Strategy

1. Define permitted goals in a YAML policy file
2. Use Agent OS `PolicyEngine` to validate all incoming goals at runtime
3. Enable audit logging for all goal transitions
4. Set `strict_mode: true` to reject any goal not explicitly permitted
