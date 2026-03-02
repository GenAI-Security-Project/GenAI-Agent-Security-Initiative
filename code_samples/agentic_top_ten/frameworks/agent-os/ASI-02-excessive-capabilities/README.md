# ASI-02: Excessive Agent Capabilities / Tool Misuse

## Vulnerability

An agent granted unrestricted access to tools (filesystem, network, databases) can perform destructive operations beyond its intended scope. Without capability sandboxing, any agent can read, write, or delete arbitrary resources.

**OWASP Reference:** [ASI-02 — Excessive Agency / Tool Misuse](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

## Insecure Example (`insecure.py`)

The insecure agent has full filesystem and network access:
- Can read any file on the system
- Can write to any directory
- Can make arbitrary network requests
- No permission boundaries

## Secure Example (`secure.py`)

Agent OS Capability Sandbox restricts agent permissions:
- Ring-based permission model (Ring 0–3) limits scope
- Filesystem access restricted to a virtual sandbox
- Network calls require explicit capability grants
- All tool invocations are audited

## Mitigation Strategy

1. Define capability grants per agent in the policy file
2. Use Agent OS `CapabilitySandbox` to enforce least-privilege access
3. Assign agents to appropriate execution rings (Ring 3 = most restricted)
4. Monitor tool usage with `AuditLogger`
