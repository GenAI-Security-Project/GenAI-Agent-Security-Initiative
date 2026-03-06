# Agent OS — Governance Framework for Agentic AI Security

[Agent OS](https://github.com/microsoft/agent-governance-toolkit) is an open-source governance kernel for autonomous AI agents. It provides runtime policy enforcement, capability sandboxing, and kill-switch controls — addressing 9 of 10 OWASP Agentic Top 10 risks.

## Architecture

Agent OS uses a **kernel-based** approach inspired by operating system design:

| Component | OWASP Risk Mitigated | Description |
|-----------|---------------------|-------------|
| **Policy Engine** | ASI-01 (Agent Hijacking) | Runtime policy enforcement prevents goal drift |
| **Capability Sandbox** | ASI-02 (Tool Misuse) | Ring-based permission model limits agent capabilities |
| **DID Identity** (Agent Mesh) | ASI-03 (Insecure Identity) | Decentralized identity for inter-agent trust |
| **Execution Rings** (Hypervisor) | ASI-05 (Insecure Output) | Tiered execution with output validation |
| **VFS + CMVK** | ASI-06 (Prompt/Memory Poisoning) | Virtual filesystem with content verification |
| **IATP Protocol** (Agent Mesh) | ASI-07 (Insufficient Monitoring) | Inter-Agent Trust Protocol with audit trails |
| **Circuit Breakers** (Agent SRE) | ASI-08 (Error Handling) | Graceful degradation and fallback patterns |
| **Approval Workflows** | ASI-09 (Human-in-the-Loop Bypass) | Configurable approval gates for sensitive actions |
| **Kill Switch** (Hypervisor) | ASI-10 (Uncontrolled Autonomy) | Emergency shutdown with state preservation |

## Samples in This Directory

Each subdirectory contains:
1. **`insecure.py`** — A deliberately vulnerable agent demonstrating the risk
2. **`secure.py`** — The same agent secured with Agent OS governance
3. **`README.md`** — Vulnerability description and mitigation strategy

### Available Samples

| Sample | Risk | Vulnerability Demonstrated |
|--------|------|---------------------------|
| [ASI-01-agent-hijacking](./ASI-01-agent-hijacking/) | Agent Goal Hijacking | Unrestricted goal modification via prompt injection |
| [ASI-02-excessive-capabilities](./ASI-02-excessive-capabilities/) | Excessive Tool Access | Agent with unrestricted filesystem and network access |
| [ASI-05-insecure-output](./ASI-05-insecure-output/) | Insecure Output Handling | Unvalidated agent outputs passed to downstream systems |

## Prerequisites

```bash
pip install agent-os agentmesh agent-hypervisor
```

## Links

- [Agent OS](https://github.com/microsoft/agent-governance-toolkit) — Governance kernel
- [Agent Mesh](https://github.com/microsoft/agent-governance-toolkit) — Inter-agent trust layer
- [Agent Hypervisor](https://github.com/microsoft/agent-governance-toolkit) — Execution isolation
- [Agent SRE](https://github.com/microsoft/agent-governance-toolkit) — Observability & reliability
- [Agent Governance](https://github.com/microsoft/agent-governance-toolkit) — Meta-framework & compliance
- [OWASP Compliance Mapping](https://github.com/microsoft/agent-governance-toolkit/blob/master/docs/OWASP-COMPLIANCE.md)
