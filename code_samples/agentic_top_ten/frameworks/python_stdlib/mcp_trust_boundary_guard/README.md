# ASI02 / ASI04 / ASI07 MCP Trust-Boundary & Tool-Description Poisoning Guard

Zero-dependency Python 3.11+ reference sample demonstrating deterministic host-side controls for Model Context Protocol (MCP) tool discovery and invocation across trust boundaries:

- **ASI02 (Tool Misuse & Exploitation)**: Rejects covert instruction-injection patterns and bidirectional / zero-width Unicode smuggling (`U+200B`..`U+2067`, `U+FEFF`) in tool descriptions and JSON schemas, and blocks untrusted provenance values from flowing into high-impact sink arguments (`payments/transfer`, `filesystem/write`, `email/send_external`).
- **ASI04 (Agentic Supply Chain Vulnerabilities)**: Cryptographically pins each registered tool descriptor (`canonical_digest()` over `server_id`, `name`, `description`, `input_schema`) and blocks mid-session "rug-pull" mutations at invocation time.
- **ASI07 (Insecure Inter-Agent Communication)**: Prevents untrusted MCP servers from shadowing bare tool names owned by trusted servers.

## Run Locally

```bash
python main.py
python -m unittest discover -v
```
