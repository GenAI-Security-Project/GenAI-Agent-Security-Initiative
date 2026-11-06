# ASI03 / ASI07 / ASI09 A2A Identity Binding and Confused-Deputy Verifier

Zero-dependency Python 3.11+ reference control for multi-agent Agent-to-Agent (A2A) calls. A tool server honors a call only when the presented agent card is signed, unexpired, single-use, bound to the key authenticated on this channel, bound to the claimed agent id, and minted for this server.

- **ASI03 (Identity and Privilege Abuse):** A peer that presents another agent's still-valid card is denied because the channel key must equal the card's key id, and that key id must be registered to the card's agent id.
- **ASI07 (Insecure Inter-Agent Communication):** Card and delegation signatures are HMAC-SHA256 over a canonical payload. A tampered capability list or a replayed nonce fails closed.
- **ASI09 (Human-Agent Trust Exploitation):** A card minted for a different audience cannot make this server act as a confused deputy. A delegation whose subject is not the card's agent id is denied.

This sample does not replace commit-point authorization, MCP tool-description pinning, or swarm quarantine. Those are separate controls.

## Run locally

```bash
python main.py
python -m unittest discover -v
```

No third-party packages are required.

## What the demo prints

`python main.py` allows a card presented on its own channel to `files`, then denies the same style of card presented on Mallory's channel and a payments card presented to the files server.
