# ASI03 Concurrent Delegated-Authority Conservation (`DA-01`..`DA-06`)

Zero-dependency Python 3.11+ reference sample demonstrating executable enforcement of the six formal delegated-authority boundary invariants discussed in [GenAI-Agent-Security-Initiative#19](https://github.com/GenAI-Security-Project/GenAI-Agent-Security-Initiative/issues/19) under **ASI03: Identity & Privilege Abuse**.

## Invariants Enforced

| Invariant | Name | Security Property |
|---|---|---|
| `DA-01` | Origin Non-Escalation | Root grant capabilities and budget cannot exceed the human principal's ceiling. |
| `DA-02` | Monotonic Attenuation | Every child hop narrows capabilities (`child <= parent`), expiry, and budget. |
| `DA-03` | Revocation Cascade | Revoking any grant atomically invalidates all transitive descendants. |
| `DA-04` | Sibling Budget Conservation | Concurrent subagents cannot double-spend a shared parent budget (`sum(children) + consumed <= budget`). |
| `DA-05` | Commit-Point Re-Verification | Side-effecting actions re-verify the full ancestor chain at execution time, closing TOCTOU windows. |
| `DA-06` | Cryptographic Lineage Binding | Each grant carries an HMAC-SHA256 digest over its scope, budget, expiry, and parent digest. |

## Run Locally

```bash
python main.py
python -m unittest discover -v
```
