# ASI09: evidence provenance before human review

This offline Python 3.9+ sample illustrates a guard against presenting an
unsupported agent claim as review-ready. A separately managed registry pins
approved source IDs to SHA-256 digests. Every citation must refer to an approved,
unchanged source and contain a nonblank exact quotation; missing or changed
evidence withholds the claim. The sample makes no external effects.

```sh
python -B main.py
python -B -m unittest -v
```

Passing the check **does not establish that the claim is true, that the quote
entails it, or that the source is authoritative**. A human must assess relevance,
completeness and truth before acting. In production, source acquisition and the
approved digest registry must be independently authenticated and protected from
the agent; this illustrative in-memory sample supplies neither.
