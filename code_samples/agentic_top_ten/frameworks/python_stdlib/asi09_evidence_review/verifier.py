"""Verify citation provenance before presenting a claim for human review."""

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class Citation:
    source_id: str
    quote: str


def source_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def eligible_for_review(
    claim: str,
    citations: list[Citation],
    approved_digests: Mapping[str, str],
    sources: Mapping[str, str],
) -> bool:
    """Return whether every citation points to an approved, unchanged source."""
    if not isinstance(claim, str) or not claim.strip() or not citations:
        return False
    for citation in citations:
        if not isinstance(citation, Citation):
            return False
        if not isinstance(citation.source_id, str) or not isinstance(citation.quote, str):
            return False
        if not citation.source_id.strip() or not citation.quote.strip():
            return False
        expected = approved_digests.get(citation.source_id)
        content = sources.get(citation.source_id)
        if (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)
                or not isinstance(content, str)):
            return False
        if not hmac.compare_digest(source_digest(content), expected):
            return False
        if citation.quote not in content:
            return False
    return True
