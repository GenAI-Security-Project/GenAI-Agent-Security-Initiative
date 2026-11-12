from verifier import Citation, eligible_for_review, source_digest


def main():
    sources = {"policy-v1": "Refunds over $100 require manual approval."}
    approved = {"policy-v1": source_digest(sources["policy-v1"])}
    citation = Citation("policy-v1", "require manual approval")
    for claim, citations in [
        ("Escalate a $150 refund.", [citation]),
        ("Approve the refund immediately.", [Citation("policy-v1", "always approve")]),
    ]:
        status = "ready for human review" if eligible_for_review(
            claim, citations, approved, sources
        ) else "withheld: evidence unavailable"
        print(f"{claim} {status}")


if __name__ == "__main__":
    main()
