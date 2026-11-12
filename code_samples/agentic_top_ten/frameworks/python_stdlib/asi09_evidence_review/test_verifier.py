import unittest

from verifier import Citation, eligible_for_review, source_digest


class EvidenceReviewTests(unittest.TestCase):
    def setUp(self):
        self.sources = {"policy-v1": "Refunds over $100 require manual approval."}
        self.approved = {"policy-v1": source_digest(self.sources["policy-v1"])}
        self.citation = Citation("policy-v1", "require manual approval")

    def check_claim(self, citations, sources=None, approved=None, claim="Escalate"):
        return eligible_for_review(
            claim, citations,
            self.approved if approved is None else approved,
            self.sources if sources is None else sources,
        )

    def test_exact_quote_in_approved_source_is_ready_for_review(self):
        self.assertTrue(self.check_claim([self.citation]))

    def test_missing_empty_or_unrecognized_evidence_is_withheld(self):
        for citations in ([], [Citation("unknown", "approval")],
                          [Citation("policy-v1", " ")], [Citation("policy-v1", "always")],
                          [None]):
            with self.subTest(citations=citations):
                self.assertFalse(self.check_claim(citations))
        self.assertFalse(self.check_claim([self.citation], claim="  "))

    def test_changed_or_missing_source_is_withheld(self):
        self.assertFalse(self.check_claim([self.citation], sources={}))
        self.assertFalse(self.check_claim(
            [self.citation], sources={"policy-v1": self.sources["policy-v1"] + " changed"}
        ))
        self.assertFalse(self.check_claim([self.citation], approved={}))
        self.assertFalse(self.check_claim([self.citation], approved={"policy-v1": "é"}))

    def test_every_citation_must_pass(self):
        self.assertFalse(self.check_claim(
            [self.citation, Citation("policy-v1", "not present")]
        ))

    def test_changed_approved_revision_can_be_reviewed(self):
        sources = {"policy-v1": "Updated policy requires independent approval."}
        approved = {"policy-v1": source_digest(sources["policy-v1"])}
        self.assertTrue(self.check_claim(
            [Citation("policy-v1", "independent approval")], sources, approved
        ))


if __name__ == "__main__":
    unittest.main()
