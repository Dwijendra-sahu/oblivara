"""
Oblivara - Test Hardening: Identity & Intent Edge Cases
Module: tests.test_identity_intent_hardening
Covers Phase 2 hardening: Unicode handling, phone collision guards,
audit log temporal ordering, complex negation, questions, and ambiguous intent.
"""

import sys
import unittest
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))

from code.identity_resolution import (
    CanonicalIdentity,
    IdentifierRecord,
    IdentifierType,
    IdentityGraph,
    ResolutionConfidence,
    ResolutionStatus,
)
from code.intent_classifier import (
    IntentCategory,
    IntentClassifier,
    RequestIntent,
)


class TestIdentityIntentHardening(unittest.TestCase):
    """Hardened edge-case tests for IdentityGraph and IntentClassifier."""

    def setUp(self) -> None:
        self.graph = IdentityGraph()
        self.classifier = IntentClassifier()

    def test_unicode_and_case_folding_email(self) -> None:
        """Verifies case folding and unicode handling in email addresses."""
        email_rec = IdentifierRecord.create("Müller.André@Domain.COM", IdentifierType.EMAIL, "identities")
        user = CanonicalIdentity(user_id="user_uni", current_email=email_rec)
        self.graph.users["user_uni"] = user
        self.graph.current_email_index["müller.andré@domain.com"] = "user_uni"

        # Query with uppercase and mixed case
        res = self.graph.resolve_email("c_uni_1", "MÜLLER.ANDRÉ@domain.com")
        self.assertEqual(res.status, ResolutionStatus.RESOLVED)
        self.assertEqual(res.canonical_user_id, "user_uni")

        # Original query email preserved in raw form for provenance
        self.assertEqual(res.input_identifier, "MÜLLER.ANDRÉ@domain.com")

    def test_phone_collision_guard(self) -> None:
        """Verifies that two users sharing a phone number or family plan do not merge."""
        e1 = IdentifierRecord.create("alice@example.com", IdentifierType.EMAIL, "identities")
        u1 = CanonicalIdentity(user_id="user_01", current_email=e1)
        u1.current_phone = IdentifierRecord.create("+15550199", IdentifierType.PHONE, "identities")

        e2 = IdentifierRecord.create("bob@example.com", IdentifierType.EMAIL, "identities")
        u2 = CanonicalIdentity(user_id="user_02", current_email=e2)
        u2.current_phone = IdentifierRecord.create("+15550199", IdentifierType.PHONE, "identities")

        self.graph.users["user_01"] = u1
        self.graph.users["user_02"] = u2
        self.graph.current_email_index["alice@example.com"] = "user_01"
        self.graph.current_email_index["bob@example.com"] = "user_02"

        # Resolving alice does not resolve bob or mix records
        res_alice = self.graph.resolve_email("c_col_1", "alice@example.com")
        self.assertEqual(res_alice.canonical_user_id, "user_01")
        self.assertIsNotNone(res_alice.identity)
        self.assertNotIn("bob@example.com", res_alice.identity.all_emails())

        res_bob = self.graph.resolve_email("c_col_2", "bob@example.com")
        self.assertEqual(res_bob.canonical_user_id, "user_02")
        self.assertIsNotNone(res_bob.identity)
        self.assertNotIn("alice@example.com", res_bob.identity.all_emails())

    def test_audit_log_temporal_mutation_precedence(self) -> None:
        """Verifies that historical email mutations correctly map to the canonical user."""
        latest_rec = IdentifierRecord.create("latest@example.com", IdentifierType.EMAIL, "identities")
        u = CanonicalIdentity(user_id="user_mut", current_email=latest_rec)

        hist_1 = IdentifierRecord.create("old1@example.com", IdentifierType.EMAIL, "audit_log", "2025-01-01T00:00:00Z")
        hist_2 = IdentifierRecord.create("old2@example.com", IdentifierType.EMAIL, "audit_log", "2025-06-01T00:00:00Z")
        u.historical_emails = [hist_1, hist_2]

        self.graph.users["user_mut"] = u
        self.graph.current_email_index["latest@example.com"] = "user_mut"
        self.graph.historical_email_index["old1@example.com"] = {"user_mut": hist_1}
        self.graph.historical_email_index["old2@example.com"] = {"user_mut": hist_2}

        res_old1 = self.graph.resolve_email("c_mut_1", "old1@example.com")
        self.assertEqual(res_old1.status, ResolutionStatus.RESOLVED)
        self.assertEqual(res_old1.canonical_user_id, "user_mut")
        self.assertEqual(res_old1.confidence, ResolutionConfidence.HISTORICAL_AUDIT)

        res_old2 = self.graph.resolve_email("c_mut_2", "old2@example.com")
        self.assertEqual(res_old2.status, ResolutionStatus.RESOLVED)
        self.assertEqual(res_old2.canonical_user_id, "user_mut")

    def test_intent_strong_negation(self) -> None:
        """Requests containing strong negation phrases must be classified as NOT_APPLICABLE."""
        negation_prompts = [
            ("neg_01", "Please do not delete my account, I just want to update my credit card."),
            ("neg_02", "I am writing to make sure you do NOT erase my profile. Please keep it active."),
            ("neg_03", "Never delete my purchase history, but please send me my receipts."),
            ("neg_04", "Don't delete anything, I only need to change my shipping address."),
        ]
        for cid, text in negation_prompts:
            with self.subTest(cid=cid, text=text):
                res = self.classifier.classify(cid, text)
                self.assertEqual(
                    res.intent,
                    RequestIntent.NOT_APPLICABLE,
                    f"Failed negation classification on: {text}",
                )
                self.assertFalse(res.requires_audit)

    def test_intent_questions_without_authorization(self) -> None:
        """Inquiries asking how deletion works without requesting it are NOT_APPLICABLE or AMBIGUOUS."""
        question_prompts = [
            ("q_01", "Can you explain how personal data deletion works on your platform?"),
            ("q_02", "Is it possible to see what data would be deleted if I were to request it?"),
            ("q_03", "Where is the button to delete my account in the mobile app?"),
        ]
        for cid, text in question_prompts:
            with self.subTest(cid=cid, text=text):
                res = self.classifier.classify(cid, text)
                self.assertIn(
                    res.intent,
                    (RequestIntent.NOT_APPLICABLE, RequestIntent.AMBIGUOUS),
                    f"Question should not authorize deletion: {text}",
                )
                self.assertFalse(res.requires_audit)

    def test_intent_mixed_language_and_symbols(self) -> None:
        """Verifies intent classification with multilingual tokens and punctuation."""
        mixed_cases = [
            ("mix_01", "アカウント削除をお願いします (Please permanently delete my account).", RequestIntent.DELETION_REQUESTED),
            ("mix_02", "Supprimer mon compte s'il vous plaît / Please erase my profile immediately.", RequestIntent.DELETION_REQUESTED),
            ("mix_03", "*** DELETE ACCOUNT NOW *** ID: 994821", RequestIntent.DELETION_REQUESTED),
        ]
        for cid, text, expected_intent in mixed_cases:
            with self.subTest(cid=cid, text=text):
                res = self.classifier.classify(cid, text)
                self.assertEqual(res.intent, expected_intent)

    def test_intent_empty_and_whitespace_only(self) -> None:
        """Empty, whitespace, and symbol-only requests must be handled safely as AMBIGUOUS."""
        for cid, text in [("e_1", ""), ("e_2", "   \t\n  "), ("e_3", "!@#$%^&*()")]:
            res = self.classifier.classify(cid, text)
            self.assertEqual(res.intent, RequestIntent.AMBIGUOUS)
            self.assertFalse(res.requires_audit)


if __name__ == "__main__":
    unittest.main()
