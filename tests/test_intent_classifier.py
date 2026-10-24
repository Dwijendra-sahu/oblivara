"""
Unit tests for code.intent_classifier
Covers all required intent classification cases: multilingual deletions, explicit non-deletions,
conflicting instructions, and edge cases.
"""

import sys
import unittest
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))

from code.intent_classifier import (
    IntentClassifier,
    RequestIntent,
    IntentCategory,
)


class TestIntentClassifier(unittest.TestCase):

    def setUp(self) -> None:
        self.classifier = IntentClassifier()

    def test_01_multilingual_deletion_requests(self) -> None:
        """Requirement 1: Valid deletion requests across multiple languages."""
        test_cases = [
            ("en_01", "Please permanently delete the account associated with this email address.", IntentCategory.ACCOUNT_DELETION),
            ("en_02", "I want to close this account and have its associated personal data deleted.", IntentCategory.ACCOUNT_DELETION),
            ("en_03", "Please erase the account linked to this email address.", IntentCategory.ACCOUNT_DELETION),
            ("fr_01", "Je demande la suppression définitive du compte associé à cette adresse e-mail.", IntentCategory.ACCOUNT_DELETION),
            ("es_01", "Solicito la eliminación permanente de la cuenta asociada a este correo.", IntentCategory.ACCOUNT_DELETION),
            ("pt_01", "Solicito a exclusão permanente da conta associada a este e-mail.", IntentCategory.ACCOUNT_DELETION),
            ("ja_01", "このメールアドレスに関連するアカウントの完全な削除を依頼します。", IntentCategory.ACCOUNT_DELETION),
            ("ko_01", "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다.", IntentCategory.ACCOUNT_DELETION),
            ("de_01", "Bitte veranlassen Sie die dauerhafte Löschung meines Kontos.", IntentCategory.ACCOUNT_DELETION),
            ("it_01", "Richiedo la cancellazione permanente del mio account.", IntentCategory.ACCOUNT_DELETION),
            ("ar_01", "أطلب حذف الحساب وجميع البيانات الشخصية المرتبطة به نهائياً.", IntentCategory.ACCOUNT_DELETION),
            ("ru_01", "Пожалуйста, выполните полное удаление моего аккаунта.", IntentCategory.ACCOUNT_DELETION)
        ]

        for req_id, text, expected_category in test_cases:
            with self.subTest(req_id=req_id, text=text):
                res = self.classifier.classify(req_id, text)
                self.assertEqual(res.intent, RequestIntent.DELETION_REQUESTED)
                self.assertEqual(res.category, expected_category)
                self.assertTrue(res.requires_audit)
                self.assertGreater(res.confidence, 0.9)

    def test_02_explicit_non_deletion_requests(self) -> None:
        """Requirement 7: Requests that explicitly do not request deletion."""
        non_del_cases = [
            # Subject access inquiry
            (
                "sar_01",
                "Can you tell me what personal information you hold about me? This is an information request, not a request to erase it.",
                IntentCategory.DATA_ACCESS
            ),
            # Data copy inquiry
            (
                "sar_02",
                "Could you send me a copy of the information held on my account? I still use it, so please don't delete or change anything.",
                IntentCategory.DATA_ACCESS
            ),
            # Invoices
            (
                "inv_01",
                "I need a copy of last year's invoices for my records. Please leave my profile and purchase history in place.",
                IntentCategory.DATA_ACCESS
            ),
            # Portability / Export
            (
                "exp_01",
                "I'd like to download my account information in a portable format. Please keep the account as it is.",
                IntentCategory.DATA_PORTABILITY_EXPORT
            ),
            # Profile correction / Rectification
            (
                "rect_01",
                "My surname is misspelled on the account. Can you correct it without removing any of my records?",
                IntentCategory.RECTIFICATION_CORRECTION
            ),
            # Phone update
            (
                "rect_02",
                "The mobile number on my profile is out of date. Please replace it with the new one and leave the account active.",
                IntentCategory.RECTIFICATION_CORRECTION
            ),
            # Email update
            (
                "rect_03",
                "Please change the email address used for this account. I want to continue using the service.",
                IntentCategory.RECTIFICATION_CORRECTION
            ),
            # Marketing opt-out
            (
                "mkt_01",
                "Please remove me from marketing lists only.",
                IntentCategory.MARKETING_OPT_OUT
            ),
            (
                "mkt_02",
                "Please stop the promotional emails.",
                IntentCategory.MARKETING_OPT_OUT
            ),
            # Login recovery
            (
                "sup_01",
                "I can't access my profile and need help resetting the login.",
                IntentCategory.SUPPORT_ASSISTANCE
            )
        ]

        for req_id, text, expected_category in non_del_cases:
            with self.subTest(req_id=req_id):
                res = self.classifier.classify(req_id, text)
                self.assertEqual(res.intent, RequestIntent.NOT_APPLICABLE)
                self.assertEqual(res.category, expected_category)
                self.assertFalse(res.requires_audit)
                self.assertEqual(res.confidence, 1.0)

    def test_03_conflicting_and_ambiguous_intent(self) -> None:
        """Requirement 8: Deletion requests with ambiguous or conflicting intent evidence."""
        # Contains explicit disclaimer overriding deletion word
        res = self.classifier.classify(
            "conflict_01",
            "I want my data copy, please don't delete my account or delete my history."
        )
        self.assertEqual(res.intent, RequestIntent.NOT_APPLICABLE)
        self.assertTrue(len(res.warnings) > 0)

        # Unrecognized / vague text
        res_vague = self.classifier.classify("vague_01", "Hello, I am writing regarding order ORD-889912.")
        self.assertEqual(res_vague.intent, RequestIntent.AMBIGUOUS)
        self.assertEqual(res_vague.category, IntentCategory.UNKNOWN)
        self.assertFalse(res_vague.requires_audit)

        # Empty text
        res_empty = self.classifier.classify("empty_01", "   ")
        self.assertEqual(res_empty.intent, RequestIntent.AMBIGUOUS)
        self.assertFalse(res_empty.requires_audit)


if __name__ == "__main__":
    unittest.main()
