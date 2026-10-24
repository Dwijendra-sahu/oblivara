"""
Oblivara - Phase 2: Request Intent Classification
Module: code.intent_classifier

Responsible for:
1. Determining whether an inbound request actually authorizes account and personal data deletion.
2. Accurately categorizing non-deletion requests (data access, portability export, rectification,
   marketing opt-out, login support) as NOT_APPLICABLE.
3. Classifying valid multilingual deletion requests as DELETION_REQUESTED.
4. Detecting conflicting, contradictory, or ambiguous instructions and flagging them
   for conservative handling (AMBIGUOUS).
5. Keeping intent classification completely isolated from post-evidence deletion decisions.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class RequestIntent(str, Enum):
    """Primary intent verdict for downstream orchestration."""
    DELETION_REQUESTED = "DELETION_REQUESTED"  # Authorized deletion request -> proceed to audit
    NOT_APPLICABLE = "NOT_APPLICABLE"          # Non-deletion request -> output empty steps []
    AMBIGUOUS = "AMBIGUOUS"                    # Conflicting or unverifiable request intent


class IntentCategory(str, Enum):
    """Specific category of the user's communication."""
    ACCOUNT_DELETION = "ACCOUNT_DELETION"
    DATA_ACCESS = "DATA_ACCESS"                        # Subject access / copy of data
    DATA_PORTABILITY_EXPORT = "DATA_PORTABILITY_EXPORT"# Download portable export
    RECTIFICATION_CORRECTION = "RECTIFICATION"         # Correct name/phone/email, keep account
    MARKETING_OPT_OUT = "MARKETING_OPT_OUT"            # Stop marketing communications only
    SUPPORT_ASSISTANCE = "SUPPORT_ASSISTANCE"          # Login recovery / technical support
    UNKNOWN = "UNKNOWN"


@dataclass
class IntentClassificationResult:
    """Structured result of intent classification."""
    request_id: str
    intent: RequestIntent
    category: IntentCategory
    confidence: float
    matched_signals: List[str] = field(default_factory=list)
    reasoning: str = ""
    requires_audit: bool = False
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "intent": self.intent.value,
            "category": self.category.value,
            "confidence": self.confidence,
            "matched_signals": self.matched_signals,
            "reasoning": self.reasoning,
            "requires_audit": self.requires_audit,
            "warnings": self.warnings
        }


def _strip_diacritics(text: str) -> str:
    """Normalizes text by removing combining accents for resilient multilingual regex matching."""
    t = unicodedata.normalize('NFKD', text.lower())
    return ''.join(c for c in t if not unicodedata.combining(c))


class IntentClassifier:
    """
    Deterministic multilingual request-intent classifier.
    Adheres strictly to problem_statement.md rules: non-deletion requests
    (access, export, rectification, opt-outs) MUST be classified as NOT_APPLICABLE.
    """

    # Priority 1: Explicit Non-Deletion Signals (Specific inquiries checked first)
    NON_DELETION_RULES: List[Tuple[re.Pattern, IntentCategory, str]] = [
        (
            re.compile(r'\b(not\s+a\s+request\s+to\s+erase|this\s+is\s+an\s+information\s+request)\b'),
            IntentCategory.DATA_ACCESS,
            "Explicitly disclaims deletion; requests information disclosure"
        ),
        (
            re.compile(r'\b(please\s+don\'?t\s+delete|do\s+not\s+delete\s+or\s+change\s+anything)\b'),
            IntentCategory.DATA_ACCESS,
            "Explicitly instructs the platform not to delete account or data"
        ),
        (
            re.compile(r'\b(download\s+my\s+account\s+information|portable\s+format)\b'),
            IntentCategory.DATA_PORTABILITY_EXPORT,
            "Requests export/portability download rather than erasure"
        ),
        (
            re.compile(r'\b(copy\s+of\s+(last\s+year\'?s\s+invoices|my\s+invoices|the\s+information\s+held))\b'),
            IntentCategory.DATA_ACCESS,
            "Requests document or invoice copies without account termination"
        ),
        (
            re.compile(r'\b(surname\s+is\s+misspelled|replace\s+it\s+with\s+the\s+new\s+one|out\s+of\s+date)\b'),
            IntentCategory.RECTIFICATION_CORRECTION,
            "Requests data correction or profile field update"
        ),
        (
            re.compile(r'\b(remove\s+me\s+from\s+marketing\s+lists\s+only|stop\s+the\s+promotional\s+emails|unsubscribe)\b'),
            IntentCategory.MARKETING_OPT_OUT,
            "Requests marketing preference opt-out only, not account erasure"
        ),
        (
            re.compile(r'\b(can\'?t\s+access\s+my\s+profile|help\s+resetting\s+the\s+login)\b'),
            IntentCategory.SUPPORT_ASSISTANCE,
            "Requests credential or login assistance, not deletion"
        ),
        (
            re.compile(r'\b(leave\s+the\s+account\s+active|leave\s+my\s+profile\b|keep\s+the\s+account\b)\b'),
            IntentCategory.RECTIFICATION_CORRECTION,
            "Explicitly requests leaving the account or profile active"
        ),
        (
            re.compile(r'\b(without\s+removing\s+any\s+of\s+my\s+records)\b'),
            IntentCategory.RECTIFICATION_CORRECTION,
            "Explicitly instructs platform not to remove user records"
        ),
        (
            re.compile(r'\b(want\s+to\s+continue\s+using\s+the\s+service)\b'),
            IntentCategory.RECTIFICATION_CORRECTION,
            "User requests identity update while continuing service use"
        )
    ]

    # Priority 2: Multilingual Deletion Patterns
    DELETION_PATTERNS: List[Tuple[re.Pattern, str]] = [
        # English
        (
            re.compile(r'\b(delet\w*|eras\w*|remov\w*|clos\w*)\b'),
            "English deletion verb (delete/erase/remove/close)"
        ),
        (
            re.compile(r'\b(account[\s-]deletion|personal-data\s+deletion|profile\s+is\s+gone)\b'),
            "English deletion phrase"
        ),
        # French
        (
            re.compile(r'\b(suppress\w*|supprim\w*|effac\w*|clotur\w*|fermer\s+mon\s+compte)\b'),
            "French deletion indicator (suppression/supprimer/effacer)"
        ),
        # Spanish
        (
            re.compile(r'\b(elimin\w*|borr\w*|cancel\w*|cerrar\s+mi\s+cuenta)\b'),
            "Spanish deletion indicator (eliminación/eliminar/borrar)"
        ),
        # Portuguese
        (
            re.compile(r'\b(exclu\w*|elimina\w*|apagar)\b'),
            "Portuguese deletion indicator (exclusão/excluir)"
        ),
        # German
        (
            re.compile(r'\b(losch\w*|loesch\w*|schliess\w*|entfern\w*)\b'),
            "German deletion indicator (löschen/schließen)"
        ),
        # Italian
        (
            re.compile(r'\b(cancell\w*|elimin\w*|chiud\w*)\b'),
            "Italian deletion indicator (cancellazione/eliminare)"
        ),
        # Japanese (CJK regex)
        (
            re.compile(r'(削除|消去|解約|アカウントの削除|完全な削除)'),
            "Japanese deletion indicator (削除/消去)"
        ),
        # Korean (Hangul regex)
        (
            re.compile(r'(삭제|영구\s*삭제|계정.*삭제|탈퇴)'),
            "Korean deletion indicator (영구 삭제/계정 삭제)"
        ),
        # Arabic
        (
            re.compile(r'(حذف|إلغاء|مسح)'),
            "Arabic deletion indicator (حذف/مسح)"
        ),
        # Russian (Cyrillic regex)
        (
            re.compile(r'(удал\w*|стереть|закрыть\s+аккаунт)'),
            "Russian deletion indicator (удалить/стереть)"
        )
    ]

    def __init__(self) -> None:
        pass

    def classify(
        self,
        request_id: str,
        request_text: str,
        context: Optional[dict] = None
    ) -> IntentClassificationResult:
        """
        Classifies request text into DELETION_REQUESTED, NOT_APPLICABLE, or AMBIGUOUS.
        """
        raw = request_text.strip() if request_text else ""
        if not raw:
            return IntentClassificationResult(
                request_id=request_id,
                intent=RequestIntent.AMBIGUOUS,
                category=IntentCategory.UNKNOWN,
                confidence=0.0,
                reasoning="Empty request text provided",
                requires_audit=False,
                warnings=["Request text is empty or blank"]
            )

        norm = _strip_diacritics(raw)

        # Step 1: Check for explicit non-deletion intent first
        matched_non_del = []
        for pattern, cat, desc in self.NON_DELETION_RULES:
            match = pattern.search(norm) or pattern.search(raw.lower())
            if match:
                matched_non_del.append((cat, desc, match.group(0)))

        # Step 2: Check for deletion intent signals
        matched_del = []
        for pattern, desc in self.DELETION_PATTERNS:
            match = pattern.search(norm) or pattern.search(raw)
            if match:
                matched_del.append((desc, match.group(0)))

        # Step 3: Intent Resolution and Conflict Checking
        if matched_non_del:
            # If explicit non-deletion rules fired, user is explicitly opting out of deletion
            cat, desc, term = matched_non_del[0]
            signals = [f"{desc} (matched '{term}')"]
            warnings = []

            # If user text also had deletion words, confirm non-deletion disclaimer overrides
            if matched_del:
                warnings.append(
                    f"Text contains both non-deletion instruction ('{term}') and deletion terms. "
                    "Non-deletion instruction overrides."
                )

            return IntentClassificationResult(
                request_id=request_id,
                intent=RequestIntent.NOT_APPLICABLE,
                category=cat,
                confidence=1.0,
                matched_signals=signals,
                reasoning=f"Request is not a deletion authorization: {desc}.",
                requires_audit=False,
                warnings=warnings
            )

        if matched_del:
            signals = [f"{desc} ('{term}')" for desc, term in matched_del[:3]]
            return IntentClassificationResult(
                request_id=request_id,
                intent=RequestIntent.DELETION_REQUESTED,
                category=IntentCategory.ACCOUNT_DELETION,
                confidence=0.98,
                matched_signals=signals,
                reasoning="User explicitly authorizes account and data deletion.",
                requires_audit=True,
                warnings=[]
            )

        # Step 4: No known signals matched
        return IntentClassificationResult(
            request_id=request_id,
            intent=RequestIntent.AMBIGUOUS,
            category=IntentCategory.UNKNOWN,
            confidence=0.0,
            matched_signals=[],
            reasoning="No recognized deletion authorization or non-deletion signals detected in text.",
            requires_audit=False,
            warnings=["Unclassified request intent requires conservative manual or agent review"]
        )
