from typing import List, Dict, Optional
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, EntityRecognizer, RecognizerResult, Pattern
from presidio_analyzer.recognizer_registry import RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngine, SpacyNlpEngine
import re


# Risk level mapping - configurable for future purpose-aware adjustments
RISK_MAPPING = {
    "EMAIL_ADDRESS": "MEDIUM",
    "PHONE_NUMBER": "HIGH",
    "CREDIT_CARD": "CRITICAL",
    "AADHAAR_NUMBER": "CRITICAL",
    "API_KEY": "CRITICAL",
    "PASSWORD": "CRITICAL",
    "PERSON": "LOW",
}

# Risk score weights for calculating overall risk score
RISK_SCORE_WEIGHTS = {
    "LOW": 10,
    "MEDIUM": 40,
    "HIGH": 70,
    "CRITICAL": 100,
}


class AadhaarRecognizer(PatternRecognizer):
    """
    Custom recognizer for Indian Aadhaar numbers.
    Pattern: 12-digit number (Indian national ID format)
    Avoids treating every 12-digit number as Aadhaar.
    """

    def __init__(self):
        patterns = [
            Pattern(
                name="Aadhaar Number (with spaces)",
                regex=r"\b\d{4}\s\d{4}\s\d{4}\b",
                score=0.85,
            ),
            Pattern(
                name="Aadhaar Number (hyphenated)",
                regex=r"\b\d{4}-\d{4}-\d{4}\b",
                score=0.85,
            ),
            Pattern(
                name="Aadhaar Number (plain 12 digits)",
                regex=r"\b\d{12}\b",
                score=0.60,  # Lower score for plain 12-digit to reduce false positives
            ),
        ]
        super().__init__(
            supported_entity="AADHAAR_NUMBER",
            patterns=patterns,
            name="Aadhaar Recognizer",
        )


class APIKeyRecognizer(PatternRecognizer):
    """
    Custom recognizer for API keys.
    Uses safe synthetic/demo patterns to avoid flagging random alphanumeric strings.
    """

    def __init__(self):
        patterns = [
            Pattern(
                name="API Key with prefix (sk-, pk-, api_key=)",
                regex=r"\b(sk_|pk_|api_key\s*[=:]\s*)[a-zA-Z0-9]{20,}\b",
                score=0.85,
            ),
            Pattern(
                name="Bearer token pattern",
                regex=r"\bBearer\s+[a-zA-Z0-9_-]{20,}\b",
                score=0.80,
            ),
            Pattern(
                name="API key in configuration format",
                regex=r'(api[_-]?key|apikey|secret)["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_-]{20,}["\']?',
                score=0.75,
            ),
        ]
        super().__init__(
            supported_entity="API_KEY",
            patterns=patterns,
            name="API Key Recognizer",
        )


class PasswordRecognizer(PatternRecognizer):
    """
    Custom recognizer for passwords.
    Detects contextual patterns like "password=abc123", "password: abc123", etc.
    Does NOT classify every random word as a password.
    """

    def __init__(self):
        patterns = [
            Pattern(
                name="Password with equals sign",
                regex=r'password\s*=\s*["\']?([^\s"\']{4,})["\']?',
                score=0.85,
            ),
            Pattern(
                name="Password with colon",
                regex=r'password\s*:\s*["\']?([^\s"\']{4,})["\']?',
                score=0.85,
            ),
            Pattern(
                name="Password phrase",
                regex=r'(my|the|your)\s+password\s+(is|was)\s+["\']?([^\s"\']{4,})["\']?',
                score=0.80,
            ),
            Pattern(
                name="Password in config format",
                regex=r'(passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s"\']{4,})["\']?',
                score=0.75,
            ),
        ]
        super().__init__(
            supported_entity="PASSWORD",
            patterns=patterns,
            name="Password Recognizer",
        )


class SensitiveDataDetector:
    """
    Main detector class that uses Presidio Analyzer with custom recognizers.
    
    SECURITY NOTE: This detector analyzes text locally and does NOT send
    user prompts to any external AI model. All processing happens on the
    local machine using spaCy and Presidio.
    """

    def __init__(self):
        # Initialize NLP engine with spaCy
        try:
            self.nlp_engine = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": "en_core_web_sm"}])
        except Exception:
            # Fallback if model not installed yet
            self.nlp_engine = None
        
        # Initialize analyzer with custom recognizers
        self.analyzer = AnalyzerEngine(
            nlp_engine=self.nlp_engine if self.nlp_engine else None,
        )
        
        # Add custom recognizers
        self._add_custom_recognizers()

    def _add_custom_recognizers(self):
        """Add custom recognizers to the analyzer."""
        custom_recognizers = [
            AadhaarRecognizer(),
            APIKeyRecognizer(),
            PasswordRecognizer(),
        ]
        
        for recognizer in custom_recognizers:
            self.analyzer.registry.add_recognizer(recognizer)

    def detect(self, text: str) -> List[Dict]:
        """
        Detect sensitive data in the given text.
        
        Args:
            text: The text to analyze
            
        Returns:
            List of detected entities with entity_type, value, start, end, score, risk
        """
        if not text or not text.strip():
            return []
        
        # Supported entities to detect
        entities = ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "PERSON", 
                   "AADHAAR_NUMBER", "API_KEY", "PASSWORD"]
        
        try:
            results = self.analyzer.analyze(
                text=text,
                entities=entities,
                language="en",
            )
        except Exception as e:
            # Handle case where spaCy model is not loaded
            # Fall back to regex-only detection
            results = self._fallback_detection(text, entities)
        
        # Convert results to the expected format
        detected = []
        for result in results:
            entity = {
                "entity_type": result.entity_type,
                "value": text[result.start:result.end],
                "start": result.start,
                "end": result.end,
                "score": result.score,
                "risk": RISK_MAPPING.get(result.entity_type, "MEDIUM"),
            }
            detected.append(entity)
        
        return detected

    def _fallback_detection(self, text: str, entities: List[str]) -> List[RecognizerResult]:
        """
        Fallback detection using only custom recognizers when spaCy is not available.
        """
        results = []
        
        # Only use custom recognizers that don't require NLP
        custom_recognizers = [
            AadhaarRecognizer(),
            APIKeyRecognizer(),
            PasswordRecognizer(),
        ]
        
        for recognizer in custom_recognizers:
            if recognizer.supported_entities[0] in entities:
                try:
                    recognizer_results = recognizer.analyze(text, entities)
                    results.extend(recognizer_results)
                except Exception:
                    continue
        
        return results

    def calculate_risk_score(self, detected: List[Dict]) -> int:
        """
        Calculate an overall risk score based on detected entities.
        
        Args:
            detected: List of detected entities
            
        Returns:
            Overall risk score (0-100)
        """
        if not detected:
            return 0
        
        # Sum the weighted risk scores
        total_score = sum(
            RISK_SCORE_WEIGHTS.get(entity["risk"], 0) * entity["score"]
            for entity in detected
        )
        
        # Normalize to 0-100 range
        max_possible = len(detected) * 100
        if max_possible == 0:
            return 0
        
        normalized_score = int((total_score / max_possible) * 100)
        return min(normalized_score, 100)
