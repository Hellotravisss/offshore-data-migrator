"""Lightweight ML-based PII detection.

Supports two backends (in order of preference):
1. Microsoft Presidio (if installed)
2. spaCy NER (if installed) - lighter alternative
3. Regex only (always available)
"""

from typing import List, Tuple

# Try Presidio first
try:
    from presidio_analyzer import AnalyzerEngine
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False

# Try spaCy as fallback
try:
    import spacy
    SPACY_AVAILABLE = True
except ImportError:
    SPACY_AVAILABLE = False


class LightweightMLPIIDetector:
    """Lightweight ML PII detector using spaCy NER."""

    def __init__(self):
        self.nlp = None
        if SPACY_AVAILABLE:
            try:
                # Try to load a small English model
                self.nlp = spacy.load("en_core_web_sm")
            except OSError:
                # Model not downloaded, try to download
                try:
                    spacy.cli.download("en_core_web_sm")
                    self.nlp = spacy.load("en_core_web_sm")
                except Exception:
                    self.nlp = None

    def detect_pii(self, text: str) -> List[Tuple[str, str, float]]:
        """
        Detect PII using spaCy NER.
        
        Returns:
            List of (entity_type, text, confidence)
        """
        if not self.nlp:
            return []
        
        doc = self.nlp(text)
        detections = []
        
        for ent in doc.ents:
            # Map spaCy entity types to PII categories
            if ent.label_ in ["PERSON", "ORG", "GPE", "LOC"]:
                pii_type = {
                    "PERSON": "PERSON",
                    "ORG": "ORGANIZATION", 
                    "GPE": "LOCATION",
                    "LOC": "LOCATION"
                }.get(ent.label_, ent.label_)
                
                detections.append((pii_type, ent.text, 0.85))
        
        return detections


# Global instances
_presidio_engine = None
_spacy_detector = None


def get_ml_detector():
    """Get the best available ML detector."""
    global _presidio_engine, _spacy_detector
    
    if PRESIDIO_AVAILABLE:
        if _presidio_engine is None:
            try:
                _presidio_engine = AnalyzerEngine()
            except Exception:
                _presidio_engine = None
        if _presidio_engine:
            return ("presidio", _presidio_engine)
    
    if SPACY_AVAILABLE:
        if _spacy_detector is None:
            _spacy_detector = LightweightMLPIIDetector()
        if _spacy_detector.nlp:
            return ("spacy", _spacy_detector)
    
    return (None, None)


def detect_pii_ml(text: str) -> List[Tuple[str, str, float]]:
    """Detect PII using the best available ML backend."""
    backend, engine = get_ml_detector()
    
    if backend == "presidio" and engine:
        try:
            results = engine.analyze(text=text, language="en", score_threshold=0.6)
            return [(r.entity_type, text[r.start:r.end], r.score) for r in results]
        except Exception:
            pass
    
    elif backend == "spacy" and engine:
        try:
            return engine.detect_pii(text)
        except Exception:
            pass
    
    return []
