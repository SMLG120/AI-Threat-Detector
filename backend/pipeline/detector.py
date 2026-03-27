"""
Detection Pipeline
Orchestrates: Feature Extraction → Rule Engine → ML Ensemble → Score Aggregation
"""
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

from core.config import settings
from pipeline.feature_extractor import RawRequest, extract_features
from rules.engine import run_rules, RuleMatch
from ml.model_manager import model_manager


@dataclass
class DetectionResult:
    threat_score: float
    threat_level: str          # LOW | MEDIUM | HIGH
    is_malicious: bool
    attack_types: List[str]
    rule_score: float
    isolation_forest_score: float
    random_forest_score: float
    autoencoder_score: float
    features: dict
    rule_matches: List[RuleMatch] = field(default_factory=list)


def classify_threat_level(score: float) -> str:
    if score >= settings.THREAT_SCORE_HIGH:
        return "HIGH"
    elif score >= settings.THREAT_SCORE_MEDIUM:
        return "MEDIUM"
    elif score >= settings.THREAT_SCORE_LOW:
        return "MEDIUM"
    return "LOW"


async def analyze_request(req: RawRequest) -> DetectionResult:
    """Full detection pipeline for a single request."""

    parsed = urlparse(req.url)
    query = parsed.query or ""
    path = parsed.path or ""

    # ── 1. Feature Extraction ─────────────────────────────────────────────
    feature_vector = extract_features(req)
    features_np = feature_vector.to_numpy()

    # ── 2. Rule Engine ────────────────────────────────────────────────────
    rule_score, rule_matches = run_rules(
        url=req.url,
        body=req.request_body or "",
        query=query,
    )

    # ── 3. ML Ensemble ────────────────────────────────────────────────────
    ml_scores = model_manager.predict(features_np)
    if_score = ml_scores["isolation_forest"]
    rf_score = ml_scores["random_forest"]
    ae_score = ml_scores["autoencoder"]

    # ── 4. Weighted Ensemble Score ────────────────────────────────────────
    threat_score = (
        rule_score * settings.RULE_WEIGHT
        + if_score * settings.ISOLATION_FOREST_WEIGHT
        + rf_score * settings.RANDOM_FOREST_WEIGHT
        + ae_score * settings.AUTOENCODER_WEIGHT
    )

    # Clamp
    threat_score = round(min(max(threat_score, 0.0), 1.0), 4)
    threat_level = classify_threat_level(threat_score)
    is_malicious = threat_score >= settings.THREAT_SCORE_MEDIUM

    # Unique attack types from rule matches
    attack_types = list({m.category for m in rule_matches})

    return DetectionResult(
        threat_score=threat_score,
        threat_level=threat_level,
        is_malicious=is_malicious,
        attack_types=attack_types,
        rule_score=round(rule_score, 4),
        isolation_forest_score=round(if_score, 4),
        random_forest_score=round(rf_score, 4),
        autoencoder_score=round(ae_score, 4),
        features=feature_vector.model_dump(),
        rule_matches=rule_matches,
    )
