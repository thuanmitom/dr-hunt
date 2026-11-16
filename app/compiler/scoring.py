"""Deterministic confidence: evidence features -> base score, then time decay and feedback.
The LLM has no input into any number computed here."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.schemas.enums import AttackVector, Severity

DEFAULT_HALF_LIFE_HOURS = {
    AttackVector.IDENTITY_AITM_INFOSTEALER: 72,  # phishing domains burn fast
    AttackVector.CLICKFIX_FILELESS: 96,
    AttackVector.LOTS_RMM_TUNNEL: 168,
    AttackVector.SUPPLY_CHAIN_SEO: 336,
    AttackVector.BYOVD_DLL_SIDELOAD: 720,
    AttackVector.EDGE_DEVICE_EXPLOIT: 720,  # exploitation of a KEV persists for weeks
}
EXPIRY_FLOOR = 20


def base_confidence(vector: AttackVector, features: dict[str, Any]) -> int:
    s = 0
    if vector is AttackVector.EDGE_DEVICE_EXPLOIT:
        # 70, not 50 (D-64): KEV means exploited in the wild, so it reaches the default delivery threshold (60) on its
        # own and stays above it for about 7 days of decay (half-life 30 d), the length of the KEV lookback window.
        s += 70 if features.get("in_kev") else 0
        s += 15 if features.get("epss_alert") else 0
        s += 10 if features.get("epss_percentile", 0) >= 0.9 else 0
        s += 10 if features.get("credible_poc") else 0
        s += 10 if features.get("nuclei_template") else 0
        s += 10 if features.get("ransomware_use") else 0
    elif vector is AttackVector.CLICKFIX_FILELESS:
        s += 40 if features.get("clipboard_lure") else 0
        s += 25 if features.get("unpacked_c2") else 0
        s += 10 if features.get("lure_count", 0) >= 2 else 0
        s += 5 if features.get("layers", 0) >= 2 else 0
    elif vector is AttackVector.IDENTITY_AITM_INFOSTEALER and "generic" in features:
        s += int(features["generic"])
    elif vector is AttackVector.IDENTITY_AITM_INFOSTEALER:
        s += 70 if features.get("credential_exposure") else 0
        s += 10 if features.get("exposed_accounts", 0) >= 3 else 0
        s += int(features.get("aitm_score", 0) * 0.7)
        s += 30 if features.get("lookalike_cert") else 0
        s += 10 if features.get("aitm_score", 0) and features.get("lookalike_cert") else 0
    else:
        s += int(features.get("generic", 40))
    return max(0, min(100, s))


def decayed(base: int, last_seen: datetime, now: datetime, half_life_hours: int) -> int:
    age_h = max(0.0, (now - last_seen).total_seconds() / 3600)
    return int(round(base * 0.5 ** (age_h / half_life_hours)))


def with_feedback(score: int, sighting_count: int) -> int:
    """Sightings corroborate; 'clean' results do not lower confidence (absence of evidence)."""
    return min(100, score + min(15, 5 * sighting_count))


def severity_for(vector: AttackVector, confidence: int) -> Severity:
    boost = 5 if vector in (AttackVector.EDGE_DEVICE_EXPLOIT, AttackVector.IDENTITY_AITM_INFOSTEALER) else 0
    c = confidence + boost
    if c >= 85:
        return Severity.CRITICAL
    if c >= 65:
        return Severity.HIGH
    if c >= 40:
        return Severity.MEDIUM
    return Severity.LOW
