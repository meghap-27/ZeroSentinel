"""Severity score per docs/decisions.md D3. Every term is stored on the finding."""
from ..schema import Finding

BASE = {"CWE-78": 6.0, "CWE-89": 5.5, "CWE-22": 5.0}
CONFIDENCE = {"pattern-match": 0.0, "reachable": 0.5, "proof-confirmed": 1.0}


def factors(f: Finding, public_route: bool, sanitizer_present: bool = False) -> dict[str, float]:
    reachable = 1.0 if f.confidence_tier != "pattern-match" else 0.0
    return {
        "base": BASE.get(f.cwe, 4.0),
        "reachable": 1.5 * reachable,
        "public_route": 1.0 if (public_route and reachable) else 0.0,
        "confidence": CONFIDENCE[f.confidence_tier],
        "sanitizer_present": -2.0 if sanitizer_present else 0.0,
    }


def grade(f: Finding, public_route: bool, sanitizer_present: bool = False) -> Finding:
    fx = factors(f, public_route, sanitizer_present)
    score = round(max(0.0, min(10.0, sum(fx.values()))), 1)
    return f.model_copy(update={"severity": score, "severity_factors": fx})


def label(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"
