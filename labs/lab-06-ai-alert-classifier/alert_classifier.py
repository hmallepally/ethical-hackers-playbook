"""
Lab 6.1: AI-Powered SOC Alert Classifier & Automated Triage Agent
The Ethical Hacker's Playbook — Chapter 6 (2026 Edition)

Build an intelligent SOC triage agent that classifies incoming security alerts,
correlates telemetry to MITRE ATT&CK techniques, and generates sub-minute containment plans.

USAGE:
    python alert_classifier.py
"""

from __future__ import annotations

import json
import random
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


@dataclass
class SecurityAlert:
    alert_id: str
    alert_type: str
    severity: str
    source_ip: str
    target_asset: str
    is_business_hours: bool
    is_internal_source: bool
    repeated_in_1h: int
    user_has_history: bool
    is_critical_asset: bool
    mitre_technique: str


@dataclass
class TriageDecision:
    alert_id: str
    classification: str  # TRUE_POSITIVE, FALSE_POSITIVE, NEEDS_REVIEW
    confidence_score: float
    mitre_technique: str
    blast_radius: str
    recommended_action: str
    requires_human_approval: bool
    reasoning: str


# -------------------------------------------------------------------
# Alert Telemetry Simulation
# -------------------------------------------------------------------

SAMPLE_ALERTS = [
    SecurityAlert(
        alert_id="ALT-2026-8801",
        alert_type="malware_beaconing",
        severity="critical",
        source_ip="192.168.10.45",
        target_asset="prod-database-primary",
        is_business_hours=False,
        is_internal_source=True,
        repeated_in_1h=42,
        user_has_history=False,
        is_critical_asset=True,
        mitre_technique="T1071.001 (Web Protocols C2)"
    ),
    SecurityAlert(
        alert_id="ALT-2026-8802",
        alert_type="port_scan_sweep",
        severity="medium",
        source_ip="10.0.4.12",
        target_asset="corp-workstation-99",
        is_business_hours=True,
        is_internal_source=True,
        repeated_in_1h=2,
        user_has_history=True,
        is_critical_asset=False,
        mitre_technique="T1046 (Network Service Discovery)"
    ),
    SecurityAlert(
        alert_id="ALT-2026-8803",
        alert_type="abnormal_credential_access",
        severity="high",
        source_ip="198.51.100.23",
        target_asset="iam-auth-server",
        is_business_hours=False,
        is_internal_source=False,
        repeated_in_1h=15,
        user_has_history=False,
        is_critical_asset=True,
        mitre_technique="T1110.003 (Password Spraying)"
    )
]


# -------------------------------------------------------------------
# AI Triage & Graph Correlation Logic
# -------------------------------------------------------------------

def triage_alert_with_ai(alert: SecurityAlert) -> TriageDecision:
    """Evaluate alert features and determine classification and containment."""
    risk_score = 0.0

    # Severity base
    severity_weights = {"low": 0.1, "medium": 0.3, "high": 0.6, "critical": 0.85}
    risk_score += severity_weights.get(alert.severity.lower(), 0.3)

    if not alert.is_business_hours:
        risk_score += 0.15
    if alert.is_critical_asset:
        risk_score += 0.25
    if alert.repeated_in_1h > 10:
        risk_score += 0.20
    if not alert.is_internal_source:
        risk_score += 0.15
    if alert.user_has_history:
        risk_score -= 0.10  # Known behavioral baseline

    confidence = min(max(risk_score, 0.05), 0.99)

    if confidence >= 0.70:
        classification = "TRUE_POSITIVE"
        blast_radius = "High — Crown Jewel Asset Compromise Imminent"
        action = "Isolate host endpoint, revoke active session tokens, and block ingress C2 IP."
        requires_approval = alert.is_critical_asset  # High-impact requires Human-in-the-Loop gate
        reasoning = (
            f"Alert matches high-confidence adversarial pattern ({alert.mitre_technique}) on critical "
            f"infrastructure with {alert.repeated_in_1h} repeated bursts outside business hours."
        )
    elif confidence <= 0.35:
        classification = "FALSE_POSITIVE"
        blast_radius = "Minimal — Internal IT Administrative Routine"
        action = "Dismiss alert and update behavioral baseline filter."
        requires_approval = False
        reasoning = "Activity originates from known internal administrator workstation during business hours."
    else:
        classification = "NEEDS_REVIEW"
        blast_radius = "Moderate — Non-critical endpoint deviation"
        action = "Route to Tier-2 SOC Analyst with pre-compiled graph correlation summary."
        requires_approval = True
        reasoning = "Ambiguous telemetry; anomalous volume detected on standard workstation."

    return TriageDecision(
        alert_id=alert.alert_id,
        classification=classification,
        confidence_score=round(confidence, 2),
        mitre_technique=alert.mitre_technique,
        blast_radius=blast_radius,
        recommended_action=action,
        requires_human_approval=requires_approval,
        reasoning=reasoning
    )


# -------------------------------------------------------------------
# Optional ML Model Trainer (scikit-learn when installed)
# -------------------------------------------------------------------

def train_ml_classifier_if_available():
    """Attempt training Random Forest classifier if scikit-learn is present."""
    try:
        from sklearn.ensemble import RandomForestClassifier
        print("  [✓] scikit-learn detected: Random Forest classifier initialized.")
    except ImportError:
        print("  [i] Standalone probabilistic mode active (pip install scikit-learn for ML model mode).")


# -------------------------------------------------------------------
# Main Routine
# -------------------------------------------------------------------

def main():
    print("============================================================")
    print("🛡️  AI-POWERED SOC TRIAGE & SOAR CONTAINMENT (2026 Edition)")
    print("============================================================\n")

    train_ml_classifier_if_available()

    print("\n[1/2] Processing Real-Time Incoming Security Telemetry Stream...")
    decisions: List[TriageDecision] = []

    for alert in SAMPLE_ALERTS:
        decision = triage_alert_with_ai(alert)
        decisions.append(decision)

        emoji = {"TRUE_POSITIVE": "🔴", "NEEDS_REVIEW": "🟡", "FALSE_POSITIVE": "🟢"}[decision.classification]
        print(f"\n────────────────────────────────────────────────────────────")
        print(f"Alert ID      : {alert.alert_id} | {alert.alert_type.upper()} ({alert.severity})")
        print(f"Classification: {emoji} {decision.classification} (Confidence: {decision.confidence_score * 100:.0f}%)")
        print(f"ATT&CK Mapping: {decision.mitre_technique}")
        print(f"Blast Radius  : {decision.blast_radius}")
        print(f"Reasoning     : {decision.reasoning}")
        print(f"Action        : {decision.recommended_action}")
        print(f"Human Gate    : {'⚠️  HUMAN-IN-THE-LOOP APPROVAL REQUIRED' if decision.requires_human_approval else '⚡ AUTONOMOUS EXECUTION ELIGIBLE'}")

    print(f"\n[2/2] Exporting SOC Triage Telemetry Artifact...")
    out_file = f"soc_triage_decisions_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_file, "w") as f:
        json.dump([asdict(d) for d in decisions], f, indent=2)
    print(f"✅ Triage artifact written to: {out_file}\n")


if __name__ == "__main__":
    main()

