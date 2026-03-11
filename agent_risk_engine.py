"""
Zarelva Agent Risk Engine
Behavioral fraud detection framework for autonomous AI agents.

Author: Gururaj GJ
Founder - Zarelva | Fraud Intelligence & Risk Architecture
Website: https://zarelva.com
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


class Decision(Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class SignalSeverity(Enum):
    LOW = 5
    MEDIUM = 15
    HIGH = 30
    CRITICAL = 50


@dataclass
class FraudSignal:
    name: str
    category: str
    severity: SignalSeverity
    description: str
    score_impact: int


@dataclass
class RiskEvaluationResult:
    agent_id: str
    trust_score: int
    decision: Decision
    signals_triggered: List[str] = field(default_factory=list)
    risk_categories: List[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            "agent_id": self.agent_id,
            "trust_score": self.trust_score,
            "decision": self.decision.value,
            "signals_triggered": self.signals_triggered,
            "risk_categories": self.risk_categories,
            "recommendation": self.recommendation
        }


class ZarelvaRiskEngine:
    """
    Zarelva Agent Risk Engine

    Evaluates behavioral fraud signals for autonomous AI agents
    and produces a trust score with Allow / Review / Block decision.

    Signal categories:
    - Identity Signals
    - Behavioral Signals
    - Delegation Signals
    - Coordination Signals
    - Network Signals
    - Financial Signals
    """

    # Trust score thresholds
    ALLOW_THRESHOLD = 70
    REVIEW_THRESHOLD = 40
    # Below REVIEW_THRESHOLD = BLOCK

    # Starting trust score (max 100)
    BASE_SCORE = 100

    def __init__(self):
        self.signal_library = self._build_signal_library()

    def _build_signal_library(self) -> Dict[str, FraudSignal]:
        """Build the fraud signal library."""
        signals = [
            # --- Identity Signals ---
            FraudSignal(
                name="identity_age_new",
                category="Identity",
                severity=SignalSeverity.HIGH,
                description="Agent identity created very recently (< 24 hours)",
                score_impact=30
            ),
            FraudSignal(
                name="identity_revoked",
                category="Identity",
                severity=SignalSeverity.CRITICAL,
                description="Agent identity has been revoked or invalidated",
                score_impact=50
            ),
            FraudSignal(
                name="unknown_issuer",
                category="Identity",
                severity=SignalSeverity.HIGH,
                description="Agent credential issued by unknown or untrusted authority",
                score_impact=30
            ),
            FraudSignal(
                name="identity_cloned",
                category="Identity",
                severity=SignalSeverity.CRITICAL,
                description="Duplicate agent identity detected across multiple systems",
                score_impact=50
            ),

            # --- Behavioral Signals ---
            FraudSignal(
                name="action_velocity_high",
                category="Behavioral",
                severity=SignalSeverity.HIGH,
                description="Agent performing actions at abnormally high velocity",
                score_impact=25
            ),
            FraudSignal(
                name="impossible_navigation_speed",
                category="Behavioral",
                severity=SignalSeverity.HIGH,
                description="Agent navigating between resources at impossible speed",
                score_impact=25
            ),
            FraudSignal(
                name="repeated_failed_actions",
                category="Behavioral",
                severity=SignalSeverity.MEDIUM,
                description="Agent repeatedly attempting failed operations",
                score_impact=15
            ),
            FraudSignal(
                name="abnormal_data_access_pattern",
                category="Behavioral",
                severity=SignalSeverity.HIGH,
                description="Agent accessing data outside normal operational scope",
                score_impact=25
            ),

            # --- Delegation Signals ---
            FraudSignal(
                name="delegation_depth_high",
                category="Delegation",
                severity=SignalSeverity.HIGH,
                description="Delegation chain depth exceeds acceptable threshold",
                score_impact=25
            ),
            FraudSignal(
                name="privilege_escalation",
                category="Delegation",
                severity=SignalSeverity.CRITICAL,
                description="Agent attempting to acquire permissions beyond delegation scope",
                score_impact=50
            ),
            FraudSignal(
                name="delegation_to_unknown_agent",
                category="Delegation",
                severity=SignalSeverity.HIGH,
                description="Delegation passed to unrecognized or unverified agent",
                score_impact=30
            ),

            # --- Coordination Signals ---
            FraudSignal(
                name="multi_agent_convergence",
                category="Coordination",
                severity=SignalSeverity.HIGH,
                description="Multiple agents converging on same resource simultaneously",
                score_impact=25
            ),
            FraudSignal(
                name="shared_credentials",
                category="Coordination",
                severity=SignalSeverity.CRITICAL,
                description="Multiple agents sharing identical cryptographic credentials",
                score_impact=50
            ),
            FraudSignal(
                name="synchronized_activity",
                category="Coordination",
                severity=SignalSeverity.HIGH,
                description="Synchronized action patterns across multiple agents",
                score_impact=30
            ),

            # --- Network Signals ---
            FraudSignal(
                name="tor_exit_node",
                category="Network",
                severity=SignalSeverity.HIGH,
                description="Agent operating from known Tor exit node",
                score_impact=30
            ),
            FraudSignal(
                name="vpn_detected",
                category="Network",
                severity=SignalSeverity.MEDIUM,
                description="Agent operating behind VPN or proxy service",
                score_impact=15
            ),
            FraudSignal(
                name="datacenter_ip",
                category="Network",
                severity=SignalSeverity.MEDIUM,
                description="Agent originating from datacenter IP block",
                score_impact=10
            ),

            # --- Financial Signals ---
            FraudSignal(
                name="unauthorized_payment_action",
                category="Financial",
                severity=SignalSeverity.CRITICAL,
                description="Financial action without valid human authorization",
                score_impact=50
            ),
            FraudSignal(
                name="abnormal_payment_frequency",
                category="Financial",
                severity=SignalSeverity.HIGH,
                description="Payment initiation frequency exceeds normal operational baseline",
                score_impact=30
            ),
            FraudSignal(
                name="data_exfiltration_pattern",
                category="Financial",
                severity=SignalSeverity.CRITICAL,
                description="Large internal data read followed by external write pattern",
                score_impact=50
            ),
        ]
        return {s.name: s for s in signals}

    def evaluate(self, agent_data: Dict) -> Dict:
        """
        Evaluate an agent for fraud risk signals.

        Args:
            agent_data: Dictionary containing agent attributes.
                Keys:
                    agent_id (str): Unique identifier for the agent
                    identity_age_days (int): Age of agent identity in days
                    identity_revoked (bool): Whether identity is revoked
                    unknown_issuer (bool): Whether issuer is unknown
                    identity_cloned (bool): Whether identity is cloned
                    action_velocity (int): Actions per minute
                    repeated_failed_actions (bool): Whether repeated failures detected
                    abnormal_data_access (bool): Abnormal data access pattern
                    delegation_depth (int): Depth of delegation chain
                    privilege_escalation (bool): Privilege escalation detected
                    delegation_to_unknown (bool): Delegation to unknown agent
                    multi_agent_convergence (bool): Multi-agent convergence
                    shared_credentials (bool): Shared credentials detected
                    synchronized_activity (bool): Synchronized activity detected
                    network_type (str): 'clean', 'vpn', 'datacenter', 'tor'
                    financial_actions (bool): Financial actions without authorization
                    abnormal_payment_frequency (bool): Abnormal payment frequency
                    data_exfiltration (bool): Data exfiltration pattern detected

        Returns:
            Dictionary with trust_score, decision, and triggered signals.
        """
        agent_id = agent_data.get("agent_id", "unknown")
        triggered_signals = []
        risk_categories = set()
        score = self.BASE_SCORE

        # --- Identity Checks ---
        if agent_data.get("identity_age_days", 999) < 1:
            triggered_signals.append("identity_age_new")
        if agent_data.get("identity_revoked", False):
            triggered_signals.append("identity_revoked")
        if agent_data.get("unknown_issuer", False):
            triggered_signals.append("unknown_issuer")
        if agent_data.get("identity_cloned", False):
            triggered_signals.append("identity_cloned")

        # --- Behavioral Checks ---
        if agent_data.get("action_velocity", 0) > 100:
            triggered_signals.append("action_velocity_high")
        if agent_data.get("impossible_speed", False):
            triggered_signals.append("impossible_navigation_speed")
        if agent_data.get("repeated_failed_actions", False):
            triggered_signals.append("repeated_failed_actions")
        if agent_data.get("abnormal_data_access", False):
            triggered_signals.append("abnormal_data_access_pattern")

        # --- Delegation Checks ---
        if agent_data.get("delegation_depth", 0) > 3:
            triggered_signals.append("delegation_depth_high")
        if agent_data.get("privilege_escalation", False):
            triggered_signals.append("privilege_escalation")
        if agent_data.get("delegation_to_unknown", False):
            triggered_signals.append("delegation_to_unknown_agent")

        # --- Coordination Checks ---
        if agent_data.get("multi_agent_convergence", False):
            triggered_signals.append("multi_agent_convergence")
        if agent_data.get("shared_credentials", False):
            triggered_signals.append("shared_credentials")
        if agent_data.get("synchronized_activity", False):
            triggered_signals.append("synchronized_activity")

        # --- Network Checks ---
        network = agent_data.get("network_type", "clean")
        if network == "tor":
            triggered_signals.append("tor_exit_node")
        elif network == "vpn":
            triggered_signals.append("vpn_detected")
        elif network == "datacenter":
            triggered_signals.append("datacenter_ip")

        # --- Financial Checks ---
        if agent_data.get("financial_actions", False):
            triggered_signals.append("unauthorized_payment_action")
        if agent_data.get("abnormal_payment_frequency", False):
            triggered_signals.append("abnormal_payment_frequency")
        if agent_data.get("data_exfiltration", False):
            triggered_signals.append("data_exfiltration_pattern")

        # Calculate score deductions
        for signal_name in triggered_signals:
            signal = self.signal_library.get(signal_name)
            if signal:
                score -= signal.score_impact
                risk_categories.add(signal.category)

        # Clamp score between 0 and 100
        trust_score = max(0, min(100, score))

        # Determine decision
        if trust_score >= self.ALLOW_THRESHOLD:
            decision = Decision.ALLOW
            recommendation = "Agent cleared. Continue monitoring for behavioral changes."
        elif trust_score >= self.REVIEW_THRESHOLD:
            decision = Decision.REVIEW
            recommendation = "Agent flagged for manual review. Suspend high-risk actions."
        else:
            decision = Decision.BLOCK
            recommendation = "Agent blocked. Initiate investigation and revoke active sessions."

        result = RiskEvaluationResult(
            agent_id=agent_id,
            trust_score=trust_score,
            decision=decision,
            signals_triggered=triggered_signals,
            risk_categories=list(risk_categories),
            recommendation=recommendation
        )

        return result.to_dict()

    def get_signal_library(self) -> List[Dict]:
        """Return the full fraud signal library."""
        return [
            {
                "name": s.name,
                "category": s.category,
                "severity": s.severity.name,
                "description": s.description,
                "score_impact": s.score_impact
            }
            for s in self.signal_library.values()
        ]
