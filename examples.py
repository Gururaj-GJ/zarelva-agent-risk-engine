"""
Zarelva Agent Risk Engine - Usage Examples

Demonstrates fraud risk evaluation for various AI agent scenarios.

Author: Gururaj GJ
Founder - Zarelva | Fraud Intelligence & Risk Architecture
Website: https://zarelva.com
"""

from agent_risk_engine import ZarelvaRiskEngine
import json


def print_result(scenario_name: str, result: dict):
    """Pretty-print evaluation result."""
    print(f"\n{'='*60}")
    print(f"Scenario: {scenario_name}")
    print(f"{'='*60}")
    print(f"Agent ID      : {result['agent_id']}")
    print(f"Trust Score   : {result['trust_score']} / 100")
    print(f"Decision      : {result['decision']}")
    print(f"Risk Categories: {', '.join(result['risk_categories']) or 'None'}")
    print(f"Signals Triggered:")
    if result['signals_triggered']:
        for signal in result['signals_triggered']:
            print(f"  - {signal}")
    else:
        print("  None")
    print(f"Recommendation: {result['recommendation']}")


def main():
    engine = ZarelvaRiskEngine()

    # -------------------------------------------------------
    # Scenario 1: Clean Agent - Normal Operations
    # A well-established agent with normal behavior
    # Expected: ALLOW
    # -------------------------------------------------------
    clean_agent = {
        "agent_id": "finance-agent-001",
        "identity_age_days": 90,
        "identity_revoked": False,
        "unknown_issuer": False,
        "identity_cloned": False,
        "action_velocity": 10,
        "impossible_speed": False,
        "repeated_failed_actions": False,
        "abnormal_data_access": False,
        "delegation_depth": 1,
        "privilege_escalation": False,
        "delegation_to_unknown": False,
        "multi_agent_convergence": False,
        "shared_credentials": False,
        "synchronized_activity": False,
        "network_type": "clean",
        "financial_actions": False,
        "abnormal_payment_frequency": False,
        "data_exfiltration": False
    }
    result = engine.evaluate(clean_agent)
    print_result("Clean Agent - Normal Operations", result)

    # -------------------------------------------------------
    # Scenario 2: Suspicious Agent - New Identity + High Velocity
    # New agent with high action velocity operating via VPN
    # Expected: REVIEW or BLOCK
    # -------------------------------------------------------
    suspicious_agent = {
        "agent_id": "unknown-agent-x99",
        "identity_age_days": 0,
        "identity_revoked": False,
        "unknown_issuer": True,
        "identity_cloned": False,
        "action_velocity": 150,
        "impossible_speed": False,
        "repeated_failed_actions": True,
        "abnormal_data_access": False,
        "delegation_depth": 2,
        "privilege_escalation": False,
        "delegation_to_unknown": False,
        "multi_agent_convergence": False,
        "shared_credentials": False,
        "synchronized_activity": False,
        "network_type": "vpn",
        "financial_actions": False,
        "abnormal_payment_frequency": False,
        "data_exfiltration": False
    }
    result = engine.evaluate(suspicious_agent)
    print_result("Suspicious Agent - New Identity + High Velocity", result)

    # -------------------------------------------------------
    # Scenario 3: Compromised Financial Agent
    # Agent with valid identity but fraudulent financial behavior
    # Expected: BLOCK
    # -------------------------------------------------------
    compromised_agent = {
        "agent_id": "payment-agent-007",
        "identity_age_days": 30,
        "identity_revoked": False,
        "unknown_issuer": False,
        "identity_cloned": False,
        "action_velocity": 20,
        "impossible_speed": False,
        "repeated_failed_actions": False,
        "abnormal_data_access": True,
        "delegation_depth": 1,
        "privilege_escalation": True,
        "delegation_to_unknown": False,
        "multi_agent_convergence": False,
        "shared_credentials": False,
        "synchronized_activity": False,
        "network_type": "clean",
        "financial_actions": True,
        "abnormal_payment_frequency": True,
        "data_exfiltration": False
    }
    result = engine.evaluate(compromised_agent)
    print_result("Compromised Financial Agent", result)

    # -------------------------------------------------------
    # Scenario 4: Coordinated Agent Fraud Ring
    # Multiple agents showing coordination and shared credentials
    # Expected: BLOCK
    # -------------------------------------------------------
    coordinated_agent = {
        "agent_id": "bot-agent-ring-042",
        "identity_age_days": 0,
        "identity_revoked": False,
        "unknown_issuer": True,
        "identity_cloned": True,
        "action_velocity": 200,
        "impossible_speed": True,
        "repeated_failed_actions": False,
        "abnormal_data_access": True,
        "delegation_depth": 5,
        "privilege_escalation": False,
        "delegation_to_unknown": True,
        "multi_agent_convergence": True,
        "shared_credentials": True,
        "synchronized_activity": True,
        "network_type": "tor",
        "financial_actions": False,
        "abnormal_payment_frequency": False,
        "data_exfiltration": True
    }
    result = engine.evaluate(coordinated_agent)
    print_result("Coordinated Agent Fraud Ring", result)

    # -------------------------------------------------------
    # Scenario 5: Data Exfiltration Agent
    # Agent reading large data internally and writing externally
    # Expected: BLOCK
    # -------------------------------------------------------
    exfiltration_agent = {
        "agent_id": "data-agent-leak-01",
        "identity_age_days": 60,
        "identity_revoked": False,
        "unknown_issuer": False,
        "identity_cloned": False,
        "action_velocity": 40,
        "impossible_speed": False,
        "repeated_failed_actions": False,
        "abnormal_data_access": True,
        "delegation_depth": 2,
        "privilege_escalation": False,
        "delegation_to_unknown": False,
        "multi_agent_convergence": False,
        "shared_credentials": False,
        "synchronized_activity": False,
        "network_type": "datacenter",
        "financial_actions": False,
        "abnormal_payment_frequency": False,
        "data_exfiltration": True
    }
    result = engine.evaluate(exfiltration_agent)
    print_result("Data Exfiltration Agent", result)

    # Print signal library summary
    print(f"\n{'='*60}")
    print("Zarelva Fraud Signal Library Summary")
    print(f"{'='*60}")
    signals = engine.get_signal_library()
    print(f"Total signals in library: {len(signals)}")
    categories = {}
    for s in signals:
        cat = s['category']
        categories[cat] = categories.get(cat, 0) + 1
    for cat, count in sorted(categories.items()):
        print(f"  {cat}: {count} signals")


if __name__ == "__main__":
    main()
