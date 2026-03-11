# Zarelva Fraud Signal Library

Behavioral fraud detection signals for autonomous AI agents.

**Zarelva** — Fraud Intelligence & Risk Architecture | [https://zarelva.com](https://zarelva.com)

---

This document defines the fraud signal library used by the Zarelva Agent Risk Engine.
Each signal represents a behavioral, identity, delegation, coordination, network,
or financial anomaly that may indicate compromised or malicious agent activity.

---

## Signal Severity Levels

| Severity | Score Impact | Description |
|---|---|---|
| LOW | -5 | Minor anomaly, worth noting |
| MEDIUM | -15 | Moderate risk, monitor closely |
| HIGH | -25 to -30 | Significant fraud indicator |
| CRITICAL | -50 | Severe fraud signal, immediate action |

---

## 1. Identity Signals

Signals related to agent identity verification and credential integrity.

---

### `identity_age_new`
- **Severity:** HIGH
- **Score Impact:** -30
- **Description:** Agent identity was created very recently (less than 24 hours ago).
- **Why it matters:** Fraudulent agents are often created just before an attack. New identities with no history are a strong fraud indicator.
- **Detection:** Check `identity_created_at` timestamp. Flag if age < 1 day.

---

### `identity_revoked`
- **Severity:** CRITICAL
- **Score Impact:** -50
- **Description:** The agent's credential or identity has been formally revoked or invalidated.
- **Why it matters:** A revoked identity that is still active indicates either a replay attack or a system failure.
- **Detection:** Verify revocation status in the credential registry.

---

### `unknown_issuer`
- **Severity:** HIGH
- **Score Impact:** -30
- **Description:** The agent's credential was issued by an unknown, unregistered, or untrusted authority.
- **Why it matters:** Credentials from unknown issuers cannot be trusted. May indicate forged or self-issued credentials.
- **Detection:** Cross-reference credential issuer against trusted issuer registry.

---

### `identity_cloned`
- **Severity:** CRITICAL
- **Score Impact:** -50
- **Description:** The same agent identity (e.g., same signing key or credential) is being used simultaneously across multiple systems or locations.
- **Why it matters:** Identity cloning indicates stolen credentials being reused across a fraud operation.
- **Detection:** Monitor for identical credential usage across geographically or logically separate systems.

---

## 2. Behavioral Signals

Signals based on operational behavior patterns of the agent.

---

### `action_velocity_high`
- **Severity:** HIGH
- **Score Impact:** -25
- **Description:** The agent is performing actions at an abnormally high rate (e.g., > 100 actions per minute).
- **Why it matters:** Humans and legitimate agents operate within normal velocity ranges. High velocity suggests automation abuse, scraping, or flooding.
- **Detection:** Measure action rate over rolling time windows. Compare against agent-type baseline.

---

### `impossible_navigation_speed`
- **Severity:** HIGH
- **Score Impact:** -25
- **Description:** The agent transitions between resources or systems at a speed that is physically or logically impossible.
- **Why it matters:** Indicates either multiple agents acting as one, or an automated fraud tool bypassing normal workflows.
- **Detection:** Compare transition timestamps and resource locations.

---

### `repeated_failed_actions`
- **Severity:** MEDIUM
- **Score Impact:** -15
- **Description:** The agent is repeatedly attempting operations that fail — e.g., repeated authentication failures, access denied events.
- **Why it matters:** Common indicator of brute force attempts, credential stuffing, or probing for access.
- **Detection:** Count consecutive or frequent failed operations within a time window.

---

### `abnormal_data_access_pattern`
- **Severity:** HIGH
- **Score Impact:** -25
- **Description:** The agent is accessing data resources outside its normal operational scope — different datasets, higher volumes, or unusual timing.
- **Why it matters:** Precursor to data exfiltration or unauthorized intelligence gathering.
- **Detection:** Compare access patterns against agent role baseline and historical behavior.

---

## 3. Delegation Signals

Signals related to how agents delegate permissions and authority to other agents.

---

### `delegation_depth_high`
- **Severity:** HIGH
- **Score Impact:** -25
- **Description:** The delegation chain from the originating agent exceeds an acceptable depth (e.g., > 3 levels).
- **Why it matters:** Deep delegation chains obscure accountability and can be used to hide the true origin of malicious actions.
- **Detection:** Count delegation hops from root agent. Flag chains exceeding threshold.

---

### `privilege_escalation`
- **Severity:** CRITICAL
- **Score Impact:** -50
- **Description:** The agent is attempting to acquire or exercise permissions beyond what was originally delegated to it.
- **Why it matters:** Privilege escalation is a core attack pattern across all security domains. In agent systems, it can enable unauthorized actions.
- **Detection:** Compare requested permissions against delegated permissions at each step.

---

### `delegation_to_unknown_agent`
- **Severity:** HIGH
- **Score Impact:** -30
- **Description:** The agent has delegated authority to a second agent that is unknown, unregistered, or unverified.
- **Why it matters:** Delegating to unknown agents is a common way to inject malicious agents into a trusted workflow.
- **Detection:** Verify all delegation recipients against known agent registry.

---

## 4. Coordination Signals

Signals that suggest multiple agents may be operating together as part of a coordinated fraud operation.

---

### `multi_agent_convergence`
- **Severity:** HIGH
- **Score Impact:** -25
- **Description:** Multiple distinct agents are simultaneously targeting the same resource, system, or endpoint.
- **Why it matters:** Coordinated convergence can overwhelm systems or concentrate fraudulent activity. Mirrors botnet behavior.
- **Detection:** Monitor for simultaneous agent activity on the same resource within short time windows.

---

### `shared_credentials`
- **Severity:** CRITICAL
- **Score Impact:** -50
- **Description:** Multiple agents are using identical cryptographic credentials, signing keys, or authentication tokens.
- **Why it matters:** Legitimate agents each have unique credentials. Sharing indicates credential theft, reuse, or a fraud ring operating from a single stolen identity.
- **Detection:** Detect credential hash collisions across distinct agent sessions.

---

### `synchronized_activity`
- **Severity:** HIGH
- **Score Impact:** -30
- **Description:** Multiple agents are performing identical or near-identical actions within very tight time windows.
- **Why it matters:** Human-coordinated fraud requires communication latency. Synchronized automation without latency indicates programmatic coordination.
- **Detection:** Cluster agent activity by action type and timestamp. Flag near-simultaneous identical actions.

---

## 5. Network Signals

Signals based on the network origin and infrastructure of the agent.

---

### `tor_exit_node`
- **Severity:** HIGH
- **Score Impact:** -30
- **Description:** The agent is originating from a known Tor network exit node.
- **Why it matters:** Tor is commonly used to anonymize fraudulent activity. Legitimate enterprise agents typically do not use Tor.
- **Detection:** Cross-reference source IP against known Tor exit node lists.

---

### `vpn_detected`
- **Severity:** MEDIUM
- **Score Impact:** -15
- **Description:** The agent appears to be operating behind a VPN or proxy service.
- **Why it matters:** VPN usage can obscure the true origin of an agent. Common in fraud attempts to bypass geo-restrictions or rate limits.
- **Detection:** Use IP reputation databases to identify VPN and proxy infrastructure.

---

### `datacenter_ip`
- **Severity:** MEDIUM
- **Score Impact:** -10
- **Description:** The agent is originating from a known datacenter or cloud provider IP range rather than a legitimate business network.
- **Why it matters:** While cloud-hosted agents are normal, unexpected datacenter IPs for agents claiming to be on-premises systems is anomalous.
- **Detection:** Cross-reference source IP against datacenter IP block databases (AWS, GCP, Azure, etc.).

---

## 6. Financial Signals

Signals specific to agents interacting with financial systems, payment platforms, or sensitive data.

---

### `unauthorized_payment_action`
- **Severity:** CRITICAL
- **Score Impact:** -50
- **Description:** The agent is initiating or processing financial transactions without valid human authorization in the delegation chain.
- **Why it matters:** Financial actions without human oversight represent the highest fraud risk in agent ecosystems.
- **Detection:** Verify that all financial actions have a valid, traceable human authorization event in the delegation chain.

---

### `abnormal_payment_frequency`
- **Severity:** HIGH
- **Score Impact:** -30
- **Description:** The agent is initiating payment events at a frequency that exceeds the normal operational baseline for its role and context.
- **Why it matters:** A compromised payment agent may attempt to push through many transactions quickly before being detected.
- **Detection:** Monitor payment event frequency against agent-type baseline. Alert on anomalies.

---

### `data_exfiltration_pattern`
- **Severity:** CRITICAL
- **Score Impact:** -50
- **Description:** The agent exhibits a pattern of large internal data reads followed immediately by external API writes or data transfers.
- **Why it matters:** This is a primary indicator of data theft via a compromised agent. Data read and immediately exported externally is rarely legitimate.
- **Detection:** Correlate large internal read events with outbound data transfer events within short time windows.

---

## Signal Summary Table

| Signal | Category | Severity | Score Impact |
|---|---|---|---|
| `identity_age_new` | Identity | HIGH | -30 |
| `identity_revoked` | Identity | CRITICAL | -50 |
| `unknown_issuer` | Identity | HIGH | -30 |
| `identity_cloned` | Identity | CRITICAL | -50 |
| `action_velocity_high` | Behavioral | HIGH | -25 |
| `impossible_navigation_speed` | Behavioral | HIGH | -25 |
| `repeated_failed_actions` | Behavioral | MEDIUM | -15 |
| `abnormal_data_access_pattern` | Behavioral | HIGH | -25 |
| `delegation_depth_high` | Delegation | HIGH | -25 |
| `privilege_escalation` | Delegation | CRITICAL | -50 |
| `delegation_to_unknown_agent` | Delegation | HIGH | -30 |
| `multi_agent_convergence` | Coordination | HIGH | -25 |
| `shared_credentials` | Coordination | CRITICAL | -50 |
| `synchronized_activity` | Coordination | HIGH | -30 |
| `tor_exit_node` | Network | HIGH | -30 |
| `vpn_detected` | Network | MEDIUM | -15 |
| `datacenter_ip` | Network | MEDIUM | -10 |
| `unauthorized_payment_action` | Financial | CRITICAL | -50 |
| `abnormal_payment_frequency` | Financial | HIGH | -30 |
| `data_exfiltration_pattern` | Financial | CRITICAL | -50 |

---

## Trust Score & Decision Framework

| Trust Score | Decision | Action |
|---|---|---|
| 70 - 100 | ALLOW | Agent cleared for normal operations |
| 40 - 69 | REVIEW | Suspend high-risk actions, flag for manual review |
| 0 - 39 | BLOCK | Block agent, revoke sessions, initiate investigation |

---

## Research Notes

This signal library is part of ongoing research into fraud detection for AI-native systems.

As autonomous agent frameworks evolve, this library will be extended to cover:
- LLM prompt injection signals
- Agentic memory manipulation
- Cross-system privilege propagation
- Agent impersonation patterns

---

## Author

**Gururaj GJ**  
Founder — Zarelva  
Fraud Intelligence & Risk Architecture  
[https://zarelva.com](https://zarelva.com)

---

*Zarelva — Fraud Intelligence & Risk Architecture*
