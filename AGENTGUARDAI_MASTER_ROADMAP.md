# AGENTGUARD AI
## MASTER DEVELOPMENT ROADMAP

Vision:
An explainable blockchain security intelligence platform that investigates
blockchain activity, identifies potential threats, evaluates proposed
transactions and protects AI agents through independent security policies
and human approval.

Project principles:
- Explainable, evidence-based security intelligence.
- Human-controlled approval.
- Read-only blockchain investigation.
- No private-key or seed-phrase collection.
- No real transaction signing or broadcasting.
- Independent security policy enforcement.
- Free tools and sample data wherever possible.
- Never describe unverified capabilities as production-ready.

---

# CURRENT PROJECT BASELINE

The following capabilities have been implemented or represented in the
existing project. Their current production readiness must be verified
during the relevant development phase.

- NEAR network monitoring.
- NEAR market intelligence.
- NEAR transaction investigation.
- NEAR wallet behaviour analysis.
- Wallet investigation history.
- Wallet investigation comparison.
- Threat verdict comparison.
- Access-Key Security Scanner.
- Multi-Account Security Scanner.
- Transaction risk assessment.
- Approval management.
- Simulated transaction executor.
- Transaction history.
- Developer API gateway.
- API key management.
- Python SDK.
- Developer analytics.
- Account authentication.

Previously reported automated test baseline:
360 tests passed.

This is a historical baseline, not a guarantee that every future change
has passed the complete test suite.

---

# PHASE 1 - CORE SECURITY AND RELIABILITY

Priority: CRITICAL
Status: PLANNED / VERIFICATION REQUIRED

Tasks:

1. Complete wallet comparison API regression tests.
2. Test identical threat verdicts.
3. Test different threat verdicts.
4. Test missing historical verdict fields.
5. Secure wallet investigation history.
6. Enforce authenticated user ownership.
7. Add authorization tests.
8. Improve API input validation.
9. Improve error handling.
10. Add RPC timeout and retry handling.
11. Improve structured application logging.
12. Review API rate limiting.
13. Review authentication and session security.
14. Review CSRF protection.
15. Review sensitive data exposure.
16. Add security regression tests.

Deliverable:
A secure and reliable application foundation.

Important:
Wallet history must not be presented as private until ownership and
authorization controls are enforced and tested.

---

# PHASE 2 - ADVANCED NEAR TRANSACTION INTELLIGENCE

Priority: CRITICAL
Status: PLANNED / EXISTING FEATURES TO VERIFY

Tasks:

1. Detailed transaction execution analysis.
2. Receipt execution timeline.
3. Failed receipt investigation.
4. Contract interaction profiling.
5. Function-call analysis.
6. Transfer and balance-change analysis where evidence is available.
7. Account permission change detection.
8. Suspicious transaction pattern detection.
9. Transaction evidence summaries.
10. Historical transaction comparison.
11. Better RPC failure reporting.
12. Investigation report export.

Proposed feature:
NEAR Transaction Intelligence Report.

Report contents:

- Transaction overview.
- Sender and receiver information.
- Contract interactions.
- Execution outcome.
- Receipt analysis.
- Security findings.
- Supporting evidence.
- Risk assessment.
- Confidence level.
- Investigation limitations.

Deliverable:
A detailed, evidence-based NEAR transaction investigation system.

---

# PHASE 3 - ADVANCED WALLET INTELLIGENCE

Priority: CRITICAL
Status: EXISTING FOUNDATION / EXPANSION PLANNED

Tasks:

1. Wallet activity profiling.
2. Permission change monitoring.
3. Contract interaction profiling.
4. Repeated failure detection.
5. Suspicious activity clustering.
6. Wallet risk history.
7. Investigation evidence comparison.
8. Confidence improvements.
9. Wallet investigation export.
10. Better sample coverage reporting.
11. Historical finding comparison.
12. Improved investigation summaries.

Proposed feature:
Wallet Security Timeline.

Timeline events may include:

- New access key detected.
- Contract deployment detected.
- Account deletion action detected.
- Repeated receipt failures detected.
- Other evidence-supported security events.

Deliverable:
A stronger wallet investigation and behavioural intelligence system.

---

# PHASE 4 - ACCESS-KEY SECURITY INTELLIGENCE

Priority: HIGH
Status: EXISTING FOUNDATION / EXPANSION PLANNED

Tasks:

1. Full-access key detection.
2. Function-call key analysis.
3. Contract permission inspection.
4. Allowance analysis.
5. Receiver restrictions.
6. Permission change comparison.
7. Risk explanations for individual keys.
8. Historical key comparison.
9. Key exposure summaries.
10. Exportable security reports.
11. Better account permission visualisation.
12. Permission investigation tests.

Proposed feature:
Account Permission Risk Report.

Deliverable:
Evidence-based account permission security analysis.

---

# PHASE 5 - MULTI-ACCOUNT SECURITY INTELLIGENCE

Priority: HIGH
Status: EXISTING FOUNDATION / EXPANSION PLANNED

Tasks:

1. Configurable account lists.
2. Account permission comparison.
3. Balance comparison.
4. Security exposure comparison.
5. Account relationship investigation.
6. Bulk security reports.
7. Account risk ranking.
8. Historical scan comparison.
9. Failed account scan reporting.
10. Exportable multi-account reports.
11. Better scan progress indicators.
12. Improved account scan validation.

Proposed feature:
NEAR Ecosystem Security Map.

Important:
Distinguish direct transaction relationships from other receipt participants.

Deliverable:
Multi-account blockchain security intelligence.

---

# PHASE 6 - ADVANCED TRANSACTION PROTECTION

Priority: CRITICAL
Status: EXISTING FOUNDATION / EXPANSION PLANNED

Tasks:

1. Pre-transaction inspection.
2. Recipient risk evaluation.
3. Contract interaction checks.
4. Unlimited approval detection.
5. Spending-limit enforcement.
6. Duplicate transaction prevention.
7. Policy-based transaction decisions.
8. Human approval requirements.
9. Transaction fingerprinting.
10. Security decision audit logs.
11. Policy enforcement tests.
12. Independent executor validation.

Proposed architecture:

AI AGENT
    |
    v
PROPOSED TRANSACTION
    |
    v
AGENTGUARD INSPECTION
    |
    v
SECURITY INTELLIGENCE
    |
    v
INDEPENDENT POLICY ENGINE
    |
    +-------------------+
    |                   |
    v                   v
  PERMIT               BLOCK
    |
    v
APPROVAL CHECK
    |
    +-------------------+
    |                   |
    v                   v
REQUIRES             APPROVED
CONFIRMATION

Important:
A permitted decision does not bypass applicable approval requirements.

Deliverable:
An independently enforced transaction security gateway.

---

# PHASE 7 - AI AGENT SECURITY PLATFORM

Priority: VERY HIGH
Status: PLANNED

Tasks:

1. Agent identity registration.
2. Agent permission profiles.
3. Agent transaction inspection.
4. Agent spending policies.
5. Agent activity history.
6. Agent risk profiles.
7. Agent authorization.
8. Agent audit trail.
9. Reusable policy templates.
10. Agent security dashboard.
11. Agent inspection analytics.
12. Agent integration examples.

Flagship feature:
AGENTGUARD SENTINEL.

Purpose:
An independent security layer between AI agents and blockchain
transaction execution systems.

Core principle:
An AI agent may propose an action, but AgentGuard evaluates whether
that action satisfies configured security policies.

Deliverable:
A reusable AI-agent transaction protection platform.

---

# PHASE 8 - CROSS-CHAIN SECURITY INTELLIGENCE

Priority: HIGH
Status: PLANNED / NETWORK CAPABILITIES MUST BE VERIFIED

Network roadmap:

1. NEAR.
2. BNB Chain.
3. Ethereum.

Tasks:

1. Network-specific transaction analyzers.
2. Network-specific account analyzers.
3. Contract interaction investigation.
4. Token approval analysis.
5. Network-specific risk rules.
6. Unified investigation reports.
7. Unified API interface.
8. Network-specific integration tests.
9. RPC provider reliability.
10. Network capability documentation.

Important:
Do not advertise live investigation capabilities for a network until
they have actually been implemented and tested.

Deliverable:
A multi-network blockchain security intelligence platform.

---

# PHASE 9 - SECURITY INTELLIGENCE ENGINE

Priority: VERY HIGH
Status: EXISTING RULE ENGINE / EXPANSION PLANNED

Tasks:

1. Centralized risk indicator registry.
2. Evidence-based finding generation.
3. Confidence calculation.
4. Risk score explanations.
5. Configurable security policies.
6. Network-specific detection rules.
7. Detection rule versioning.
8. False-positive tracking.
9. Finding severity classification.
10. Explainable security summaries.
11. Detection regression tests.
12. Security rule documentation.

Future research:

Machine-learning-assisted anomaly detection may be investigated
after reliable datasets, validation procedures and measurable
accuracy are available.

Important:
The current deterministic rule-based engine must not be described
as a machine-learning model.

Deliverable:
A maintainable and explainable security intelligence engine.

---

# PHASE 10 - DEVELOPER PLATFORM AND SDK

Priority: HIGH
Status: EXISTING FOUNDATION / EXPANSION PLANNED

Tasks:

1. Comprehensive API documentation.
2. SDK usage examples.
3. API error documentation.
4. API versioning.
5. Request validation examples.
6. Authentication tutorials.
7. Rate-limit documentation.
8. Webhook support where appropriate.
9. SDK integration tests.
10. AI-agent integration examples.
11. Developer sandbox.
12. Sample transaction datasets.
13. API health monitoring.
14. Developer onboarding documentation.

Proposed integrations:

- Python AI agents.
- LangChain-based agents.
- Custom autonomous agents.
- Web3 applications.
- Backend transaction services.

Deliverable:
A developer-friendly blockchain security API and SDK.

---

# PHASE 11 - DASHBOARD AND USER EXPERIENCE

Priority: MEDIUM
Status: EXISTING DASHBOARD / IMPROVEMENTS PLANNED

Tasks:

1. Reorganise navigation.
2. Group investigation tools together.
3. Group protection tools together.
4. Improve mobile responsiveness.
5. Improve investigation reports.
6. Add investigation status indicators.
7. Improve loading states.
8. Improve empty states.
9. Add downloadable reports.
10. Improve charts and visualisations.
11. Add consistent risk-level styling.
12. Improve accessibility.
13. Improve error messages.
14. Improve dashboard performance.

Proposed navigation:

AGENTGUARD AI
|
+-- OVERVIEW
|
+-- BLOCKCHAIN INTELLIGENCE
|   +-- Network Activity
|   +-- NEAR Market
|   +-- Transaction Investigator
|   +-- Wallet Behaviour
|   +-- Access-Key Scanner
|   +-- Multi-Account Scanner
|
+-- SECURITY PROTECTION
|   +-- Transaction Security
|   +-- Agent Protection
|   +-- Approval Center
|   +-- Security Policies
|
+-- INVESTIGATION HISTORY
|   +-- Transaction History
|   +-- Wallet History
|   +-- Investigation Comparison
|
+-- DEVELOPER PLATFORM
|   +-- API Keys
|   +-- Developer Analytics
|   +-- Python SDK
|   +-- API Reference
|
+-- ACCOUNT AND SETTINGS

Deliverable:
A coherent, accessible and professional security dashboard.

---

# PHASE 12 - PRODUCTION READINESS AND RELEASE

Priority: CRITICAL
Status: PLANNED

Tasks:

1. Comprehensive unit testing.
2. Integration testing.
3. Authentication and authorization review.
4. Privacy and data retention review.
5. RPC resilience testing.
6. Database optimisation.
7. API performance testing.
8. Application health monitoring.
9. Error monitoring.
10. Technical documentation.
11. Deployment reliability.
12. Database backup and recovery.
13. Release versioning.
14. Changelog maintenance.
15. Security limitations documentation.
16. Production readiness review.

Release stages:

- Development.
- Internal testing.
- Public beta.
- Security review.
- Production release.

Deliverable:
A documented, tested and maintainable release.

---

# FLAGSHIP FEATURES

These are major future product capabilities.

1. AgentGuard Sentinel
   Independent AI-agent transaction protection.

2. Wallet Security Timeline
   Chronological evidence-based wallet activity.

3. NEAR Ecosystem Security Map
   Visual investigation of observed account relationships.

4. Smart Contract Risk Investigator
   Investigation of contract interactions and available metadata.

5. Agent Behaviour Intelligence
   Analysis of observed AI-agent transaction proposals.

6. Cross-Chain Security Engine
   Unified security analysis across supported networks.

7. Security Intelligence Reports
   Evidence-backed investigation reports.

8. Policy Intelligence Centre
   Reusable transaction security policies.

---

# MASTER PRIORITY ORDER

1. Core Security and Reliability.
2. Advanced NEAR Transaction Intelligence.
3. Advanced Wallet Intelligence.
4. Access-Key Security Intelligence.
5. Multi-Account Security Intelligence.
6. Advanced Transaction Protection.
7. AI Agent Security Platform.
8. Cross-Chain Security Intelligence.
9. Security Intelligence Engine.
10. Developer Platform and SDK.
11. Dashboard and User Experience.
12. Production Readiness and Release.

---

# DEVELOPMENT SPRINT RULES

Every sprint must follow this process:

1. Inspect the existing code.
2. Identify the exact feature and dependencies.
3. Design the implementation.
4. Make changes using PowerShell.
5. Run targeted tests.
6. Run the complete test suite.
7. Inspect the Git diff.
8. Commit and push only after validation.
9. Verify Render deployment.
10. Update this roadmap.

Never:

- Invent completed features.
- Claim untested functionality is production-ready.
- Collect private keys or seed phrases.
- Sign or broadcast real transactions.
- Allow intelligence findings to override security policies.
- Treat unusual activity as proof of malicious behaviour.
- Describe rule-based analysis as machine learning.
- Expose private user data without authorization.

---

# SUCCESS VISION

AgentGuard AI will be developed around five pillars:

1. BLOCKCHAIN INTELLIGENCE
   Understand blockchain activity.

2. WALLET INTELLIGENCE
   Investigate account behaviour and permissions.

3. SECURITY INTELLIGENCE
   Detect and explain potential threats.

4. AGENT PROTECTION
   Protect AI agents from unsafe proposed transactions.

5. DEVELOPER INFRASTRUCTURE
   Allow applications and agents to integrate AgentGuard.

Central product principle:

An AI agent may be intelligent, but intelligence alone does not
guarantee safety.

AgentGuard AI provides an independent, explainable security layer
between autonomous agents and blockchain transactions.

END OF MASTER ROADMAP