# AgentGuard AI 🛡️

### Blockchain Transaction Security Gateway for AI Agents

AgentGuard AI is a blockchain security platform designed to help developers and AI agents inspect proposed blockchain transactions before execution.

It provides transaction risk analysis, security intelligence, human approval workflows, developer API authentication, and NEAR network investigation tools.

**Live Dashboard:** https://agentguardai.onrender.com
**GitHub Repository:** https://github.com/abdulazizusman8171-del/AgentGuardAI

---

## 1. The Problem

AI agents are increasingly interacting with blockchain networks, smart contracts, wallets, and decentralized applications.

However, autonomous transaction workflows introduce security risks:

- Transactions sent to unknown recipients.
- Suspicious contract interactions.
- Excessive token approvals.
- Duplicate transaction attempts.
- Transactions exceeding configured spending limits.
- Insufficient human oversight.

AgentGuard AI addresses these challenges by introducing a security inspection layer between AI agents and blockchain transaction workflows.

## 2. Our Solution

AgentGuard AI evaluates proposed transactions and returns structured security assessments.

Depending on the assessment, a transaction may be:

- Permitted for simulated execution.
- Held for human approval.
- Rejected because of security concerns.

The platform also provides blockchain intelligence and monitoring capabilities, with a particular focus on the NEAR ecosystem.

## 3. Key Features

### Transaction Security
- Transaction risk evaluation.
- Recipient and transaction checks.
- Duplicate transaction detection.
- Spending-limit enforcement.
- Structured security decisions.

### Human Approval Management
- Pending approval workflows.
- Approval ownership controls.
- Transaction fingerprinting.
- Approval lifecycle management.

### NEAR Blockchain Intelligence
- NEAR account monitoring.
- Finalized transaction investigation.
- Contract interaction analysis.
- Receipt execution evidence.
- Delegate transaction analysis.
- NEAR market monitoring, subject to external data availability.
- Large-buy activity monitoring, dependent on external market data.

### Security Intelligence
- Access-key security analysis.
- Gas-key analysis.
- Transaction security intelligence.
- Risk assessment and explanatory findings.

### Developer Integration
- Authenticated developer API.
- API key management.
- Python SDK.
- Structured JSON responses.
- Request size and rate-limit protections.

---

## 4. Architecture

AgentGuard AI consists of four main layers:

| Layer | Responsibility |
|---|---|
| Dashboard | User interface and blockchain monitoring |
| FastAPI backend | API routing and application services |
| Security engine | Transaction inspection, risk analysis and approval workflows |
| Developer SDK | Python integration for AI agents |

The platform uses SQLite for application data storage and integrates with NEAR network data services.

### Wallet Investigation Data Protection

Saved wallet behaviour reports are associated with the authenticated user who created them. The API restricts history, individual report retrieval and comparisons to the report owner. Unauthenticated requests are rejected.

---

## 5. Python SDK

The AgentGuard Python SDK allows developers to submit proposed transactions to the security gateway.

### Installation

Install from the locally built wheel:

```powershell
python -m pip install dist\agentguard_ai-0.1.0-py3-none-any.whl
```

The package distribution name is `agentguard-ai`, and its Python import name is `agentguard`.

PyPI publication should only be announced once the package has actually been published.

### Authentication

Create an AgentGuard developer API key through the authenticated developer API workflow.

Set the key as an environment variable:

```powershell
$env:AGENTGUARD_API_KEY = "YOUR_AGENTGUARD_API_KEY"
```

Never commit API keys to GitHub or share them publicly.

### Quick Start

```python
import os

from agentguard import AgentGuardClient, AgentGuardError

client = AgentGuardClient(
    api_key=os.environ["AGENTGUARD_API_KEY"]
)

transaction = {
    "transaction_id": "agentguard-demo-001",
    "amount": 0.1,
    "network": "ethereum",
    "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
    "recipient_known": True,
    "new_contract": False,
    "unlimited_approval": False
}

try:
    result = client.inspect(transaction)

    print("Gateway:", result["gateway_status"])
    print("Security decision:", result["security_report"]["decision"])
    print("Risk score:", result["security_report"]["risk_score"])

except AgentGuardError as error:
    print("AgentGuard error:", error)
```

Use an API key issued to your own account. The transaction above is illustrative test data.

### Gateway Decisions

| Gateway status | Meaning |
|---|---|
| `PERMITTED` | Eligible for simulated execution |
| `APPROVAL_REQUIRED` | Human approval is required |
| `REJECTED` | Transaction was rejected |

The SDK also provides:

```python
client.is_permitted(result)
client.requires_approval(result)
client.is_rejected(result)
```

---

## 6. Security Model

AgentGuard AI's Python SDK is inspection-only.

It does not:

- Sign blockchain transactions.
- Broadcast transactions.
- Execute real blockchain transactions.
- Approve transactions.
- Request wallet private keys or seed phrases.

A `PERMITTED` response is not authorization to sign or broadcast a transaction.

The gateway's approval workflow provides an additional human oversight mechanism.

API keys should be stored securely and must never be exposed in public repositories or frontend code.

---

## 7. Technology Stack

- Python
- FastAPI
- SQLite
- JavaScript
- HTML and CSS
- NEAR blockchain integration
- CoinGecko market data integration
- Python SDK
- Git and GitHub
- Render deployment

---

## 8. Testing

The project has a backend regression test suite.

Run:

```powershell
python -m unittest discover -s tests -v
```

Validate frontend JavaScript:

```powershell
node --check app\static\app.js
```

Build the Python SDK:

```powershell
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
```

The reported final regression run completed with **307 tests passing**.

The SDK wheel was also successfully built and installed in the development environment.

The latest targeted Sprint 6 verification completed with 131 passing API and storage tests.

---

## 9. Project Links

- Live application: https://agentguardai.onrender.com
- Source code: https://github.com/abdulazizusman8171-del/AgentGuardAI

---

## 10. Current Limitations

- Transaction inspection does not guarantee that a transaction is safe.
- `PERMITTED` does not authorize real transaction execution.
- NEAR monitoring depends on the availability of external network data services.
- Rate limiting is process-local and may require shared storage for multi-instance deployments.
- The Python SDK is version 0.1.0.
- Public PyPI availability must be confirmed separately.

---

## 11. License

AgentGuard AI is released under the MIT License.

See [LICENSE](LICENSE) for details.
