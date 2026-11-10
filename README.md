# AgentGuardAI 🛡️

### Explainable Blockchain Transaction Security

AgentGuardAI is a blockchain transaction security application designed to help users identify potentially dangerous transactions before execution.

It evaluates transaction risk, identifies suspicious activity, provides understandable security findings, and supports human approval workflows.

The project combines a Python security engine, a FastAPI backend, a SQLite transaction tracker, and a web-based security dashboard.

> **Project status:** Hackathon prototype — under active development.

---

## 🚀 Key Features

### 1. Transaction Risk Assessment
Evaluates transactions using configurable security rules, including:

- Large transaction amounts.
- Transactions exceeding configured spending limits.
- Unknown recipients.
- Interactions with new smart contracts.
- Unlimited token approvals.
- Dangerous addresses on a configurable blocklist.
- Duplicate transaction detection.

### 2. Explainable Security Intelligence

AgentGuardAI generates understandable security findings containing:

- Risk severity.
- Explanation of detected risks.
- Recommended protective actions.
- Overall transaction security decisions.

The current intelligence engine uses deterministic rules rather than a trained machine-learning model.

### 3. Human Approval Workflow

Transactions requiring additional confirmation can enter an approval workflow.

Features include:
- Approval request creation.
- Time-limited approvals.
- Approval verification.
- Protection against unauthorized confirmation.
- Approval consumption during processing.

The current approval lifetime is five minutes.

### 4. Blockchain Integration

Supported network identifiers include:

| Network | Current capabilities |
|---|---|
| Ethereum | Address validation and security evaluation |
| BNB Chain | Address validation and security evaluation |
| NEAR Protocol | Address validation, account queries and transaction queries |

**Important:** Ethereum and BNB Chain transaction evaluation currently uses supplied transaction information. NEAR integration supports read-only RPC queries. The application does not broadcast real blockchain transactions.

### 5. Transaction Tracking

SQLite-backed storage supports transaction tracking and duplicate detection.

### 6. Security Dashboard

The web dashboard provides:

- Transaction risk evaluation.
- Risk scores.
- Security decisions.
- Security findings.
- Recommendations.
- Network selection.
- Transaction simulation feedback.

---

## 🏗️ Technology Stack

| Component | Technology |
|---|---|
| Backend | Python |
| API | FastAPI |
| Dashboard | HTML, CSS, JavaScript |
| Templates | Jinja2 |
| Database | SQLite |
| Blockchain integration | NEAR JSON-RPC |
| Testing | Python unittest |
| Server | Uvicorn |

---

## 📁 Project Structure

```text
AgentGuardAI/
│
├── app/
│   ├── api.py
│   ├── main.py
│   ├── approval.py
│   ├── executor.py
│   ├── workflow.py
│   ├── storage.py
│   ├── near_client.py
│   ├── security_intelligence.py
│   │
│   ├── templates/
│   │   └── index.html
│   │
│   └── static/
│       ├── app.js
│       └── styles.css
│
├── data/
├── storage/
├── tests/
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

### Requirements

- Python 3.12 or compatible version.
- Git.
- Internet connection for NEAR RPC queries.

### 1. Clone the repository

```bash
git clone https://github.com/abdulazizusman8171-del/AgentGuardAI.git
cd AgentGuardAI
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Start the application

```bash
python -m uvicorn app.api:app --reload
```

### 5. Open the dashboard

Visit:

```text
http://127.0.0.1:8000/
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

Health check:

```text
http://127.0.0.1:8000/health
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Security dashboard |
| GET | `/health` | Application health |
| POST | `/evaluate` | Evaluate transaction risk |
| POST | `/intelligence` | Generate explainable security findings |
| POST | `/approvals` | Create approval request when required |
| POST | `/approvals/{approval_id}/approve` | Approve a pending request |
| POST | `/process` | Process a transaction through the security workflow |
| GET | `/near/accounts/{account_id}` | Retrieve NEAR account information |
| GET | `/near/transactions/{tx_hash}` | Retrieve NEAR transaction information |

---

## 🧪 Running Tests

Run the complete test suite:

```bash
python -m unittest discover -s tests -v
```

The tests cover transaction evaluation, security intelligence, approval workflows, transaction execution, storage, API behavior, and NEAR RPC integration.

---

## 🔐 Security Design

AgentGuardAI follows a security-first transaction workflow:

1. Receive transaction information.
2. Validate transaction data and recipient address.
3. Check configured security rules.
4. Calculate a risk score.
5. Generate a security decision.
6. Request human confirmation when required.
7. Block transactions identified as dangerous.
8. Simulate execution when permitted.
9. Record successful simulated executions.

### Security decisions

| Decision | Meaning |
|---|---|
| ALLOW | No blocking security condition was detected |
| REQUIRE_CONFIRMATION | Additional human verification is required |
| BLOCK | The transaction must not proceed |

---

## ⚠️ Current Limitations

AgentGuardAI is an experimental prototype and is not production-ready.

- Transaction risk assessment currently uses deterministic rules.
- It does not perform a comprehensive smart-contract audit.
- It does not independently verify all transaction claims against blockchain state.
- Ethereum and BNB Chain live transaction execution are not implemented.
- NEAR integration is read-only.
- Transaction execution is simulated.
- The system has not undergone an independent security audit.

Never use this prototype as the sole security control for real funds.

---

## 🎯 Project Vision

The long-term goal is to develop AgentGuardAI into a multi-chain transaction security platform that helps users understand transaction risks before interacting with blockchain applications.

Future development may include:

- More advanced smart-contract analysis.
- Additional blockchain integrations.
- Improved threat intelligence.
- Wallet integrations with explicit user authorization.
- More sophisticated risk detection.
- Enhanced security monitoring.

---

## 👨‍💻 Development

AgentGuardAI is an actively developing open-source project.

Contributions, feedback, testing, and collaboration are welcome.

**GitHub:** https://github.com/abdulazizusman8171-del/AgentGuardAI

---

**AgentGuardAI — Understand the risk before you transact.**