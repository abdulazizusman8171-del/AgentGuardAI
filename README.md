# AgentGuard AI 🛡️

### NEAR-First Blockchain Security Intelligence

AgentGuard AI is a blockchain security intelligence platform designed to help users investigate suspicious blockchain activity through evidence-based findings.

The project focuses on NEAR Protocol, providing read-only investigation of accounts, access keys, finalized transactions, receipt execution outcomes, and network activity.

**Project status:** Hackathon prototype.

**Live Demo:** https://agentguardai.onrender.com/

## Key Features

### NEAR Transaction Investigator
- Investigates finalized NEAR transactions.
- Examines receipt execution success, failure, and unresolved outcomes.
- Reviews authorization and execution evidence.
- Identifies delegated actions, access-key additions, and account deletion activity.

### Access-Key Security Intelligence
- Full-access permissions.
- Function-call restrictions.
- Receiver-account restrictions.
- Allowed methods and gas allowances.
- Public-key information.

### Gas Key Investigation
Examines available Gas Key metadata, restrictions, allowance, balance, and nonce evidence.

### Explainable Security Findings
Structured findings include code, title, severity, description, evidence, and recommendation.

### Transaction Risk Assessment
Uses deterministic rules to evaluate supplied transaction information, including spending limits, unknown recipients, new contracts, unlimited approvals, and duplicate transactions.

### Human Approval Workflow
Supports approval requests and approval tracking.

### NEAR Network Intelligence
Provides NEAR network activity, market information, and large-buy activity.

## Technology Stack

- Python 3.12
- FastAPI
- JavaScript
- HTML and CSS
- SQLite
- NEAR blockchain RPC
- Uvicorn


## Project Structure

- app/api.py
- app/main.py
- app/near_client.py
- app/access_key_analyzer.py
- app/security_intelligence.py
- app/storage.py
- app/templates/
- app/static/
- tests/
- requirements.txt
- README.md


## Installation

Requirements: Python 3.12, Git, and internet connection.

### 1. Clone the repository
```bash
git clone https://github.com/abdulazizusman8171-del/AgentGuardAI.git
cd AgentGuardAI
```

### 2. Create virtual environment
```powershell
python -m venv .venv
```

### 3. Activate environment
```powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Install dependencies
```powershell
pip install -r requirements.txt
```

### 5. Start application
```powershell
python -m uvicorn app.api:app --reload
```

Dashboard: http://127.0.0.1:8000
API documentation: http://127.0.0.1:8000/docs


## Render Deployment

Build command:

```bash
pip install -r requirements.txt
```

Start command:

```bash
python -m uvicorn app.api:app --host 0.0.0.0 --port $PORT
```


## API Reference

| Method | Endpoint | Purpose |
|---|---|---|
| GET | /health | Application health |
| GET | /near/accounts/{account_id} | NEAR account information |
| GET | /near/accounts/{account_id}/access-keys | Access-key investigation |
| GET | /near/network-activity | NEAR network activity |
| GET | /near/market | NEAR market intelligence |
| GET | /near/transactions/{tx_hash} | Transaction investigation |
| GET | /near/transactions/{tx_hash}/analysis | Transaction security analysis |
| GET | /near/large-buys | Large-buy activity |
| POST | /evaluate | Evaluate supplied transaction data |
| POST | /intelligence | Generate security intelligence |
| GET | /transactions/history | Transaction history |
| GET | /approvals | View approval requests |
| POST | /approvals | Create approval request |
| POST | /approvals/{approval_id}/approve | Approve request |
| POST | /process | Process transaction request |


## Testing

Run the automated test suite:

```powershell
python -m unittest discover -s tests -v
```

The current development build has passed 198 automated tests.

## Security and Limitations

- NEAR investigation uses read-only blockchain queries.
- The application does not request private keys or seed phrases.
- The application does not sign or broadcast blockchain transactions.
- Security findings are evidence-based indicators, not proof of compromise.
- Transaction risk assessment uses deterministic rules, not a trained machine-learning model.
- Ethereum and BNB Chain evaluation uses supplied transaction information; live investigation is focused on NEAR.
- This is a hackathon prototype, not a production security audit.

## Project Vision

AgentGuard AI aims to make blockchain security intelligence easier to understand through transparent investigation, explainable findings, and practical recommendations.

## Contributing

Contributions, testing, feedback, and suggestions are welcome.

## License

A license has not yet been specified.

GitHub Repository: https://github.com/abdulazizusman8171-del/AgentGuardAI

## Personal Approval Center Accounts

The Approval Center now uses verified email accounts and individual Approval Keys:

- Register with an email address and a password of at least 12 characters.
- Verify the email using the one-time token delivered by SMTP.
- Log in to receive a secure, HttpOnly session cookie.
- Generate a personal Approval Key. The raw key is shown only once; only its SHA-256 hash is stored.
- Recover a forgotten key through a time-limited email token. Recovery replaces the old key and revokes active sessions.
- Approval records are scoped to the authenticated account. Existing records without an owner remain unassigned.
- Confirmation-required processing requires an authenticated account, the account's Approval Key, CSRF validation, and an approval ID belonging to that account.

### Account-related environment variables

Configure these in the deployment environment (never commit credentials):

- `AGENTGUARD_SMTP_HOST`
- `AGENTGUARD_SMTP_PORT` (587 for STARTTLS or 465 for implicit TLS)
- `AGENTGUARD_SMTP_USERNAME`
- `AGENTGUARD_SMTP_PASSWORD`
- `AGENTGUARD_SMTP_FROM`
- `AGENTGUARD_PUBLIC_URL` (for example, the HTTPS Render URL)
- `AGENTGUARD_COOKIE_SECURE=true` in production HTTPS; use `false` only for local HTTP development.

The login throttler is in-process. For multi-worker production deployments, also enforce rate limits at the hosting proxy or use a shared rate-limit store. Configure a persistent Render disk for the SQLite database if account/session data must survive service restarts.
