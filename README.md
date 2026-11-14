# AgentGuard AI Python SDK

A lightweight Python SDK for connecting AI agents to the AgentGuard AI transaction security gateway.

## Features

- Inspect proposed blockchain transactions.
- Receive ALLOW, REQUIRE_CONFIRMATION, and BLOCK decisions.
- Identify transactions requiring human approval.
- Retrieve structured security reports.
- No external runtime dependencies.
- Python 3.10+ support.

## Installation

The package is being prepared for its first public PyPI release.

After publication, install using:

    python -m pip install agentguard-ai

## Quick Start

    from agentguard import AgentGuardClient

    client = AgentGuardClient()

    transaction = {
        "transaction_id": "my-agent-001",
        "amount": 0.1,
        "network": "ethereum",
        "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
        "recipient_known": True,
        "new_contract": False,
        "unlimited_approval": False
    }

    result = client.inspect(transaction)

    print("Gateway:", result["gateway_status"])
    print("Security decision:", result["security_report"]["decision"])
    print("Risk score:", result["security_report"]["risk_score"])

## Gateway Decisions

| Decision | Gateway status | Recommended action |
|---|---|---|
| ALLOW | PERMITTED | Eligible for simulated execution |
| REQUIRE_CONFIRMATION | APPROVAL_REQUIRED | Wait for human approval |
| BLOCK | REJECTED | Stop the transaction |

## Error Handling

    from agentguard import AgentGuardClient, AgentGuardError

    client = AgentGuardClient()

    try:
        result = client.inspect(transaction)
        print(result["gateway_status"])
    except AgentGuardError as error:
        print("AgentGuard error:", error)
    except ValueError as error:
        print("Invalid input:", error)

## Security

AgentGuard AI SDK is inspection-only.

It does not:
- Sign transactions.
- Broadcast transactions.
- Execute transactions.
- Approve transactions.
- Request wallet private keys or seed phrases.

PERMITTED means eligible for simulated execution. It does not authorize signing or broadcasting a real transaction.

Transactions requiring confirmation must use the authenticated AgentGuard AI human-approval workflow.

## Development

Run SDK tests:

    python -m unittest tests.test_sdk -v

Run example:

    python -m agentguard.example

Build distribution packages:

    python -m build

## Package Information

- Distribution name: agentguard-ai
- Import name: agentguard
- Version: 0.1.0
- License: MIT
- Website: https://agentguardai.onrender.com/

## License

MIT License. See LICENSE.
## Python SDK

Install with `pip install agentguard-ai`.

Create a developer API key in your AgentGuard account and set it as AGENTGUARD_API_KEY. Initialize AgentGuardClient(api_key=your_api_key) to inspect transactions. The SDK is inspection-only: it does not sign, broadcast, approve, or execute transactions.
