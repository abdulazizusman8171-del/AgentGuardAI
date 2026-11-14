from agentguard import AgentGuardClient, AgentGuardError

client = AgentGuardClient()

transaction = {
    "transaction_id": "sdk-demo-001",
    "amount": 0.1,
    "network": "ethereum",
    "recipient_address": "0x1234567890abcdef1234567890abcdef12345678",
    "recipient_known": True,
    "new_contract": False,
    "unlimited_approval": False
}

try:
    result = client.inspect(transaction)

    print("\nAGENTGUARD AI SECURITY REPORT")
    print("-----------------------------")

    print("Gateway:", result["gateway_status"])
    print("Risk score:", result["security_report"]["risk_score"])
    print("Decision:", result["security_report"]["decision"])

    if client.is_permitted(result):
        print("Result: Eligible for simulated execution.")

    elif client.requires_approval(result):
        print("Result: Waiting for human approval.")

    elif client.is_rejected(result):
        print("Result: Transaction rejected.")

    print("Executed:", result["execution_performed"])
    print("Signed:", result["transaction_signed"])
    print("Broadcast:", result["transaction_broadcast"])

except AgentGuardError as error:
    print("AgentGuard connection error:", error)
