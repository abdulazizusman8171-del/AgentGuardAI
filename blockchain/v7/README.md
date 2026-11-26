# AgentGuardAI V7 — Multi-User Architecture

## 1. Project Objective

Build a non-custodial, multi-user blockchain security system.

## 2. Core Principles

- Every user controls their own security vault.
- One personal vault per wallet address in V7.
- Each vault has an independent owner.
- Each user configures their own transaction limits.
- Each user controls approved recipients.
- Each user authorizes and revokes AI executors.
- Each user can pause their vault.
- Users retain the ability to recover their funds.
- AgentGuardAI administrators have no withdrawal privileges.
- The factory cannot withdraw or control vault funds.

## 3. Smart Contract Components

### AgentGuardFactoryV7
- Creates personal vaults.
- Records vault ownership.
- Prevents duplicate vault creation.
- Provides vault discovery.

### AgentGuardVaultV7
- Maintains individual security policies.
- Enforces transaction limits.
- Controls authorized executors.
- Provides emergency pause.
- Supports owner-controlled fund recovery.

## 4. Development Restrictions

- V4, V5 and V6 remain untouched.
- V7 development remains local initially.
- No deployment without explicit approval.
- No GitHub push without explicit approval.
- All tests use local development networks initially.

## 5. Security Requirement

No platform administrator or factory administrator may have hidden authority to withdraw funds from user vaults.

## 6. Current Status

Architecture planning started.
Smart contracts not yet implemented.
Deployment not performed.

## 7. Withdrawal Security Architecture

### Standard Withdrawal

1. Vault owner initiates withdrawal.
2. Owner wallet authorization is verified.
3. Recipient approval and transaction limits are checked.
4. Security risk assessment is performed.
5. Additional owner approval is required when configured.
6. Smart contract executes the withdrawal.
7. The transaction is recorded on-chain.

### Emergency Recovery

1. Vault owner initiates emergency recovery.
2. Owner authorization is verified.
3. A 24-hour security delay begins.
4. The owner can cancel a pending recovery.
5. After 24 hours, the owner can execute recovery.
6. Emergency recovery remains available while normal execution is paused.
7. Recovery events are permanently recorded on-chain.

### Emergency Recovery Restrictions

- AI executors cannot initiate or approve emergency recovery.
- AgentGuardAI administrators cannot approve or block recovery.
- Factory administrators have no recovery privileges.
- The recovery delay is enforced by the smart contract.
- Recovery must not depend on the AgentGuardAI backend being online.

### Important Verification Boundary

Wallet signatures prove control of an authorized wallet, not a person's real-world identity.

Any additional identity verification must use an explicitly defined verification mechanism. It must not create hidden platform custody or indefinite withdrawal restrictions.

### Approved Recovery Delay

24 hours.

