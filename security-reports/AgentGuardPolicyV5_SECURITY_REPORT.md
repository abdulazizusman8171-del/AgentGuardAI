# AgentGuardPolicyV5 — Security Review Report

**Project:** AgentGuardAI
**Contract:** AgentGuardPolicyV5
**Review date:** 23 November 2026
**Review status:** Experimental — further review required
**Network used for testing:** Local in-memory Ganache
**Solidity compiler:** 0.8.24
**Static analysis:** Slither 0.11.6

---

## 1. Executive Summary

AgentGuardPolicyV5 is an experimental upgrade to AgentGuardPolicyV4.

Its main improvement is recipient-specific spending protection. Instead of relying exclusively on global transaction and daily spending limits, V5 also applies individual limits to each owner-approved recipient.

V5 passed the locally executed recipient-spending, core-security, authorization-epoch, and additional lifecycle test suites.

An updated Slither scan analyzed the contract using 102 detectors and reported 5 results across 2 categories:
- Block timestamp usage.
- Low-level calls.

An earlier scan reported an arbitrary-send-eth finding, but this finding was not reported in the latest scan. Its disappearance does not independently establish that the underlying executor-compromise risk has been eliminated.

These findings and residual risks require continued review. Passing the current tests does not establish that the contract is free of vulnerabilities.

**V5 has not received an independent professional security audit.**

---

## 2. Main Security Improvements

V5 retains important security controls from V4 and introduces recipient-specific spending policies.

### Global protections

- Owner-controlled executor authorization.
- Authorization epochs that automatically invalidate previously authorized executors after ownership transfer.
- Global transaction spending limit.
- Global daily spending limit.
- Emergency pause functionality.
- Two-step ownership transfer.
- Reentrancy protection.
- Rejection of unapproved recipients.
- Rejection of zero-value transfers.
- Rejection of unsupported transaction data.
- Balance checks before execution.
- Accounting rollback when transfers fail.

### Recipient-specific protections

Each recipient has an individual policy containing:

- Approval status.
- Maximum transaction value.
- Daily spending limit.
- Current accounting day.
- Daily amount already spent.

The contract also preserves spending history when a recipient's policy is changed or revoked and subsequently re-approved within the same accounting day.

This prevents an executor or policy change from resetting the recipient's spending allowance.

---

## 3. Local Recipient-Spending Test Results

**Result: 9/9 passed**

| Test | Result |
|---|---|
| Unconfigured recipient rejected | PASS |
| Recipient transaction limit enforced | PASS |
| Recipient spending recorded correctly | PASS |
| Lowering recipient limit preserves previous spending | PASS |
| Re-approval cannot reset recipient daily spending | PASS |
| Spending across recipients counted globally | PASS |
| Global daily limit enforced across recipients | PASS |
| Recipient and global daily views reset on new UTC day | PASS |
| New-day spending works correctly | PASS |

---

## 4. Local Core Security Test Results

**Result: 10 PASS outputs**

| Security check | Result |
|---|---|
| Unauthorized executor cannot execute | PASS |
| Executor cannot create or modify recipient policy | PASS |
| Executor cannot change global spending limits | PASS |
| Unnominated account cannot accept ownership | PASS |
| Ownership transfer requires acceptance | PASS |
| Previous owner loses executor authorization | PASS |
| Paused V5 rejects executor transactions | PASS |
| V5 reentrancy attack blocked and accounting preserved | PASS |
| Rejecting recipient causes transfer failure | PASS |
| Failed transfer rolls back global and recipient accounting | PASS |

These tests were executed on a local, in-memory Ganache blockchain using temporary test accounts.

They did not use real funds or perform BNB Testnet transactions.

---

## 5. Slither Static Analysis

**Tool:** Slither 0.11.6
**Detectors executed:** 102
**Reported results:** 5
**Categories:** 2
**Contracts analysed:** 1
**Latest scan:** 23 November 2026

### Finding A — timestamp

**Impact:** Low
**Confidence:** Medium

Slither identifies uses of `block.timestamp / 86400` in daily spending accounting.

The timestamp determines the UTC-day accounting period for global and recipient spending.

**Assessment:** A documented timing assumption. Block timestamps are not perfectly controllable, so the daily boundary should not be treated as a precise real-world clock.

### Finding B — low-level-calls

**Impact:** Informational
**Confidence:** High

Location:

`AgentGuardPolicyV5.execute()`

Slither identifies the external transfer:

`recipient.call{value: amount}("")`

The contract checks the returned success value and reverts if the transfer fails.

**Assessment:** The transfer failure check is present. External-call behaviour and reentrancy protections still require continued review.

### Previous finding — arbitrary-send-eth

An earlier Slither scan reported this finding with High impact and Medium confidence. It was not reported in the latest scan.

The underlying risk remains relevant: an authorized executor can select among approved recipients, subject to recipient-specific and global spending limits.

**Assessment:** The disappearance of this detector finding does not prove that executor-compromise risk has been eliminated. Manual review remains necessary.

---

## 6. Authorization Epoch Upgrade

V5 now uses an authorization epoch to invalidate previously authorized executors when ownership transfers.

The implementation:
- Initializes the authorization epoch to 1.
- Increments the epoch after a successful ownership transfer.
- Authorizes the new owner in the new epoch.
- Makes executors authorized under previous epochs fail the current authorization check.
- Allows the new owner to explicitly authorize a previous executor again if required.

This avoids iterating through every previously authorized executor during ownership transfer.

**Local authorization epoch tests: 14 checks passed.**

**Additional lifecycle tests: 9 checks passed.**

These included:
- Previous owner authorization revoked.
- Previous executors automatically revoked.
- Previous executors cannot execute after ownership transfer.
- New owner can explicitly reauthorize a previous executor.
- New owner can revoke that executor again.
- Ownership nomination and cancellation lifecycle checks.
- Recipient spending behaviour across UTC-day rollover.

These are local test results, not an independent security audit.

---

## 7. Known Limitations and Residual Risks

1. An authorized executor can select between owner-approved recipients.
2. Recipient-specific limits reduce exposure but do not eliminate executor-compromise risk.
3. A malicious or compromised approved recipient remains a risk.
4. Daily spending boundaries depend on block timestamps.
5. Low-level external calls require careful handling.
6. The earlier arbitrary-send-eth finding is absent from the latest Slither scan, but the underlying trust and executor-compromise risks still require manual review.
7. Current tests are self-authored and do not replace independent security testing.
8. Slither findings do not, by themselves, establish exploitability or prove the absence of other vulnerabilities.

---
## 8. Recommended Next Steps

Before V5 is considered production-ready:

1. Complete a manual review of the entire contract.
2. Investigate the arbitrary-send-eth finding.
3. Review all external-call and reentrancy behaviour.
4. Expand fuzz and invariant testing.
5. Test ownership and executor lifecycle edge cases.
6. Review gas usage and operational limitations.
7. Obtain an independent smart-contract security audit.
8. Complete a separate BNB Testnet integration plan.
9. Verify deployment bytecode and contract configuration before any deployment.

---

## 9. Version and Deployment Status

### V4

V4 remains the existing BNB Smart Chain Testnet deployment.

Contract address:

`0x2FcD3078f78263578aA9B989A9D029b4E7289a5a`

Network: BNB Smart Chain Testnet
Chain ID: 97

### V5

V5 is a separate experimental contract.

Current status:
- Compiled successfully with Solidity 0.8.24.
- Recipient-specific spending tests passed.
- Core security tests passed.
- Slither analysis completed.
- Independent audit not completed.
- Not approved for production deployment.

**V4 and V5 must remain separate until the V5 review and deployment decision are complete.**

---

## 10. Final Assessment

AgentGuardPolicyV5 introduces a meaningful improvement over V4 by adding recipient-specific spending controls while retaining global spending limits and administrative protections.

The local test results are encouraging.

However, the arbitrary-send-eth finding and the remaining external-call and timestamp considerations must be reviewed before V5 progresses to deployment.

**Current decision: Continue V5 security review. Do not replace V4 or deploy V5 to a live network at this stage.**

---

*This report documents the development team's current testing and static-analysis results. It is not a professional audit certificate or a guarantee of contract security.*