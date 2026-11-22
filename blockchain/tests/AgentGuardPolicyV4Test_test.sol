// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "remix_tests.sol";
import "../AgentGuardPolicyV4.sol";

// Deploys the policy so the test contract is NOT its owner.
contract PolicyFactory {
    AgentGuardPolicyV4 public policy;

    function deploy() external returns (AgentGuardPolicyV4) {
        policy = new AgentGuardPolicyV4(0.5 ether, 2 ether);
        return policy;
    }

    function approveRecipient() external {
        policy.setRecipient(address(0x1234), true);
    }

    function fundPolicy() external payable {
        (bool success, ) = address(policy).call{value: msg.value}("");
        require(success, "Funding failed");
    }

    function attemptOverLimit() external returns (bool) {
        (bool success, ) = address(policy).call(
            abi.encodeWithSignature(
                "execute(address,uint256,bytes)",
                address(0x1234),
                0.6 ether,
                ""
            )
        );
        return success;
    }

    function attemptDailyLimit() external returns (bool) {
        (bool success, ) = address(policy).call(
            abi.encodeWithSignature(
                "execute(address,uint256,bytes)",
                address(0x1234),
                0.3 ether,
                ""
            )
        );
        return success;
    }
}

// Testing helper for cumulative daily spending.
contract DailyLimitTestHarness is AgentGuardPolicyV4 {

    constructor() AgentGuardPolicyV4(0.5 ether, 2 ether) {}

    function simulatePriorSpending() external {
        currentDay = block.timestamp / 1 days;
        dailySpent = 1.8 ether;
    }

    function attemptDailyLimit() external returns (bool) {
        try this.execute(
            payable(address(0x1234)),
            0.3 ether,
            ""
        ) {
            return true;
        } catch {
            return false;
        }
    }
}

// Main automated test suite.
contract AgentGuardPolicyV4TestSuite {

    function testUnauthorizedRecipientApproval() public {
        PolicyFactory factory = new PolicyFactory();
        AgentGuardPolicyV4 policy = factory.deploy();

        (bool success, ) = address(policy).call(
            abi.encodeWithSignature(
                "setRecipient(address,bool)",
                address(0x1234),
                true
            )
        );

        Assert.equal(success, false, "Unauthorized recipient approval succeeded");
        Assert.equal(
            policy.approvedRecipients(address(0x1234)),
            false,
            "Recipient should remain unapproved"
        );
    }

    function testUnauthorizedExecutorApproval() public {
        PolicyFactory factory = new PolicyFactory();
        AgentGuardPolicyV4 policy = factory.deploy();

        (bool success, ) = address(policy).call(
            abi.encodeWithSignature(
                "setExecutor(address,bool)",
                address(0x1234),
                true
            )
        );

        Assert.equal(success, false, "Unauthorized executor approval succeeded");
    }

    function testUnauthorizedLimitChange() public {
        PolicyFactory factory = new PolicyFactory();
        AgentGuardPolicyV4 policy = factory.deploy();

        (bool success, ) = address(policy).call(
            abi.encodeWithSignature(
                "setLimits(uint256,uint256)",
                1 ether,
                3 ether
            )
        );

        Assert.equal(success, false, "Unauthorized limit change succeeded");
        Assert.equal(
            policy.maxTransactionValue(),
            0.5 ether,
            "Transaction limit was unexpectedly changed"
        );
    }

    function testUnauthorizedPause() public {
        PolicyFactory factory = new PolicyFactory();
        AgentGuardPolicyV4 policy = factory.deploy();

        (bool success, ) = address(policy).call(
            abi.encodeWithSignature(
                "setPaused(bool)",
                true
            )
        );

        Assert.equal(success, false, "Unauthorized pause succeeded");
        Assert.equal(
            policy.paused(),
            false,
            "Contract should remain unpaused"
        );
    }

    function testUnauthorizedOwnershipTransfer() public {
        PolicyFactory factory = new PolicyFactory();
        AgentGuardPolicyV4 policy = factory.deploy();

        (bool success, ) = address(policy).call(
            abi.encodeWithSignature(
                "transferOwnership(address)",
                address(0x1234)
            )
        );

        Assert.equal(success, false, "Unauthorized ownership transfer succeeded");
        Assert.equal(
            policy.pendingOwner(),
            address(0),
            "Pending owner should remain empty"
        );
    }

    function testUnauthorizedExecution() public {
        PolicyFactory factory = new PolicyFactory();
        AgentGuardPolicyV4 policy = factory.deploy();

        (bool success, ) = address(policy).call(
            abi.encodeWithSignature(
                "execute(address,uint256,bytes)",
                address(0x1234),
                1,
                ""
            )
        );

        Assert.equal(success, false, "Unauthorized execution succeeded");
        Assert.equal(
            policy.transactionCount(),
            0,
            "Transaction count should remain zero"
        );
    }

    function testUnauthorizedRecipientRevocation() public {
        PolicyFactory factory = new PolicyFactory();
        AgentGuardPolicyV4 policy = factory.deploy();

        address recipient = address(0x1234);
        factory.approveRecipient();

        (bool success, ) = address(policy).call(
            abi.encodeWithSignature(
                "setRecipient(address,bool)",
                recipient,
                false
            )
        );

        Assert.equal(success, false, "Unauthorized revocation succeeded");
        Assert.equal(
            policy.approvedRecipients(recipient),
            true,
            "Recipient approval was unexpectedly removed"
        );
    }

    function testTransactionLimitEnforcement() public {
        PolicyFactory factory = new PolicyFactory();
        AgentGuardPolicyV4 policy = factory.deploy();

        factory.approveRecipient();

        bool success = factory.attemptOverLimit();

        Assert.equal(
            success,
            false,
            "Transaction above maximum limit succeeded"
        );

        Assert.equal(
            policy.transactionCount(),
            0,
            "Transaction count should remain zero"
        );
    }

    // TEST 9: Cumulative daily spending limit.
    function testDailySpendingLimitEnforcement() public {
        DailyLimitTestHarness harness = new DailyLimitTestHarness();

        // The test suite owns the harness.
        harness.setRecipient(address(0x1234), true);
        harness.setExecutor(address(harness), true);

        // Simulate 1.8 ETH already spent today.
        harness.simulatePriorSpending();

        // Attempt another 0.3 ETH.
        bool success = harness.attemptDailyLimit();

        Assert.equal(
            success,
            false,
            "Daily spending limit was bypassed"
        );

        Assert.equal(
            harness.dailySpent(),
            1.8 ether,
            "Daily spending changed after rejected transaction"
        );

        Assert.equal(
            harness.transactionCount(),
            0,
            "Rejected transaction increased transaction count"
        );
    }

    receive() external payable {}
}