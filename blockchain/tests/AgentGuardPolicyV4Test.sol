// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "remix_tests.sol";
import "remix_accounts.sol";

import "../AgentGuardPolicyV4.sol";

contract AgentGuardPolicyV4Test {

    AgentGuardPolicyV4 policy;

    address owner;
    address user1;
    address recipient;

    function beforeAll() public {
        owner = TestsAccounts.getAccount(0);
        user1 = TestsAccounts.getAccount(1);
        recipient = TestsAccounts.getAccount(2);

        policy = new AgentGuardPolicyV4(
            0.5 ether,
            2 ether
        );
    }

    // TEST 1: Owner is correctly assigned

    function testOwnerAssignment() public {
        Assert.equal(
            policy.owner(),
            address(this),
            "Contract deployer should be owner"
        );
    }

    // TEST 2: Initial transaction limit

    function testInitialTransactionLimit() public {
        Assert.equal(
            policy.maxTransactionValue(),
            0.5 ether,
            "Incorrect transaction limit"
        );
    }

    // TEST 3: Initial daily spending limit

    function testInitialDailyLimit() public {
        Assert.equal(
            policy.dailySpendingLimit(),
            2 ether,
            "Incorrect daily limit"
        );
    }

    // TEST 4: Owner is authorized executor

    function testOwnerIsExecutor() public {
        Assert.equal(
            policy.authorizedExecutors(address(this)),
            true,
            "Owner should be authorized executor"
        );
    }

    // TEST 5: Contract starts unpaused

    function testStartsUnpaused() public {
        Assert.equal(
            policy.paused(),
            false,
            "Contract should start unpaused"
        );
    }
}