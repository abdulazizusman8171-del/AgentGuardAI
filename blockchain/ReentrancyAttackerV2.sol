// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IAgentGuardPolicyV2 {
    function execute(
        address payable recipient,
        uint256 amount,
        bytes calldata data
    ) external;
}

contract ReentrancyAttackerV2 {
    IAgentGuardPolicyV2 public target;
    address payable public owner;

    uint256 public attackAmount;
    uint256 public attackAttempts;

    bool public attackEnabled;
    bool public nestedCallBlocked;

    constructor(address targetAddress) {
        target = IAgentGuardPolicyV2(targetAddress);
        owner = payable(msg.sender);
    }

    function startAttack(uint256 amount) external {
        require(msg.sender == owner, "Not attacker owner");

        attackAmount = amount;
        attackAttempts = 0;
        attackEnabled = true;
        nestedCallBlocked = false;

        target.execute(
            payable(address(this)),
            amount,
            ""
        );

        attackEnabled = false;
    }

    receive() external payable {
        if (attackEnabled && attackAttempts < 3) {
            attackAttempts++;

            try target.execute(
                payable(address(this)),
                attackAmount,
                ""
            ) {
                // Unexpected: nested execution succeeded.
            } catch {
                // Nested execution was rejected.
                nestedCallBlocked = true;
            }
        }
    }
}