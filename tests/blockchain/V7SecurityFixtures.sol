pragma solidity ^0.8.24;

interface IAgentGuardVaultV7 {
    function execute(
        address payable recipient,
        uint256 amount
    ) external;
}

contract V7ReentrantRecipient {
    IAgentGuardVaultV7 public vault;
    uint256 public reentryAmount;
    bool public reentryAttempted;
    bool public reentryBlocked;

    function configure(
        address vaultAddress,
        uint256 amount
    ) external {
        vault = IAgentGuardVaultV7(vaultAddress);
        reentryAmount = amount;
    }

    receive() external payable {
        reentryAttempted = true;

        try vault.execute(
            payable(address(this)),
            reentryAmount
        ) {
            reentryBlocked = false;
        } catch {
            reentryBlocked = true;
        }
    }
}

contract V7RejectingRecipient {
    receive() external payable {
        revert("Payment rejected intentionally");
    }
}
