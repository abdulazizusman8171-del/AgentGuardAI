// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./AgentGuardVaultV7.sol";

/// @title AgentGuardFactoryV7
/// @notice Creates independent personal security vaults.
contract AgentGuardFactoryV7 {
    mapping(address => address) public vaultOf;

    event VaultCreated(
        address indexed owner,
        address indexed vault,
        uint256 timestamp
    );

    function createVault(
        uint256 transactionLimit,
        uint256 dailyLimit
    ) external returns (address) {
        require(vaultOf[msg.sender] == address(0), "Vault already exists");

        AgentGuardVaultV7 vault = new AgentGuardVaultV7(
            msg.sender,
            transactionLimit,
            dailyLimit
        );

        address vaultAddress = address(vault);

        vaultOf[msg.sender] = vaultAddress;

        emit VaultCreated(
            msg.sender,
            vaultAddress,
            block.timestamp
        );

        return vaultAddress;
    }

    function getVault(
        address wallet
    ) external view returns (address) {
        return vaultOf[wallet];
    }

    function hasVault(
        address wallet
    ) external view returns (bool) {
        return vaultOf[wallet] != address(0);
    }
}
