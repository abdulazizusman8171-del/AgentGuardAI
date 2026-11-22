// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract RejectingRecipient {
    receive() external payable {
        revert("Recipient rejects ETH");
    }
}