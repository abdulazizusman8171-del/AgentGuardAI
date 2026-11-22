// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ChainClock {
    function getTimestamp() external view returns (uint256) {
        return block.timestamp;
    }

    function getDay() external view returns (uint256) {
        return block.timestamp / 1 days;
    }
}