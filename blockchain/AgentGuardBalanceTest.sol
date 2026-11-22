// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AgentGuardBalanceTest {

    function attemptPayment(
    address payable recipient,
    uint256 amount
) external payable {
    require(
        address(this).balance >= amount,
        "Insufficient wallet balance"
    );

    (bool success, ) = recipient.call{value: amount}("");
    require(success, "Payment failed");
}
function fund() external payable {
}

    receive() external payable {}
}