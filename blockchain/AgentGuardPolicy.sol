
 // SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AgentGuardPolicy {
    address public owner;

    uint256 public maxTransactionValue;
    bool public paused;

    mapping(address => bool) public approvedRecipients;

    event LimitUpdated(uint256 newLimit);
    event RecipientUpdated(address recipient, bool approved);
    event PauseUpdated(bool paused);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor(uint256 initialLimit) {
        owner = msg.sender;
        maxTransactionValue = initialLimit;
    }

    function setMaxTransactionValue(uint256 newLimit)
        external onlyOwner
    {
        require(newLimit > 0, "Limit must be positive");
        maxTransactionValue = newLimit;
        emit LimitUpdated(newLimit);
    }

    function setRecipient(address recipient, bool approved)
        external onlyOwner
    {
        require(recipient != address(0), "Invalid address");
        approvedRecipients[recipient] = approved;
        emit RecipientUpdated(recipient, approved);
    }

    function setPaused(bool status) external onlyOwner {
        paused = status;
        emit PauseUpdated(status);
    }

    function checkTransaction(address recipient, uint256 amount)
        external view returns (bool)
    {
        return (
            !paused &&
            approvedRecipients[recipient] &&
            amount <= maxTransactionValue
        );
    }
}
