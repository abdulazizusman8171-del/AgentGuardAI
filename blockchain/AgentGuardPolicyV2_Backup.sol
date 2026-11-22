// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AgentGuardPolicyV2 {

    address public owner;

    uint256 public maxTransactionValue;
    uint256 public dailySpendingLimit;

    bool public paused;
    bool private executing;

    mapping(address => bool) public approvedRecipients;
    mapping(address => bool) public authorizedExecutors;

    uint256 public currentDay;
    uint256 public dailySpent;

    uint256 public transactionCount;

    event RecipientUpdated(
        address indexed recipient,
        bool approved
    );

    event ExecutorUpdated(
        address indexed executor,
        bool authorized
    );

    event LimitsUpdated(
        uint256 transactionLimit,
        uint256 dailyLimit
    );

    event PauseUpdated(bool paused);

    event TransactionExecuted(
        uint256 indexed transactionId,
        address indexed executor,
        address indexed recipient,
        uint256 amount,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyExecutor() {
        require(
            authorizedExecutors[msg.sender],
            "Not authorized executor"
        );
        _;
    }

    modifier nonReentrant() {
        require(!executing, "Reentrant call");
        executing = true;
        _;
        executing = false;
    }

    constructor(
        uint256 transactionLimit,
        uint256 dailyLimit
    ) {
        require(transactionLimit > 0, "Invalid transaction limit");
        require(dailyLimit >= transactionLimit, "Daily limit too low");

        owner = msg.sender;

        maxTransactionValue = transactionLimit;
        dailySpendingLimit = dailyLimit;

        authorizedExecutors[msg.sender] = true;

        currentDay = block.timestamp / 1 days;
    }

    receive() external payable {}

    function setRecipient(
        address recipient,
        bool approved
    ) external onlyOwner {
        require(recipient != address(0), "Invalid recipient");

        approvedRecipients[recipient] = approved;

        emit RecipientUpdated(recipient, approved);
    }

    function setExecutor(
        address executor,
        bool authorized
    ) external onlyOwner {
        require(executor != address(0), "Invalid executor");

        authorizedExecutors[executor] = authorized;

        emit ExecutorUpdated(executor, authorized);
    }

    function setLimits(
        uint256 transactionLimit,
        uint256 dailyLimit
    ) external onlyOwner {
        require(transactionLimit > 0, "Invalid transaction limit");
        require(dailyLimit >= transactionLimit, "Daily limit too low");

        maxTransactionValue = transactionLimit;
        dailySpendingLimit = dailyLimit;

        emit LimitsUpdated(transactionLimit, dailyLimit);
    }

    function setPaused(bool status) external onlyOwner {
        paused = status;

        emit PauseUpdated(status);
    }

    function execute(
        address payable recipient,
        uint256 amount,
        bytes calldata data
    ) external onlyExecutor nonReentrant {

        require(!paused, "Security system paused");
        require(recipient != address(0), "Invalid recipient");
        require(approvedRecipients[recipient], "Recipient not approved");
        require(amount > 0, "Amount must be positive");
        require(amount <= maxTransactionValue, "Transaction limit exceeded");

        uint256 today = block.timestamp / 1 days;

        if (today > currentDay) {
            currentDay = today;
            dailySpent = 0;
        }

        require(
            dailySpent + amount <= dailySpendingLimit,
            "Daily spending limit exceeded"
        );

        require(
            address(this).balance >= amount,
            "Insufficient wallet balance"
        );

        dailySpent += amount;

        transactionCount++;

        uint256 transactionId = transactionCount;

        (bool success, ) = recipient.call{value: amount}(data);

        require(success, "Execution failed");

        emit TransactionExecuted(
            transactionId,
            msg.sender,
            recipient,
            amount,
            block.timestamp
        );
    }
}