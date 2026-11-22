// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AgentGuardPolicyV3 {

    address public owner;
    address public pendingOwner;

    uint256 public maxTransactionValue;
    uint256 public dailySpendingLimit;

    bool public paused;
    bool private executing;

    mapping(address => bool) public approvedRecipients;
    mapping(address => bool) public authorizedExecutors;

    uint256 public currentDay;
    uint256 public dailySpent;

    uint256 public transactionCount;

    event OwnershipTransferStarted(
        address indexed currentOwner,
        address indexed pendingOwner
    );

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

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
        require(
            transactionLimit > 0,
            "Invalid transaction limit"
        );

        require(
            dailyLimit >= transactionLimit,
            "Daily limit too low"
        );

        owner = msg.sender;

        maxTransactionValue = transactionLimit;
        dailySpendingLimit = dailyLimit;

        authorizedExecutors[msg.sender] = true;

        currentDay = block.timestamp / 1 days;

        emit OwnershipTransferred(address(0), msg.sender);

        emit ExecutorUpdated(msg.sender, true);
    }

    receive() external payable {}

    // Ownership management

    function transferOwnership(
        address newOwner
    ) external onlyOwner {

        require(
            newOwner != address(0),
            "Invalid new owner"
        );

        require(
            newOwner != owner,
            "Already owner"
        );

        pendingOwner = newOwner;

        emit OwnershipTransferStarted(
            owner,
            newOwner
        );
    }

    function acceptOwnership() external {

        require(
            msg.sender == pendingOwner,
            "Not pending owner"
        );

        address previousOwner = owner;

        owner = msg.sender;
        pendingOwner = address(0);

        authorizedExecutors[previousOwner] = false;

        emit ExecutorUpdated(
            previousOwner,
            false
        );

        authorizedExecutors[owner] = true;

        emit ExecutorUpdated(
            owner,
            true
        );

        emit OwnershipTransferred(
            previousOwner,
            owner
        );
    }

    // Recipient management

    function setRecipient(
        address recipient,
        bool approved
    ) external onlyOwner {

        require(
            recipient != address(0),
            "Invalid recipient"
        );

        approvedRecipients[recipient] = approved;

        emit RecipientUpdated(
            recipient,
            approved
        );
    }

    // Executor management

    function setExecutor(
        address executor,
        bool authorized
    ) external onlyOwner {

        require(
            executor != address(0),
            "Invalid executor"
        );

        require(
            executor != owner || authorized,
            "Owner must remain executor"
        );

        authorizedExecutors[executor] = authorized;

        emit ExecutorUpdated(
            executor,
            authorized
        );
    }

    // Spending limits

    function setLimits(
        uint256 transactionLimit,
        uint256 dailyLimit
    ) external onlyOwner {

        require(
            transactionLimit > 0,
            "Invalid transaction limit"
        );

        require(
            dailyLimit >= transactionLimit,
            "Daily limit too low"
        );

        maxTransactionValue = transactionLimit;
        dailySpendingLimit = dailyLimit;

        emit LimitsUpdated(
            transactionLimit,
            dailyLimit
        );
    }

    // Emergency controls

    function setPaused(
        bool status
    ) external onlyOwner {

        paused = status;

        emit PauseUpdated(status);
    }

    // Controlled native ETH execution

    function execute(
        address payable recipient,
        uint256 amount,
        bytes calldata data
    )
        external
        onlyExecutor
        nonReentrant
    {

        require(
            !paused,
            "Security system paused"
        );

        require(
            recipient != address(0),
            "Invalid recipient"
        );

        require(
            recipient != address(this),
            "Self transfer prohibited"
        );

        require(
            approvedRecipients[recipient],
            "Recipient not approved"
        );

        require(
            amount > 0,
            "Amount must be positive"
        );

        require(
            amount <= maxTransactionValue,
            "Transaction limit exceeded"
        );

        require(
            data.length == 0,
            "Call data not supported"
        );

        uint256 today = block.timestamp / 1 days;

        if (today > currentDay) {

            currentDay = today;

            dailySpent = 0;
        }

        require(
            dailySpent <= dailySpendingLimit,
            "Daily limit already exceeded"
        );

        require(
            amount <= dailySpendingLimit - dailySpent,
            "Daily spending limit exceeded"
        );

        require(
            address(this).balance >= amount,
            "Insufficient wallet balance"
        );

        // Effects before external interaction

        dailySpent += amount;

        transactionCount++;

        uint256 transactionId = transactionCount;

        // Interaction

        (bool success, ) = recipient.call{
            value: amount
        }("");

        require(
            success,
            "Execution failed"
        );

        emit TransactionExecuted(
            transactionId,
            msg.sender,
            recipient,
            amount,
            block.timestamp
        );
    }
}