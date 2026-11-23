// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AgentGuardPolicyV5 {
    address public owner;
    address public pendingOwner;

    uint256 public maxTransactionValue;
    uint256 public dailySpendingLimit;

    uint256 public currentDay;
    uint256 public dailySpent;
    uint256 public transactionCount;

    bool public paused;
    bool private executing;

    mapping(address => bool) public authorizedExecutors;

    struct RecipientPolicy {
        bool approved;
        uint256 maxTransactionValue;
        uint256 dailySpendingLimit;
        uint256 currentDay;
        uint256 dailySpent;
    }

    mapping(address => RecipientPolicy) public recipientPolicies;

    event OwnershipTransferStarted(address indexed currentOwner, address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event ExecutorUpdated(address indexed executor, bool authorized);
    event RecipientPolicyUpdated(address indexed recipient, bool approved, uint256 transactionLimit, uint256 dailyLimit);
    event LimitsUpdated(uint256 transactionLimit, uint256 dailyLimit);
    event PauseUpdated(bool paused);
    event DepositReceived(address indexed sender, uint256 amount);
    event TransactionExecuted(address indexed executor, address indexed recipient, uint256 amount, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyExecutor() {
        require(authorizedExecutors[msg.sender], "Not authorized");
        _;
    }

    modifier nonReentrant() {
        require(!executing, "Reentrant call");
        executing = true;
        _;
        executing = false;
    }

    constructor(uint256 transactionLimit, uint256 dailyLimit) {
        require(transactionLimit > 0, "Invalid transaction limit");
        require(dailyLimit >= transactionLimit, "Invalid daily limit");

        owner = msg.sender;
        maxTransactionValue = transactionLimit;
        dailySpendingLimit = dailyLimit;

        authorizedExecutors[msg.sender] = true;
        currentDay = block.timestamp / 1 days;

        emit OwnershipTransferred(address(0), msg.sender);
        emit ExecutorUpdated(msg.sender, true);
    }

    receive() external payable {
        emit DepositReceived(msg.sender, msg.value);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        require(newOwner != owner, "Already owner");

        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "Not pending owner");

        address previousOwner = owner;

        owner = msg.sender;
        pendingOwner = address(0);

        authorizedExecutors[previousOwner] = false;
        authorizedExecutors[msg.sender] = true;

        emit OwnershipTransferred(previousOwner, msg.sender);
        emit ExecutorUpdated(previousOwner, false);
        emit ExecutorUpdated(msg.sender, true);
    }

    function cancelOwnershipTransfer() external onlyOwner {
        pendingOwner = address(0);
    }

    function setExecutor(address executor, bool authorized) external onlyOwner {
        require(executor != address(0), "Zero address");
        require(executor != owner || authorized, "Owner must remain executor");

        authorizedExecutors[executor] = authorized;
        emit ExecutorUpdated(executor, authorized);
    }

    function setLimits(uint256 transactionLimit, uint256 dailyLimit) external onlyOwner {
        require(transactionLimit > 0, "Invalid transaction limit");
        require(dailyLimit >= transactionLimit, "Invalid daily limit");

        maxTransactionValue = transactionLimit;
        dailySpendingLimit = dailyLimit;

        emit LimitsUpdated(transactionLimit, dailyLimit);
    }

    function setRecipientPolicy(
        address recipient,
        bool approved,
        uint256 transactionLimit,
        uint256 dailyLimit
    ) external onlyOwner {
        require(recipient != address(0), "Zero address");
        require(recipient != address(this), "Self recipient");

        if (approved) {
            require(transactionLimit > 0, "Invalid transaction limit");
            require(dailyLimit >= transactionLimit, "Invalid daily limit");
        }

        RecipientPolicy storage policy = recipientPolicies[recipient];

        // Preserve spending history across approval and limit changes.
        uint256 today = block.timestamp / 1 days;

        if (today != policy.currentDay) {
            policy.currentDay = today;
            policy.dailySpent = 0;
        }

        policy.approved = approved;

        if (approved) {
            policy.maxTransactionValue = transactionLimit;
            policy.dailySpendingLimit = dailyLimit;
        }

        emit RecipientPolicyUpdated(
            recipient,
            approved,
            policy.maxTransactionValue,
            policy.dailySpendingLimit
        );
    }

    function setPaused(bool status) external onlyOwner {
        paused = status;
        emit PauseUpdated(status);
    }

    function getCurrentDaySpending() public view returns (uint256) {
        if (block.timestamp / 1 days != currentDay) {
            return 0;
        }

        return dailySpent;
    }

    function getRecipientDailySpending(address recipient) external view returns (uint256) {
        RecipientPolicy storage policy = recipientPolicies[recipient];

        if (block.timestamp / 1 days != policy.currentDay) {
            return 0;
        }

        return policy.dailySpent;
    }

    function execute(
        address payable recipient,
        uint256 amount,
        bytes calldata data
    ) external onlyExecutor nonReentrant {
        require(!paused, "Contract paused");
        require(recipient != address(0), "Invalid recipient");
        require(recipient != address(this), "Self recipient");
        require(amount > 0, "Amount must be positive");
        require(data.length == 0, "Call data not supported");

        RecipientPolicy storage policy = recipientPolicies[recipient];

        require(policy.approved, "Recipient not approved");
        require(policy.maxTransactionValue > 0, "Recipient limit not configured");
        require(amount <= maxTransactionValue, "Global transaction limit exceeded");
        require(amount <= policy.maxTransactionValue, "Recipient transaction limit exceeded");

        uint256 today = block.timestamp / 1 days;

        if (today != currentDay) {
            currentDay = today;
            dailySpent = 0;
        }

        if (today != policy.currentDay) {
            policy.currentDay = today;
            policy.dailySpent = 0;
        }

        require(dailySpent + amount <= dailySpendingLimit, "Global daily limit exceeded");
        require(policy.dailySpent + amount <= policy.dailySpendingLimit, "Recipient daily limit exceeded");
        require(address(this).balance >= amount, "Insufficient balance");

        dailySpent += amount;
        policy.dailySpent += amount;
        transactionCount += 1;

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");

        emit TransactionExecuted(msg.sender, recipient, amount, block.timestamp);
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
