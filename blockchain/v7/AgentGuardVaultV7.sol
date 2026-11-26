// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AgentGuardVaultV7
/// @notice Individual non-custodial security vault for one wallet owner.
contract AgentGuardVaultV7 {
    address public immutable owner;

    uint256 public maxTransactionValue;
    uint256 public dailySpendingLimit;

    uint256 public currentDay;
    uint256 public dailySpent;
    uint256 public transactionCount;

    bool public paused;
    bool private executing;

    uint256 public constant RECOVERY_DELAY = 24 hours;

    uint256 public recoveryReadyAt;
    address public pendingRecoveryRecipient;

    mapping(address => bool) public authorizedExecutors;

    struct RecipientPolicy {
        bool approved;
        uint256 maxTransactionValue;
        uint256 dailySpendingLimit;
        uint256 currentDay;
        uint256 dailySpent;
    }

    mapping(address => RecipientPolicy) public recipientPolicies;

    event DepositReceived(address indexed sender, uint256 amount);
    event LimitsUpdated(uint256 transactionLimit, uint256 dailyLimit);
    event RecipientPolicyUpdated(address indexed recipient, bool approved);
    event ExecutorUpdated(address indexed executor, bool authorized);
    event PauseUpdated(bool paused);

    event TransactionExecuted(
        address indexed executor,
        address indexed recipient,
        uint256 amount,
        uint256 timestamp
    );

    event RecoveryStarted(
        address indexed recipient,
        uint256 readyAt
    );

    event RecoveryCancelled(address indexed owner);

    event RecoveryExecuted(
        address indexed recipient,
        uint256 amount
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Not vault owner");
        _;
    }

    modifier onlyOwnerOrExecutor() {
        require(
            msg.sender == owner || authorizedExecutors[msg.sender],
            "Not authorized"
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
        address vaultOwner,
        uint256 transactionLimit,
        uint256 dailyLimit
    ) {
        require(vaultOwner != address(0), "Zero owner");
        require(transactionLimit > 0, "Invalid transaction limit");
        require(dailyLimit >= transactionLimit, "Invalid daily limit");

        owner = vaultOwner;
        maxTransactionValue = transactionLimit;
        dailySpendingLimit = dailyLimit;
        currentDay = block.timestamp / 1 days;

        emit LimitsUpdated(transactionLimit, dailyLimit);
    }

    receive() external payable {
        emit DepositReceived(msg.sender, msg.value);
    }

    function setLimits(
        uint256 transactionLimit,
        uint256 dailyLimit
    ) external onlyOwner {
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
        require(recipient != address(0), "Zero recipient");
        require(recipient != address(this), "Self recipient");

        RecipientPolicy storage policy = recipientPolicies[recipient];

        if (approved) {
            require(transactionLimit > 0, "Invalid transaction limit");
            require(dailyLimit >= transactionLimit, "Invalid daily limit");

            policy.maxTransactionValue = transactionLimit;
            policy.dailySpendingLimit = dailyLimit;
        }

        policy.approved = approved;

        emit RecipientPolicyUpdated(recipient, approved);
    }

    function setExecutor(
        address executor,
        bool authorized
    ) external onlyOwner {
        require(executor != address(0), "Zero executor");
        require(executor != owner, "Owner is not an executor");

        authorizedExecutors[executor] = authorized;

        emit ExecutorUpdated(executor, authorized);
    }

    function setPaused(bool status) external onlyOwner {
        require(
            status || recoveryReadyAt == 0,
            "Pending recovery"
        );

        paused = status;

        emit PauseUpdated(status);
    }

    function getCurrentDaySpending() external view returns (uint256) {
        if (block.timestamp / 1 days != currentDay) {
            return 0;
        }

        return dailySpent;
    }

    function getRecipientDailySpending(
        address recipient
    ) external view returns (uint256) {
        RecipientPolicy storage policy = recipientPolicies[recipient];

        if (block.timestamp / 1 days != policy.currentDay) {
            return 0;
        }

        return policy.dailySpent;
    }

    function execute(
        address payable recipient,
        uint256 amount
    ) external onlyOwnerOrExecutor nonReentrant {
        require(!paused, "Vault paused");
        require(recoveryReadyAt == 0, "Recovery pending");
        require(recipient != address(0), "Zero recipient");
        require(recipient != address(this), "Self recipient");
        require(amount > 0, "Zero amount");

        RecipientPolicy storage policy = recipientPolicies[recipient];

        require(policy.approved, "Recipient not approved");
        require(amount <= maxTransactionValue, "Global transaction limit");
        require(
            amount <= policy.maxTransactionValue,
            "Recipient transaction limit"
        );

        uint256 today = block.timestamp / 1 days;

        if (today != currentDay) {
            currentDay = today;
            dailySpent = 0;
        }

        if (today != policy.currentDay) {
            policy.currentDay = today;
            policy.dailySpent = 0;
        }

        require(
            dailySpent + amount <= dailySpendingLimit,
            "Global daily limit"
        );

        require(
            policy.dailySpent + amount <= policy.dailySpendingLimit,
            "Recipient daily limit"
        );

        require(address(this).balance >= amount, "Insufficient balance");

        dailySpent += amount;
        policy.dailySpent += amount;
        transactionCount += 1;

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");

        emit TransactionExecuted(
            msg.sender,
            recipient,
            amount,
            block.timestamp
        );
    }

    /// @notice Owner starts a delayed emergency recovery.
    /// @dev Starting recovery pauses normal execution immediately.
    function initiateRecovery(
        address payable recoveryRecipient
    ) external onlyOwner {
        require(recoveryReadyAt == 0, "Recovery already pending");
        require(recoveryRecipient != address(0), "Zero recipient");
        require(recoveryRecipient != address(this), "Self recipient");

        pendingRecoveryRecipient = recoveryRecipient;
        recoveryReadyAt = block.timestamp + RECOVERY_DELAY;

        paused = true;

        emit PauseUpdated(true);
        emit RecoveryStarted(
            recoveryRecipient,
            recoveryReadyAt
        );
    }

    /// @notice Owner can cancel a pending emergency recovery.
    function cancelRecovery() external onlyOwner {
        require(recoveryReadyAt != 0, "No pending recovery");

        pendingRecoveryRecipient = address(0);
        recoveryReadyAt = 0;

        // The vault deliberately remains paused.
        emit RecoveryCancelled(owner);
    }

    /// @notice Owner executes recovery after the full 24-hour delay.
    /// @dev Recovery works while normal transactions are paused.
    function executeRecovery() external onlyOwner nonReentrant {
        require(recoveryReadyAt != 0, "No pending recovery");
        require(
            block.timestamp >= recoveryReadyAt,
            "Recovery delay active"
        );

        address payable recipient =
            payable(pendingRecoveryRecipient);

        uint256 amount = address(this).balance;

        pendingRecoveryRecipient = address(0);
        recoveryReadyAt = 0;

        if (amount > 0) {
            (bool success, ) = recipient.call{value: amount}("");
            require(success, "Recovery transfer failed");
        }

        emit RecoveryExecuted(recipient, amount);
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
