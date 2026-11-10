const form = document.getElementById("transaction-form");
const button = document.getElementById("evaluate-button");
const loading = document.getElementById("loading");
const results = document.getElementById("results");
const errorMessage = document.getElementById("error-message");

form.addEventListener("submit", async function (event) {
    event.preventDefault();

    errorMessage.classList.add("hidden");
    results.classList.add("hidden");
    loading.classList.remove("hidden");

    button.disabled = true;
    button.textContent = "Evaluating...";

    const transaction = {
        transaction_id: document.getElementById("transaction_id").value.trim(),
        amount: Number(document.getElementById("amount").value),
        network: document.getElementById("network").value,
        recipient_address: document.getElementById("recipient_address").value.trim(),
        recipient_known: document.getElementById("recipient_known").checked,
        new_contract: document.getElementById("new_contract").checked,
        unlimited_approval: document.getElementById("unlimited_approval").checked
    };

    try {
        const response = await fetch("/intelligence", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(transaction)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Transaction evaluation failed.");
        }

        displayResults(data);

    } catch (error) {
        errorMessage.textContent = error.message;
        errorMessage.classList.remove("hidden");

    } finally {
        loading.classList.add("hidden");
        button.disabled = false;
        button.textContent = "Evaluate Transaction";
    }
});


function displayResults(data) {
    const report = data.security_report;
    const intelligence = data.intelligence;

    document.getElementById("risk-score").textContent =
        report.risk_score + "/100";

    document.getElementById("decision").textContent =
        report.decision;

    document.getElementById("finding-count").textContent =
        intelligence.findings.length;

    document.getElementById("summary").textContent =
        intelligence.summary;

    const intelligenceContainer =
        document.getElementById("intelligence");

    intelligenceContainer.replaceChildren();

    const heading = document.createElement("h3");
    heading.textContent = "Security Findings";
    intelligenceContainer.appendChild(heading);

    if (intelligence.findings.length === 0) {
        const message = document.createElement("p");
        message.textContent = "No security findings detected.";
        intelligenceContainer.appendChild(message);
    }

    intelligence.findings.forEach(function (finding) {
        const card = document.createElement("div");
        card.className = "finding";

        const title = document.createElement("h4");
        title.textContent = finding.reason || finding.title || "Security finding";

        const severity = document.createElement("p");
        severity.textContent = "Severity: " + finding.severity;

        const explanation = document.createElement("p");
        explanation.textContent = finding.explanation;

        const recommendation = document.createElement("p");
        recommendation.textContent =
            "Recommendation: " + finding.recommendation;

        card.append(title, severity, explanation, recommendation);
        intelligenceContainer.appendChild(card);
    });

    results.classList.remove("hidden");
    results.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}
// ==========================================
// TRANSACTION HISTORY
// ==========================================

const historyList = document.getElementById("historyList");
const refreshHistoryButton = document.getElementById("refreshHistory");

async function loadTransactionHistory() {
    historyList.textContent = "Loading transaction history...";

    try {
        const response = await fetch("/transactions/history?limit=50");
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Could not load transaction history.");
        }

        historyList.replaceChildren();

        if (!data.transactions || data.transactions.length === 0) {
            historyList.textContent = "No executed transactions found yet.";
            return;
        }

        data.transactions.forEach(function (transaction) {
            const item = document.createElement("div");
            item.className = "record-item";

            const details = document.createElement("div");
            details.className = "record-details";

            const title = document.createElement("h3");
            title.textContent = transaction.transaction_id;

            const date = document.createElement("p");
            date.textContent = "Processed: " +
                (transaction.processed_at || "Date unavailable");

            const badge = document.createElement("span");
            badge.className = "status-badge consumed";
            badge.textContent = "EXECUTED";

            details.append(title, date);
            item.append(details, badge);
            historyList.appendChild(item);
        });

    } catch (error) {
        historyList.textContent = error.message;
    }
}


// ==========================================
// APPROVAL CENTER
// ==========================================

const approvalList = document.getElementById("approvalList");
const approvalStatus = document.getElementById("approvalStatus");
const refreshApprovalsButton = document.getElementById("refreshApprovals");

// Format approval timestamps
function formatTimestamp(value) {
    if (!value) return "Date unavailable";

    const numeric = Number(value);

    const date = Number.isFinite(numeric)
        ? new Date(numeric < 1000000000000 ? numeric * 1000 : numeric)
        : new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleString();
}
async function loadApprovals() {
    approvalList.textContent = "Loading approvals...";

    try {
        const status = approvalStatus.value;

        const query = new URLSearchParams({
            limit: "50"
        });

        if (status) {
            query.set("status", status);
        }

        const response = await fetch("/approvals?" + query.toString());
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Could not load approvals.");
        }

        approvalList.replaceChildren();

        if (!data.approvals || data.approvals.length === 0) {
            approvalList.textContent = "No approvals found.";
            return;
        }

        data.approvals.forEach(function (approval) {
            const item = document.createElement("div");
            item.className = "record-item";

            const details = document.createElement("div");
            details.className = "record-details";

            const title = document.createElement("h3");
            title.textContent = "Transaction: " + approval.transaction_id;

            const id = document.createElement("p");
            id.textContent = "Approval ID: " + approval.approval_id;

            const created = document.createElement("p");
            created.textContent = "Created: " + formatTimestamp(approval.created_at);

            const badge = document.createElement("span");
            const normalizedStatus = String(approval.status || "UNKNOWN").toLowerCase();

            badge.className = "status-badge " + normalizedStatus;
            badge.textContent = normalizedStatus.toUpperCase();

            details.append(title, id, created);
            item.append(details, badge);

            approvalList.appendChild(item);
        });

    } catch (error) {
        approvalList.textContent = error.message;
    }
}


// ==========================================
// DASHBOARD EVENT LISTENERS
// ==========================================

refreshHistoryButton.addEventListener("click", loadTransactionHistory);

refreshApprovalsButton.addEventListener("click", loadApprovals);

approvalStatus.addEventListener("change", loadApprovals);


// Load dashboard records when the page opens.

loadTransactionHistory();
loadApprovals();
