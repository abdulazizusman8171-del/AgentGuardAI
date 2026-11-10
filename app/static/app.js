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