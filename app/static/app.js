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
    const findings = intelligence.findings || [];

    document.getElementById("risk-score").textContent =
        report.risk_score + "/100";

    document.getElementById("decision").textContent =
        report.decision;

    document.getElementById("finding-count").textContent =
        findings.length;

    document.getElementById("summary").textContent =
        intelligence.summary;

    const intelligenceContainer =
        document.getElementById("intelligence-results");

    intelligenceContainer.replaceChildren();

    const severityCounts = intelligence.severity_counts || {
        CRITICAL: findings.filter(f => f.severity === "CRITICAL").length,
        HIGH: findings.filter(f => f.severity === "HIGH").length,
        MEDIUM: findings.filter(f => f.severity === "MEDIUM").length
    };

    const severityGrid = document.createElement("div");
    severityGrid.className = "result-grid severity-grid";

    ["CRITICAL", "HIGH", "MEDIUM"].forEach(function (level) {
        const card = document.createElement("div");
        card.className = "result-card severity-card severity-" + level.toLowerCase();

        const label = document.createElement("p");
        label.textContent = level + " Findings";

        const count = document.createElement("h2");
        count.textContent = severityCounts[level] ?? 0;

        card.append(label, count);
        severityGrid.appendChild(card);
    });

    intelligenceContainer.appendChild(severityGrid);

    const heading = document.createElement("h3");
    heading.textContent = "Security Findings";
    intelligenceContainer.appendChild(heading);

    if (findings.length === 0) {
        const message = document.createElement("p");
        message.textContent = "No security findings detected.";
        intelligenceContainer.appendChild(message);
    }

    findings.forEach(function (finding) {
        const card = document.createElement("div");
        card.className = "finding";

        const title = document.createElement("h4");
        title.textContent =
            finding.reason || finding.title || "Security finding";

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
const approvalApiKeyInput = document.getElementById("approvalApiKey");
const unlockApprovalsButton = document.getElementById("unlockApprovals");
const approvalAuthStatus = document.getElementById("approvalAuthStatus");

// Keep the authorization key in memory only.
let approvalApiKey = "";

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
    if (!approvalApiKey) {
        approvalList.textContent = "Unlock the Approval Center to view approvals.";
        return;
    }

    approvalList.textContent = "Loading approvals...";

    try {
        const query = new URLSearchParams({ limit: "50" });

        if (approvalStatus.value) {
            query.set("status", approvalStatus.value);
        }

        const response = await fetch("/approvals?" + query.toString(), {
            headers: {
                "X-Approval-Key": approvalApiKey
            }
        });

        const data = await response.json();

        if (response.status === 401) {
            approvalApiKey = "";
            approvalList.textContent = "Authorization failed. Unlock again.";
            approvalAuthStatus.textContent = "Your authorization key is invalid.";
            return;
        }

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

async function unlockApprovalCenter() {
    const candidateKey = approvalApiKeyInput.value.trim();

    if (!candidateKey) {
        approvalAuthStatus.textContent = "Please enter your authorization key.";
        return;
    }

    unlockApprovalsButton.disabled = true;
    approvalAuthStatus.textContent = "Checking authorization...";

    try {
        const response = await fetch("/approvals?limit=1", {
            headers: {
                "X-Approval-Key": candidateKey
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Authorization failed.");
        }

        approvalApiKey = candidateKey;
        approvalAuthStatus.textContent = "Authorization successful. Approval Center unlocked.";

        await loadApprovals();

    } catch (error) {
        approvalApiKey = "";
        approvalAuthStatus.textContent = error.message;
        approvalList.textContent = "Approval Center is locked.";

    } finally {
        approvalApiKeyInput.value = "";
        unlockApprovalsButton.disabled = false;
    }
}
// DASHBOARD EVENT LISTENERS
// ==========================================

refreshHistoryButton.addEventListener("click", loadTransactionHistory);

refreshApprovalsButton.addEventListener("click", loadApprovals);

approvalStatus.addEventListener("change", loadApprovals);

unlockApprovalsButton.addEventListener("click", unlockApprovalCenter);

approvalApiKeyInput.addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
        unlockApprovalCenter();
    }
});


// Load dashboard records when the page opens.

loadTransactionHistory();

// ==========================================
// AGENTGUARD CAROUSEL AND NETWORK THEME CONTROLS
// ==========================================

const networkSelector = document.getElementById("network");
const activityTrack = document.getElementById("activityTrack");
const activityPrev = document.getElementById("activityPrev");
const activityNext = document.getElementById("activityNext");
// AGENTGUARD CONTINUOUS INFINITE CAROUSEL
const carouselViewport = activityTrack?.parentElement;

const originalCards = activityTrack
    ? Array.from(activityTrack.children)
    : [];

const originalCardCount = originalCards.length;
const carouselDuration = 36000;

if (activityTrack && carouselViewport && originalCardCount > 0) {
    originalCards.forEach(card => {
        const clone = card.cloneNode(true);
        clone.setAttribute("aria-hidden", "true");
        clone.querySelectorAll("[id]").forEach(el => el.removeAttribute("id"));
        activityTrack.appendChild(clone);
    });

    activityTrack.style.animation =
        `agentGuardContinuousSlide ${carouselDuration}ms linear infinite`;
}

function moveCarousel(direction) {
    if (!activityTrack || originalCardCount === 0) return;

    const animation = activityTrack.getAnimations()[0];

    if (animation) {
        const stepDuration = carouselDuration / originalCardCount;
        animation.currentTime =
            (Number(animation.currentTime) || 0) + direction * stepDuration;
    }
}

if (carouselViewport && activityTrack) {
    carouselViewport.addEventListener("mouseenter", () => {
        activityTrack.style.animationPlayState = "paused";
    });

    carouselViewport.addEventListener("mouseleave", () => {
        activityTrack.style.animationPlayState = "running";
    });

    carouselViewport.addEventListener("focusin", () => {
        activityTrack.style.animationPlayState = "paused";
    });

    carouselViewport.addEventListener("focusout", () => {
        activityTrack.style.animationPlayState = "running";
    });
}

// Carousel navigation buttons
if (activityPrev) {
    activityPrev.addEventListener("click", () => moveCarousel(-1));
}

if (activityNext) {
    activityNext.addEventListener("click", () => moveCarousel(1));
}





// AGENTGUARD RESPONSIVE NAVIGATION
const menuToggle = document.getElementById("mobileMenuToggle");
const sidebarBackdrop = document.getElementById("sidebarBackdrop");
const sidebarLinks = document.querySelectorAll("#mainSidebar nav a");

function closeMobileMenu() {
    document.body.classList.remove("nav-open");

    if (menuToggle) {
        menuToggle.setAttribute("aria-expanded", "false");
        menuToggle.setAttribute("aria-label", "Open navigation menu");
    }
}

if (menuToggle) {
    menuToggle.addEventListener("click", () => {
        const isOpen = document.body.classList.toggle("nav-open");

        menuToggle.setAttribute("aria-expanded", String(isOpen));
        menuToggle.setAttribute(
            "aria-label",
            isOpen ? "Close navigation menu" : "Open navigation menu"
        );
    });
}

if (sidebarBackdrop) {
    sidebarBackdrop.addEventListener("click", closeMobileMenu);
}

sidebarLinks.forEach(link => {
    link.addEventListener("click", closeMobileMenu);
});

document.addEventListener("keydown", event => {
    if (event.key === "Escape") {
        closeMobileMenu();
    }
});

window.addEventListener("resize", () => {
    if (window.innerWidth > 900) {
        closeMobileMenu();
    }
});

// AGENTGUARD NETWORK THEME SWITCHER
function updateNetworkTheme() {
    if (!networkSelector) return;

    document.body.dataset.network = networkSelector.value;
}

// Apply the selected network theme on page load
updateNetworkTheme();

// Update the theme whenever the network changes
if (networkSelector) {
    networkSelector.addEventListener("change", updateNetworkTheme);
}

// AGENTGUARD NEAR MARKET AND VOLUME MONITOR
async function loadNearMarket() {
    const priceElement = document.getElementById("near-price");
    const changeElement = document.getElementById("near-price-change");
    const updatedElement = document.getElementById("near-price-updated");
    const volumeElement = document.getElementById("near-volume");
    const volumeChangeElement = document.getElementById("near-volume-change");
    const volumeUpdatedElement = document.getElementById("near-volume-updated");

    if (!priceElement || !changeElement || !updatedElement) return;

    try {
        const response = await fetch("/near/market");
        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(result.detail || "Market data unavailable");
        }

        const market = result.data;
        const price = Number(market.price);
        const change = Number(market.price_change_24h_percent);
        const volume = Number(market.volume_24h);

        if (
            !Number.isFinite(price) ||
            !Number.isFinite(change) ||
            !Number.isFinite(volume) ||
            volume < 0
        ) {
            throw new Error("Invalid market data received");
        }

        priceElement.textContent = "$" + price.toLocaleString(
            "en-US",
            { minimumFractionDigits: 2, maximumFractionDigits: 6 }
        );

        const direction = change >= 0 ? "+" : "";

        changeElement.textContent =
            "24h change: " + direction + change.toFixed(2) + "%";

        changeElement.dataset.direction =
            change >= 0 ? "up" : "down";

        if (market.last_updated) {
            const updated = new Date(market.last_updated);

            updatedElement.textContent = Number.isNaN(updated.getTime())
                ? "Source: CoinGecko"
                : "Updated: " + updated.toLocaleTimeString();
        } else {
            updatedElement.textContent = "Source: CoinGecko";
        }

        if (volumeElement && volumeChangeElement && volumeUpdatedElement) {
            volumeElement.textContent = "$" + volume.toLocaleString(
                "en-US",
                { maximumFractionDigits: 0 }
            );

            const storageKey = "agentguard_near_volume_previous";
            const currentTime = Date.now();
            let previous = null;

            try {
                previous = JSON.parse(localStorage.getItem(storageKey));
            } catch {
                previous = null;
            }

            if (
                previous &&
                Number.isFinite(Number(previous.volume)) &&
                Number(previous.volume) > 0 &&
                Number.isFinite(Number(previous.timestamp)) &&
                currentTime > Number(previous.timestamp)
            ) {
                const previousVolume = Number(previous.volume);
                const percentageChange =
                    ((volume - previousVolume) / previousVolume) * 100;

                const sign = percentageChange >= 0 ? "+" : "";

                volumeChangeElement.textContent =
                    "Since previous check: " +
                    sign + percentageChange.toFixed(2) + "%";

                volumeChangeElement.dataset.direction =
                    percentageChange >= 0 ? "up" : "down";

                const minutes = Math.max(
                    1,
                    Math.round(
                        (currentTime - Number(previous.timestamp)) / 60000
                    )
                );

                volumeUpdatedElement.textContent =
                    "Compared with " + minutes + " minute(s) ago";
            } else {
                volumeChangeElement.textContent =
                    "Baseline saved; comparison starts next check";

                volumeUpdatedElement.textContent =
                    "Current rolling 24h volume | CoinGecko";
            }

            try {
                localStorage.setItem(storageKey, JSON.stringify({
                    volume: volume,
                    timestamp: currentTime
                }));
            } catch (storageError) {
                console.warn("Could not save previous volume:", storageError);
            }
        }

    } catch (error) {
        priceElement.textContent = "Unavailable";
        changeElement.textContent = "Market data unavailable";
        updatedElement.textContent = "Please try again later";

        if (volumeElement) volumeElement.textContent = "Unavailable";
        if (volumeChangeElement) {
            volumeChangeElement.textContent = "Volume data unavailable";
        }
        if (volumeUpdatedElement) {
            volumeUpdatedElement.textContent = "Please try again later";
        }

        console.error("NEAR market error:", error);
    }
}

loadNearMarket();

// Refresh market data every five minutes while the page is visible.
setInterval(() => {
    if (!document.hidden) {
        loadNearMarket();
    }
}, 5 * 60 * 1000);


// AGENTGUARD NEAR LARGE BUY MONITOR
async function loadNearLargeBuys() {
    const countElement = document.getElementById("near-large-buy-count");
    const listElement = document.getElementById("near-large-buy-list");

    if (!countElement || !listElement) return;

    try {
        const response = await fetch("/near/large-buys");

        if (!response.ok) {
            throw new Error("Large-buy API unavailable");
        }

        const result = await response.json();

        if (!result.success || !Array.isArray(result.data)) {
            throw new Error("Invalid large-buy response");
        }

        // Update the card only after a successful API response.
        listElement.replaceChildren();

        if (result.data.length === 0) {
            countElement.textContent = "No buy detected";

            const message = document.createElement("p");
            message.textContent = "No verified NEAR purchases found in the latest feed.";
            listElement.appendChild(message);
            return;
        }

        const buy = result.data[0];

        countElement.textContent = "Largest buy";

        const item = document.createElement("div");
        item.className = "near-large-buy-item";

        const value = document.createElement("p");
        value.textContent =
            "$" + Number(buy.usd_value).toLocaleString("en-US", {
                maximumFractionDigits: 2
            }) + " | " +
            Number(buy.near_amount).toLocaleString("en-US", {
                maximumFractionDigits: 4
            }) + " NEAR";

        const wallet = document.createElement("small");
        wallet.textContent = "Wallet: " + (buy.wallet || "Unknown");

        const link = document.createElement("a");
        link.textContent = "View transaction";
        link.href = buy.transaction_url ||
            "https://nearblocks.io/txns/" +
            encodeURIComponent(buy.transaction_hash);
        link.target = "_blank";
        link.rel = "noopener noreferrer";

        item.append(value, wallet, link);
        listElement.appendChild(item);

    } catch (error) {
        // Keep the last successful result visible if a refresh fails.
        console.error("NEAR large-buy error:", error);
    }
}

loadNearLargeBuys();

// Refresh large-buy data every 60 seconds.
setInterval(() => {
    if (!document.hidden) {
        loadNearLargeBuys();
    }
}, 60 * 1000);

// AGENTGUARD BACKEND HEALTH MONITOR

async function checkSystemHealth() {
    const status = document.getElementById("systemStatus");
    const statusText = document.getElementById("systemStatusText");
    const statusDot = document.getElementById("systemStatusDot");

    const sidebarText = document.getElementById("sidebarEngineStatusText");
    const sidebarDot = document.getElementById("sidebarEngineStatusDot");

    if (!status || !statusText || !statusDot ||
        !sidebarText || !sidebarDot) {
        return;
    }

    try {
        const response = await fetch("/health", {
            method: "GET",
            cache: "no-store"
        });

        const data = await response.json();

        if (!response.ok || data.status !== "healthy") {
            throw new Error("Backend health check failed.");
        }

        statusText.textContent = "System Online";
        sidebarText.textContent = "Backend Online";

        status.classList.remove("status-offline", "status-checking");
        status.classList.add("status-online");

        [statusDot, sidebarDot].forEach(dot => {
            dot.classList.remove("status-offline", "status-checking");
            dot.classList.add("status-online");
        });

    } catch (error) {
        statusText.textContent = "System Offline";
        sidebarText.textContent = "Backend Unavailable";

        status.classList.remove("status-online", "status-checking");
        status.classList.add("status-offline");

        [statusDot, sidebarDot].forEach(dot => {
            dot.classList.remove("status-online", "status-checking");
            dot.classList.add("status-offline");
        });

        console.error("Backend health check:", error);
    }
}

checkSystemHealth();

setInterval(() => {
    if (!document.hidden) {
        checkSystemHealth();
    }
}, 60 * 1000);
