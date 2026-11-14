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
function formatNearTransactionAge(timestamp) {
    if (!timestamp) return "Transaction time unavailable";

    let transactionDate;

    if (typeof timestamp === "number") {
        transactionDate = new Date(
            timestamp < 100000000000 ? timestamp * 1000 : timestamp
        );
    } else {
        transactionDate = new Date(timestamp);
    }

    if (Number.isNaN(transactionDate.getTime())) {
        return "Transaction time unavailable";
    }

    const ageSeconds = Math.max(
        0,
        Math.floor((Date.now() - transactionDate.getTime()) / 1000)
    );

    if (ageSeconds < 60) return ageSeconds + " seconds ago";

    const minutes = Math.floor(ageSeconds / 60);
    if (minutes < 60) return minutes + " minutes ago";

    const hours = Math.floor(minutes / 60);
    if (hours < 24) return hours + " hours ago";

    const days = Math.floor(hours / 24);
    return days + " days ago";
}

async function loadNearLargeBuys() {
    const countElement = document.getElementById("near-large-buy-count");
    const listElement = document.getElementById("near-large-buy-list");

    if (!countElement || !listElement) return;

    let statusElement = document.getElementById("near-large-buy-status");

    if (!statusElement) {
        statusElement = document.createElement("small");
        statusElement.id = "near-large-buy-status";
        statusElement.className = "near-large-buy-status";
        listElement.parentElement.insertBefore(statusElement, listElement);
    }

    try {
        const response = await fetch("/near/large-buys");

        if (!response.ok) {
            throw new Error("Large-buy API unavailable");
        }

        const result = await response.json();

        if (!result.success || !Array.isArray(result.data)) {
            throw new Error("Invalid large-buy response");
        }

        const updatedDate = result.last_updated
            ? new Date(result.last_updated)
            : null;

        const updatedText =
            updatedDate && !Number.isNaN(updatedDate.getTime())
                ? updatedDate.toLocaleString()
                : "Unavailable";

        statusElement.textContent =
            (result.is_stale ? "STALE DATA" : "FRESH DATA") +
            " | Last updated: " + updatedText;

        statusElement.dataset.status =
            result.is_stale ? "stale" : "fresh";

        listElement.replaceChildren();

        if (result.data.length === 0) {
            countElement.textContent = "No buy detected";

            const message = document.createElement("p");
            message.textContent =
                "No verified NEAR purchases found in the latest feed.";

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

        const age = document.createElement("small");
        age.className = "near-transaction-age";
        age.textContent =
            "Transaction age: " +
            formatNearTransactionAge(buy.timestamp);

        const link = document.createElement("a");
        link.textContent = "View transaction";
        link.href = buy.transaction_url ||
            "https://nearblocks.io/txns/" +
            encodeURIComponent(buy.transaction_hash);
        link.target = "_blank";
        link.rel = "noopener noreferrer";

        item.append(value, wallet, age, link);
        listElement.appendChild(item);

    } catch (error) {
        console.error("NEAR large-buy error:", error);

        if (statusElement.textContent) {
            statusElement.textContent += " | Refresh failed";
        }
    }
}
loadNearLargeBuys();

// Refresh large-buy data every 60 seconds.
setInterval(() => {
    if (!document.hidden) {
        loadNearLargeBuys();
    }
}, 60 * 1000);


// AGENTGUARD LIVE NEAR NETWORK ACTIVITY MONITOR
let nearNetworkRequestRunning = false;
let nearNetworkHasSuccessfulData = false;

async function loadNearNetworkActivity() {
    if (nearNetworkRequestRunning || document.hidden) return;

    const status = document.getElementById("near-network-status");
    const statusDot = document.getElementById("near-network-status-dot");

    if (!status || !statusDot) return;

    nearNetworkRequestRunning = true;

    if (!nearNetworkHasSuccessfulData) {
        status.textContent = "Connecting...";
    }

    try {
        const response = await fetch("/near/network-activity?network=mainnet", {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error("NEAR network activity API returned " + response.status);
        }

        const result = await response.json();

        if (!result.success || !result.data) {
            throw new Error("Invalid NEAR network activity response");
        }

        const block = result.data;

        const requiredFields = [
            "block_height",
            "block_hash",
            "block_producer",
            "block_timestamp",
            "shard_chunk_count",
            "included_chunk_count"
        ];

        for (const field of requiredFields) {
            if (block[field] === undefined || block[field] === null) {
                throw new Error("Missing network activity field: " + field);
            }
        }

        const setText = (id, value) => {
            const element = document.getElementById(id);
            if (element) element.textContent = value;
        };

        setText("near-block-height", Number(block.block_height).toLocaleString());
        setText("near-block-producer", block.block_producer);
        setText("near-shard-count", Number(block.shard_chunk_count).toLocaleString());
        setText("near-included-count", Number(block.included_chunk_count).toLocaleString());

        const hash = String(block.block_hash);
        setText("near-block-hash", hash);
        const hashElement = document.getElementById("near-block-hash");
        if (hashElement) hashElement.title = hash;

        const blockDate = new Date(block.block_timestamp);
        if (Number.isNaN(blockDate.getTime())) {
            throw new Error("Invalid block timestamp");
        }

        setText("near-block-time", blockDate.toLocaleString("en-GB", {
            timeZone: "UTC",
            dateStyle: "medium",
            timeStyle: "medium"
        }) + " UTC");

        setText("near-network-updated", new Date().toLocaleTimeString());

        status.textContent = "Live ? Finalized";
        statusDot.classList.remove("is-error");
        statusDot.classList.add("is-live");

        nearNetworkHasSuccessfulData = true;

    } catch (error) {
        console.error("NEAR network activity error:", error);

        status.textContent = nearNetworkHasSuccessfulData
            ? "Connection issue ? Showing last data"
            : "Network data unavailable";

        statusDot.classList.remove("is-live");
        statusDot.classList.add("is-error");

    } finally {
        nearNetworkRequestRunning = false;
    }
}

loadNearNetworkActivity();

// Refresh finalized block information every 60 seconds.
setInterval(() => {
    if (!document.hidden) {
        loadNearNetworkActivity();
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

// AGENTGUARD FIVE-IMAGE FEATURE-MATCHED ROTATION
(function () {
    const imageSets = {
        "Wallet Risk Signals": [
            "/static/images/wallet-guard.svg",
            "/static/images/wallet-risk.webp",
            "/static/images/wallet-feature-1.svg",
            "/static/images/wallet-feature-2.svg",
            "/static/images/wallet-feature-3.svg"
        ],
        "Transaction Security": [
            "/static/images/transaction-flow.svg",
            "/static/images/transaction-security.webp",
            "/static/images/transaction-feature-1.svg",
            "/static/images/transaction-feature-2.svg",
            "/static/images/transaction-feature-3.svg"
        ],
        "Contract Risk Checks": [
            "/static/images/contract-shield.svg",
            "/static/images/contract-risk.webp",
            "/static/images/contract-feature-1.svg",
            "/static/images/contract-feature-2.svg",
            "/static/images/contract-feature-3.svg"
        ],
        "Risk Intelligence": [
            "/static/images/risk-intelligence.svg",
            "/static/images/risk-intelligence.webp",
            "/static/images/intelligence-feature-1.svg",
            "/static/images/intelligence-feature-2.svg",
            "/static/images/intelligence-feature-3.svg"
        ],
        "Approval Tracking": [
            "/static/images/approval-security.svg",
            "/static/images/approval-tracking.webp",
            "/static/images/approval-feature-1.svg",
            "/static/images/approval-feature-2.svg",
            "/static/images/approval-feature-3.svg"
        ],
        "Network Risk Assessment": [
            "/static/images/network-intelligence.svg",
            "/static/images/network-risk.webp",
            "/static/images/network-feature-1.svg",
            "/static/images/network-feature-2.svg",
            "/static/images/network-feature-3.svg"
        ],
        "NEAR Market Price": [
            "/static/images/near-market-visual.svg",
            "/static/images/near-market.webp",
            "/static/images/price-feature-1.svg",
            "/static/images/price-feature-2.svg",
            "/static/images/price-feature-3.svg"
        ],
        "NEAR Trading Volume": [
            "/static/images/near-volume-visual.svg",
            "/static/images/near-volume-activity.svg",
            "/static/images/volume-feature-1.svg",
            "/static/images/volume-feature-2.svg",
            "/static/images/volume-feature-3.svg"
        ],
        "Largest NEAR Pool Buy": [
            "/static/images/near-large-buy-visual.svg",
            "/static/images/near-large-buy.webp",
            "/static/images/largebuy-feature-1.svg",
            "/static/images/largebuy-feature-2.svg",
            "/static/images/largebuy-feature-3.svg"
        ]
    };

    const IMAGE_INTERVAL = 12000;
    const FADE_DURATION = 700;

    function applyAIImages() {
        document.querySelectorAll(".activity-card").forEach(card => {
            if (card.dataset.imageRotationReady === "true") return;

            const title = card.querySelector("h3")?.textContent.trim();
            const images = imageSets[title];
            const visual = card.querySelector(".activity-visual");

            if (!images || !visual) return;

            let img = visual.querySelector(".ai-card-image");

            if (!img) {
                img = document.createElement("img");
                img.className = "ai-card-image";
                img.alt = title + " feature illustration";
                img.loading = "lazy";
                visual.prepend(img);
            }

            card.dataset.imageRotationReady = "true";

            let index = 0;
            img.src = images[index];

            images.forEach(src => {
                const preload = new Image();
                preload.src = src;
            });

            window.setInterval(() => {
                if (document.hidden || !img.isConnected) return;

                const nextIndex = (index + 1) % images.length;
                const nextImage = new Image();

                nextImage.onload = () => {
                    img.classList.add("is-changing");

                    window.setTimeout(() => {
                        if (!img.isConnected) return;

                        img.src = nextImage.src;
                        index = nextIndex;

                        requestAnimationFrame(() => {
                            img.classList.remove("is-changing");
                        });
                    }, FADE_DURATION);
                };

                nextImage.src = images[nextIndex];
            }, IMAGE_INTERVAL);
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", applyAIImages);
    } else {
        applyAIImages();
    }
})();
// AGENTGUARD NEAR ACCESS-KEY SECURITY SCANNER
// ==========================================

(() => {
    const form = document.getElementById("access-key-form");
    if (!form) return;

    const accountInput = document.getElementById("access-key-account");
    const networkInput = document.getElementById("access-key-network");
    const scanButton = document.getElementById("access-key-scan-button");
    const message = document.getElementById("access-key-message");
    const results = document.getElementById("access-key-results");
    const status = document.getElementById("access-key-status");
    const statusDot = document.getElementById("access-key-status-dot");
    const tableBody = document.getElementById("access-key-table-body");

    tableBody.addEventListener("click", async (event) => {
        const copyButton = event.target.closest(".copy-public-key-button");

        if (!copyButton || !tableBody.contains(copyButton)) return;

        const publicKey = copyButton.dataset.publicKey;
        if (!publicKey) return;

        const originalText = copyButton.textContent;
        let copied = false;

        try {
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(publicKey);
                copied = true;
            } else {
                const temporaryInput = document.createElement("textarea");
                temporaryInput.value = publicKey;
                temporaryInput.style.position = "fixed";
                temporaryInput.style.opacity = "0";
                document.body.appendChild(temporaryInput);
                temporaryInput.select();
                copied = document.execCommand("copy");
                temporaryInput.remove();
            }
        } catch (error) {
            console.warn("Public key copy failed:", error);
        }

        copyButton.textContent = copied ? "Copied" : "Copy failed";

        setTimeout(() => {
            copyButton.textContent = originalText;
        }, 1600);
    });

    let scanRunning = false;

    function setText(id, value) {
        const element = document.getElementById(id);
        if (element) element.textContent = String(value);
    }

    function escapeHTML(value) {
        return String(value ?? "").replace(/[&<>"']/g, character => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        })[character]);
    }

    function setStatus(label, state) {
        status.textContent = label;
        statusDot.classList.remove("is-live", "is-error");
        if (state) statusDot.classList.add(state);
    }

    function formatNumber(value) {
        const number = Number(value);
        return Number.isFinite(number) ? number.toLocaleString() : "--";
    }

    function renderKeys(keys) {
        const riskPriority = { HIGH: 0, MEDIUM: 1, LOW: 2, UNKNOWN: 3 };

        const sortedKeys = [...keys].sort((a, b) => {
            const aRisk = a.risk_assessment?.risk_level || "UNKNOWN";
            const bRisk = b.risk_assessment?.risk_level || "UNKNOWN";

            const priorityDifference =
                (riskPriority[aRisk] ?? 3) - (riskPriority[bRisk] ?? 3);

            if (priorityDifference !== 0) {
                return priorityDifference;
            }

            return (b.risk_assessment?.risk_score || 0) -
                   (a.risk_assessment?.risk_score || 0);
        });

        const visibleKeys = sortedKeys.slice(0, 50);

        if (!visibleKeys.length) {
            tableBody.innerHTML =
                '<tr><td colspan="7">No access keys found for this account.</td></tr>';
            return;
        }

        tableBody.innerHTML = visibleKeys.map(key => {
                        const publicKey = String(key.public_key || "");
            const publicKeyDisplay = publicKey
                ? `${escapeHTML(publicKey.slice(0, 12))}…${escapeHTML(publicKey.slice(-8))}`
                : "Unavailable";

            const publicKeyCell = publicKey
                ? `
                    <div class="public-key-value" title="${escapeHTML(publicKey)}">${publicKeyDisplay}</div>
                    <button
                        type="button"
                        class="copy-public-key-button"
                        data-public-key="${escapeHTML(publicKey)}"
                        aria-label="Copy full public key"
                    >Copy</button>
                `
                : "Unavailable";
            const permission = escapeHTML(key.permission || "Unknown");
            const receiver = escapeHTML(key.receiver_id || "All account permissions");
            const methods = Array.isArray(key.method_names) && key.method_names.length
                ? escapeHTML(key.method_names.join(", "))
                : (key.permission === "FullAccess" ||
                   key.permission === "GasKeyFullAccess"
                    ? "Unrestricted"
                    : "All receiver methods");

            const allowance = key.allowance === null || key.allowance === undefined
                ? "Not applicable"
                : escapeHTML(key.allowance);

            const assessment = key.risk_assessment || {};
            const riskLevel = ["HIGH", "MEDIUM", "LOW"].includes(assessment.risk_level)
                ? assessment.risk_level
                : "UNKNOWN";

            const riskScore = Number.isFinite(Number(assessment.risk_score))
                ? Number(assessment.risk_score)
                : "--";

            const findings = Array.isArray(assessment.findings)
                ? assessment.findings
                : [];

            const reasons = Array.isArray(assessment.reasons)
                ? assessment.reasons
                : [];

            const recommendations = Array.isArray(assessment.recommendations)
                ? assessment.recommendations
                : [];

            const findingHTML = findings.map(finding => {
                const severity = ["HIGH", "MEDIUM", "LOW", "INFO"].includes(
                    finding.severity
                ) ? finding.severity : "INFO";

                const evidence = finding.evidence &&
                    typeof finding.evidence === "object"
                    ? Object.entries(finding.evidence).map(([label, value]) => {
                        const displayValue = Array.isArray(value)
                            ? value.join(", ")
                            : value !== null && typeof value === "object"
                                ? JSON.stringify(value)
                                : String(value ?? "Not available");

                        return `<div><strong>${escapeHTML(label)}:</strong> ${escapeHTML(displayValue)}</div>`;
                    }).join("")
                    : "";

                return `
                    <div class="access-key-finding">
                        <div class="access-key-finding-heading">
                            <strong>${escapeHTML(finding.title || finding.code || "Security finding")}</strong>
                            <span class="finding-severity finding-${severity.toLowerCase()}">${severity}</span>
                        </div>
                        <p>${escapeHTML(finding.description || "No explanation provided.")}</p>
                        ${evidence ? `
                            <div class="access-key-evidence">
                                <strong>Evidence</strong>
                                ${evidence}
                            </div>
                        ` : ""}
                        ${finding.recommendation ? `
                            <p class="access-key-recommendation">
                                <strong>Recommendation:</strong>
                                ${escapeHTML(finding.recommendation)}
                            </p>
                        ` : ""}
                    </div>
                `;
            }).join("");

            const fallbackHTML = [
                ...reasons,
                ...recommendations.map(item => `Recommendation: ${item}`)
            ].map(item => `<div>${escapeHTML(item)}</div>`).join("");

            const explanation = findings.length
                ? findingHTML
                : fallbackHTML;

            const assessmentNote = `
                <div class="access-key-assessment-note">
                    Heuristic assessment: these indicators do not prove compromise.
                </div>
            `;

            return `
                <tr>
                <td class="access-key-public-key">${publicKeyCell}</td>
                <td>${permission}</td>
                    <td>${receiver}</td>
                    <td>${methods}</td>
                    <td>${allowance}</td>
                    <td>
                        <span class="risk-badge risk-${riskLevel.toLowerCase()}">
                            ${riskLevel} (${riskScore})
                        </span>
                    </td>
                    <td>${explanation || "No assessment available."}${assessmentNote}</td>
                </tr>
            `;
        }).join("");

        const note = keys.length > 50
            ? `Showing 50 of ${formatNumber(keys.length)} keys.`
            : `Showing all ${formatNumber(keys.length)} keys.`;

        setText("access-key-table-note", note);
    }

    form.addEventListener("submit", async event => {
        event.preventDefault();

        if (scanRunning) return;

        const accountId = accountInput.value.trim();
        const network = networkInput.value;

        if (!accountId) {
            message.textContent = "Enter a NEAR account ID.";
            accountInput.focus();
            return;
        }

        scanRunning = true;
        scanButton.disabled = true;
        scanButton.textContent = "Scanning...";
        results.hidden = true;
        message.textContent = "Reading public access-key permissions. Large accounts may take a little longer...";
        setStatus("Scanning account...", "");

        try {
            const endpoint =
                `/near/accounts/${encodeURIComponent(accountId)}/access-keys` +
                `?network=${encodeURIComponent(network)}`;

            const response = await fetch(endpoint, {
                method: "GET",
                cache: "no-store",
                headers: { "Accept": "application/json" }
            });

            const result = await response.json();

            if (!response.ok || !result.success || !result.data) {
                throw new Error(
                    result.detail || result.error || `Scan failed (${response.status})`
                );
            }

            const data = result.data;

            if (!Array.isArray(data.keys)) {
                throw new Error("The API returned an invalid access-key list.");
            }

            setText("access-key-total", formatNumber(data.total_keys));
            setText("access-key-full", formatNumber(data.full_access_keys));
            setText("access-key-restricted", formatNumber(data.restricted_keys));
            setText("access-key-pages", formatNumber(data.pages_scanned));

            const riskSummary = data.risk_summary || {};
            setText("access-key-high-risk", formatNumber(riskSummary.high_risk));
            setText("access-key-medium-risk", formatNumber(riskSummary.medium_risk));
            setText("access-key-low-risk", formatNumber(riskSummary.low_risk));

            setText("access-key-account-result", data.account_id);
            setText("access-key-block", formatNumber(data.block_height));
            setText("access-key-data-status", data.data_status || "Unknown");

            const warning = document.getElementById("access-key-warning");
            warning.hidden = Number(data.full_access_keys) === 0;

            renderKeys(data.keys);

            results.hidden = false;
            message.textContent =
                `Scan completed for ${data.account_id} on ${data.network}.`;
            setStatus("Scan complete · Finalized", "is-live");

        } catch (error) {
            console.error("Access-key security scan failed:", error);
            message.textContent = error.message || "Unable to scan this account.";
            setStatus("Scan failed", "is-error");
        } finally {
            scanRunning = false;
            scanButton.disabled = false;
            scanButton.textContent = "Scan Account";
        }
    });
})();

// ==========================================
// AGENTGUARD NEAR MULTI-ACCOUNT SECURITY SCANNER
// ==========================================

(() => {
    const button = document.getElementById("multi-scan-button");
    if (!button) return;

    const accounts = [
        "near",
        "wrap.near",
        "intents.near",
        "social.near",
        "aurora",
        "ref-finance.near",
        "burrow.near"
    ];

    const message = document.getElementById("multi-scan-message");
    const progress = document.getElementById("multi-scan-progress");
    const results = document.getElementById("multi-scan-results");
    const tableBody = document.getElementById("multi-scan-table-body");
    const status = document.getElementById("multi-scan-status");
    const statusDot = document.getElementById("multi-scan-status-dot");
    const warning = document.getElementById("multi-scan-warning");

    let scanning = false;

    function setText(id, value) {
        const element = document.getElementById(id);
        if (element) element.textContent = String(value);
    }

    function setStatus(label, state) {
        status.textContent = label;
        statusDot.classList.remove("is-live", "is-error");
        if (state) statusDot.classList.add(state);
    }

    function createElement(tag, text, className) {
        const element = document.createElement(tag);

        if (text !== null && text !== undefined) {
            element.textContent = String(text);
        }

        if (className) element.className = className;
        return element;
    }

    function createCell(value) {
        return createElement("td", value ?? "N/A");
    }

    async function requestData(url) {
        let lastError;

        for (let attempt = 1; attempt <= 3; attempt++) {
            try {
                const response = await fetch(url, {
                    method: "GET",
                    cache: "no-store",
                    headers: { "Accept": "application/json" }
                });

                const body = await response.json();

                if (!response.ok || !body.success || !body.data) {
                    throw new Error(
                        body.detail || body.error || `HTTP ${response.status}`
                    );
                }

                return body.data;
            } catch (error) {
                lastError = error;

                if (attempt < 3) {
                    await new Promise(resolve => setTimeout(resolve, 2000));
                }
            }
        }

        throw lastError || new Error("Request failed.");
    }

    function assessAccount(keyData) {
        const invalid = {
            valid: false,
            level: "UNASSESSED",
            score: null,
            findings: [],
            recommendations: []
        };

        if (!keyData ||
            keyData.data_status !== "finalized" ||
            keyData.has_more !== false ||
            !Array.isArray(keyData.keys) ||
            !keyData.risk_summary) {
            return invalid;
        }

        const keys = keyData.keys;
        const total = Number(keyData.total_keys);
        const assessed = Number(keyData.risk_summary.assessed_keys);

        if (!Number.isInteger(total) ||
            total !== keys.length ||
            assessed !== keys.length) {
            return invalid;
        }

        const levels = ["LOW", "MEDIUM", "HIGH"];

        const validKeys = keys.every(key => {
            const assessment = key && key.risk_assessment;

            return assessment &&
                levels.includes(assessment.risk_level) &&
                Number.isFinite(Number(assessment.risk_score)) &&
                Number(assessment.risk_score) >= 0 &&
                Number(assessment.risk_score) <= 100;
        });

        if (!validKeys) return invalid;

        const assessments = keys.map(key => key.risk_assessment);

        const score = assessments.length
            ? Math.max(...assessments.map(item => Number(item.risk_score)))
            : 0;

        let level = "LOW";

        if (assessments.some(item => item.risk_level === "HIGH")) {
            level = "HIGH";
        } else if (assessments.some(item => item.risk_level === "MEDIUM")) {
            level = "MEDIUM";
        }

        const unique = values => [...new Set(
            values.filter(value => typeof value === "string" && value.trim())
        )];

        const findings = unique(
            assessments.flatMap(item => item.reasons || [])
        );

        const recommendations = unique(
            assessments.flatMap(item => item.recommendations || [])
        );

        if (!findings.length) {
            findings.push(
                "No access-key risk findings were returned for this finalized snapshot."
            );
        }

        if (!recommendations.length) {
            recommendations.push(
                "Continue monitoring permissions and re-scan after account changes."
            );
        }

        return {
            valid: true,
            level,
            score,
            findings,
            recommendations
        };
    }

    function addList(container, title, items) {
        container.appendChild(createElement("h5", title));

        const list = document.createElement("ul");

        items.forEach(item => {
            list.appendChild(createElement("li", item));
        });

        container.appendChild(list);
    }

    function addAccountRow(account, accountData, keyData, error) {
        const assessment = assessAccount(keyData);

        const complete = Boolean(accountData && assessment.valid);
        const partial = Boolean(accountData || keyData);

        const row = document.createElement("tr");

        row.appendChild(createCell(account));

        row.appendChild(createCell(
            accountData ? accountData.balance_near : "Unavailable"
        ));

        row.appendChild(createCell(
            keyData && Array.isArray(keyData.keys)
                ? keyData.keys.length.toLocaleString()
                : "Unavailable"
        ));

        row.appendChild(createCell(
            keyData ? Number(keyData.full_access_keys || 0).toLocaleString() : "Unavailable"
        ));

        row.appendChild(createCell(
            keyData ? Number(keyData.restricted_keys || 0).toLocaleString() : "Unavailable"
        ));

        const riskCell = document.createElement("td");
        const badge = createElement(
            "span",
            assessment.level,
            "risk-badge risk-" + assessment.level.toLowerCase()
        );
        riskCell.appendChild(badge);
        row.appendChild(riskCell);

        row.appendChild(createCell(
            assessment.valid ? assessment.score + " / 100" : "N/A"
        ));

        row.appendChild(createCell(
            complete ? "Complete" : partial ? "Partial" : "Failed"
        ));

        tableBody.appendChild(row);

        // Expandable evidence and recommendations.
        const detailRow = document.createElement("tr");
        detailRow.className = "multi-account-details-row";
        const detailCell = document.createElement("td");
        detailCell.colSpan = 8;

        const details = document.createElement("details");
        details.className = "multi-account-details";

        const summary = createElement(
            "summary",
            "View findings, recommendations and evidence"
        );
        details.appendChild(summary);

        const content = createElement("div", null, "multi-account-details-content");

        if (assessment.valid) {
            addList(content, "Findings", assessment.findings);
            addList(content, "Recommendations", assessment.recommendations);

            const evidence = createElement("div", null, "multi-account-evidence");

            evidence.appendChild(createElement(
                "p",
                `Assessed keys: ${keyData.risk_summary.assessed_keys}`
            ));

            evidence.appendChild(createElement(
                "p",
                `Pages scanned: ${keyData.pages_scanned ?? "N/A"}`
            ));

            evidence.appendChild(createElement(
                "p",
                `Finalized block height: ${keyData.block_height ?? "N/A"}`
            ));

            evidence.appendChild(createElement(
                "p",
                `Finalized block hash: ${keyData.block_hash ?? "N/A"}`
            ));

            evidence.appendChild(createElement(
                "p",
                `Data status: ${keyData.data_status}`
            ));

            content.appendChild(evidence);
        } else {
            content.appendChild(createElement(
                "p",
                "Risk assessment unavailable. Complete account information and validated finalized access-key data are required."
            ));

            if (error) {
                content.appendChild(createElement("p", error));
            }
        }

        details.appendChild(content);
        detailCell.appendChild(details);
        detailRow.appendChild(detailCell);
        tableBody.appendChild(detailRow);

        if (error) {
            console.warn(`NEAR scan issue for ${account}:`, error);
        }

        return {
            complete,
            assessment
        };
    }

    button.addEventListener("click", async () => {
        if (scanning) return;

        scanning = true;
        button.disabled = true;
        button.textContent = "Scanning...";
        tableBody.replaceChildren();
        results.hidden = false;
        warning.hidden = true;

        let fullAccessTotal = 0;
        let restrictedTotal = 0;
        let successfulAccounts = 0;
        let reviewAccounts = 0;
        let unassessedAccounts = 0;

        setText("multi-total-accounts", "0 / 7");
        setText("multi-full-access", "0");
        setText("multi-restricted", "0");
        setText("multi-review-count", "0");

        message.textContent =
            "Connecting to NEAR Mainnet and inspecting public account data...";

        setStatus("Scanning...", "");

        try {
            for (let index = 0; index < accounts.length; index++) {
                const account = accounts[index];

                progress.textContent =
                    `Scanning ${index + 1} of 7: ${account}`;

                message.textContent =
                    `Retrieving account details and access-key permissions for ${account}...`;

                let accountData = null;
                let keyData = null;
                const errors = [];

                try {
                    accountData = await requestData(
                        `/near/accounts/${encodeURIComponent(account)}?network=mainnet`
                    );
                } catch (error) {
                    errors.push(`Account details: ${error.message}`);
                }

                try {
                    keyData = await requestData(
                        `/near/accounts/${encodeURIComponent(account)}/access-keys?network=mainnet`
                    );
                } catch (error) {
                    errors.push(`Access keys: ${error.message}`);
                }

                const result = addAccountRow(
                    account,
                    accountData,
                    keyData,
                    errors.join("; ")
                );

                if (result.complete) successfulAccounts++;

                if (!result.assessment.valid) {
                    unassessedAccounts++;
                } else {
                    if (keyData) {
                        fullAccessTotal += Number(keyData.full_access_keys) || 0;
                        restrictedTotal += Number(keyData.restricted_keys) || 0;
                    }

                    if (["HIGH", "MEDIUM"].includes(result.assessment.level)) {
                        reviewAccounts++;
                    }
                }

                setText("multi-total-accounts", `${successfulAccounts} / 7`);
                setText("multi-full-access", fullAccessTotal.toLocaleString());
                setText("multi-restricted", restrictedTotal.toLocaleString());
                setText("multi-review-count", reviewAccounts.toLocaleString());

                warning.hidden = fullAccessTotal === 0 && reviewAccounts === 0;
            }

            const complete = successfulAccounts === accounts.length;

            progress.textContent =
                `${successfulAccounts} of 7 accounts fully scanned · ${unassessedAccounts} unassessed.`;

            message.textContent = complete
                ? "All seven accounts have been scanned and their finalized access-key assessments validated."
                : `${successfulAccounts} of 7 accounts completed fully. ${unassessedAccounts} account assessments are unavailable or incomplete.`;

            setStatus(
                complete ? "Scan complete · Mainnet" : "Scan completed with errors",
                complete ? "is-live" : "is-error"
            );

        } catch (error) {
            console.error("Multi-account scan failed:", error);
            message.textContent = error.message || "Multi-account scan failed.";
            setStatus("Scan failed", "is-error");

        } finally {
            scanning = false;
            button.disabled = false;
            button.textContent = "Scan All Seven Accounts";
        }
    });
})();
// AGENTGUARD NEAR TRANSACTION INVESTIGATOR
// ==========================================

(function initializeNearTransactionInvestigator() {
    const form = document.getElementById("near-investigator-form");

    if (!form) return;

    const button = document.getElementById("near-investigator-button");
    const message = document.getElementById("near-investigator-message");
    const results = document.getElementById("near-investigator-results");
    const status = document.getElementById("near-investigator-status");
    const statusDot = document.getElementById("near-investigator-status-dot");

    function setStatus(label, state) {
        status.textContent = label;
        statusDot.className = "near-investigator-status-dot " + state;
    }

    function makeElement(tag, text, className) {
        const element = document.createElement(tag);

        if (text !== null && text !== undefined) {
            element.textContent = String(text);
        }

        if (className) {
            element.className = className;
        }

        return element;
    }

    function makeMetric(label, value, primary = false) {
        const card = makeElement(
            "div",
            null,
            "near-network-metric" + (primary ? " near-network-primary" : "")
        );

        card.appendChild(makeElement("span", label));
        card.appendChild(makeElement("strong", value ?? "--"));

        return card;
    }

    function renderEvidence(evidence) {
        const details = makeElement("details", null, "near-investigator-evidence");
        const summary = makeElement("summary", "View supporting evidence");
        const content = makeElement("pre", JSON.stringify(evidence ?? {}, null, 2));

        details.append(summary, content);

        return details;
    }

    function renderFindings(findings) {
        const container = document.getElementById("near-investigator-findings");
        container.replaceChildren();

        if (!Array.isArray(findings) || findings.length === 0) {
            container.appendChild(
                makeElement(
                    "p",
                    "No classified findings were produced from the available transaction evidence.",
                    "near-investigator-empty"
                )
            );
            return;
        }

        findings.forEach((finding) => {
            const severity = String(finding.severity || "INFO").toLowerCase();

            const card = makeElement(
                "article",
                null,
                "near-investigator-finding severity-" + severity
            );

            const heading = makeElement("div", null, "near-investigator-finding-heading");
            const title = makeElement("h5", finding.title || finding.id || "Security finding");
            const badge = makeElement("span", severity.toUpperCase(), "near-investigator-severity");

            heading.append(title, badge);

            card.appendChild(heading);
            card.appendChild(
                makeElement("p", finding.description || "No additional description available.")
            );

            if (finding.category) {
                card.appendChild(
                    makeElement("small", String(finding.category).replaceAll("_", " "))
                );
            }

            if (finding.evidence) {
                card.appendChild(renderEvidence(finding.evidence));
            }

            container.appendChild(card);
        });
    }


    function renderInteractions(interactions) {
        const container = document.getElementById("near-investigator-interactions");
        container.replaceChildren();

        if (!Array.isArray(interactions) || interactions.length === 0) {
            container.appendChild(
                makeElement("p", "No additional contract interactions were identified.")
            );
            return;
        }

        const stageLabels = {
            AUTHORIZED_AND_EXECUTED: "Authorized + executed",
            AUTHORIZED_ONLY: "Authorization observed",
            RECEIPT_EXECUTION_ONLY: "Receipt execution observed"
        };

        interactions.forEach((interaction) => {
            const card = makeElement(
                "article",
                null,
                "near-investigator-interaction"
            );

            card.appendChild(
                makeElement("strong", interaction.action || "Action")
            );

            if (interaction.sender_id) {
                card.appendChild(
                    makeElement("span", "Delegated sender: " + interaction.sender_id)
                );
            }

            if (interaction.receiver_id) {
                card.appendChild(
                    makeElement("span", "Receiver: " + interaction.receiver_id)
                );
            }

            if (interaction.public_key) {
                card.appendChild(
                    makeElement("span", "Authorizing public key: " + interaction.public_key)
                );
            }

            if (interaction.method_name) {
                card.appendChild(
                    makeElement("span", "Method: " + interaction.method_name)
                );
            }

            if (interaction.attached_deposit_yocto !== undefined) {
                card.appendChild(
                    makeElement(
                        "span",
                        "Attached deposit: " +
                        interaction.attached_deposit_yocto +
                        " yoctoNEAR"
                    )
                );
            }

            if (interaction.transfer_yocto !== undefined) {
                card.appendChild(
                    makeElement(
                        "span",
                        "Transfer: " + interaction.transfer_yocto + " yoctoNEAR"
                    )
                );
            }

            const hasCorrelation =
                typeof interaction.authorization_observed === "boolean" ||
                typeof interaction.execution_observed === "boolean";

            if (hasCorrelation) {
                const correlation = makeElement(
                    "div",
                    null,
                    "near-investigator-correlation"
                );

                const authorizationState =
                    interaction.authorization_observed === true
                        ? "Observed"
                        : "Not observed";

                const executionState =
                    interaction.execution_observed === true
                        ? "Observed"
                        : "Not observed";

                correlation.append(
                    makeElement("span", "Authorization: " + authorizationState),
                    makeElement("span", "Execution: " + executionState)
                );

                card.appendChild(correlation);

                if (stageLabels[interaction.stage]) {
                    card.appendChild(
                        makeElement("small", stageLabels[interaction.stage])
                    );
                }

                if (interaction.authorization_evidence) {
                    card.appendChild(
                        makeElement(
                            "small",
                            "Authorization evidence: " +
                            interaction.authorization_evidence,
                            "near-investigator-evidence-reference"
                        )
                    );
                }

                if (interaction.execution_evidence) {
                    card.appendChild(
                        makeElement(
                            "small",
                            "Execution evidence: " +
                            interaction.execution_evidence,
                            "near-investigator-evidence-reference"
                        )
                    );
                }

            } else if (interaction.evidence_source) {
                card.appendChild(
                    makeElement(
                        "small",
                        "Evidence: " + interaction.evidence_source
                    )
                );
            }

            container.appendChild(card);
        });
    }


    function renderAccounts(accounts) {
        const container = document.getElementById("near-investigator-accounts");
        container.replaceChildren();

        if (!Array.isArray(accounts) || accounts.length === 0) {
            container.appendChild(makeElement("span", "No account information available."));
            return;
        }

        accounts.forEach((account) => {
            container.appendChild(
                makeElement("span", account, "near-investigator-account")
            );
        });
    }

    function renderReport(data) {
        document.getElementById("near-investigator-metrics").replaceChildren(
            makeMetric("Transaction Execution", data.transaction_execution_status),
            makeMetric("Total Receipts", data.receipt_summary?.total ?? 0),
            makeMetric("Failed Receipts", data.receipt_summary?.failed ?? 0),
            makeMetric("Unresolved Receipts", data.receipt_summary?.unresolved ?? 0, true)
        );

        document.getElementById("near-investigator-assessment").textContent =
            String(data.assessment || "Not available").replaceAll("_", " ");

        document.getElementById("near-investigator-confidence").textContent =
            data.investigation_complete ? "Complete" : "Limited";

        document.getElementById("near-investigator-verdict").textContent =
            data.threat_verdict || "NOT DETERMINED";

        renderFindings(data.findings);
        renderInteractions(data.contract_interactions);
        renderAccounts(data.involved_accounts);

        results.hidden = false;
    }

    form.addEventListener("submit", async function (event) {
        event.preventDefault();

        const transactionHash =
            document.getElementById("near-investigator-hash").value.trim();

        const senderAccount =
            document.getElementById("near-investigator-sender").value.trim();

        const network =
            document.getElementById("near-investigator-network").value;

        if (!transactionHash || !senderAccount) {
            message.textContent = "Enter both the transaction hash and sender account.";
            return;
        }

        button.disabled = true;
        button.textContent = "Investigating...";
        message.textContent = "Retrieving finalized transaction and receipt evidence...";
        results.hidden = true;

        setStatus("Investigation in progress", "is-loading");

        try {
            const query = new URLSearchParams({
                sender_account_id: senderAccount,
                network: network
            });

            const endpoint =
                "/near/transactions/" +
                encodeURIComponent(transactionHash) +
                "/analysis?" +
                query.toString();

            const response = await fetch(endpoint, {
                method: "GET",
                cache: "no-store",
                headers: {
                    "Accept": "application/json"
                }
            });

            const payload = await response.json();

            if (!response.ok || !payload.success || !payload.data) {
                throw new Error(
                    payload.detail ||
                    "Transaction investigation failed. Verify the transaction details."
                );
            }

            renderReport(payload.data);

            message.textContent =
                "Investigation completed using finalized NEAR blockchain data.";

            setStatus("Investigation complete", "is-live");

        } catch (error) {
            console.error("NEAR transaction investigation failed:", error);

            message.textContent =
                error.message || "Unable to investigate this transaction.";

            setStatus("Investigation failed", "is-error");

        } finally {
            button.disabled = false;
            button.textContent = "Investigate Transaction";
        }
    });
})();
