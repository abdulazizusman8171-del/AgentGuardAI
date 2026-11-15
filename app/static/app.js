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
            historyList.textContent = "No transaction assessments found yet.";
            return;
        }

        data.transactions.forEach(function (transaction) {
            const item = document.createElement("div");
            item.className = "record-item assessment-record";

            const details = document.createElement("div");
            details.className = "record-details";

            const title = document.createElement("h3");
            title.textContent = transaction.transaction_id;

            const summary = document.createElement("p");
            summary.textContent =
                "Network: " + transaction.network.toUpperCase() +
                " | Amount: " + transaction.amount;

            const risk = document.createElement("p");
            risk.textContent = "Risk score: " + transaction.risk_score + "/100";

            const recipient = document.createElement("p");
            recipient.textContent =
                "Recipient: " + (transaction.recipient_address || "Not provided");

            const date = document.createElement("p");
            date.textContent =
                "Assessed: " + (transaction.assessed_at || "Date unavailable");

            const reasons = document.createElement("p");
            reasons.textContent =
                "Reasons: " +
                (Array.isArray(transaction.reasons) && transaction.reasons.length
                    ? transaction.reasons.join("; ")
                    : "No security concerns detected.");

            const badges = document.createElement("div");
            badges.className = "assessment-badges";

            const decision = document.createElement("span");
            decision.className =
                "status-badge decision-" +
                String(transaction.decision).toLowerCase();
            decision.textContent = transaction.decision;

            const execution = document.createElement("span");
            execution.className =
                "status-badge execution-" +
                String(transaction.execution_status).toLowerCase();
            execution.textContent = transaction.execution_status.replaceAll("_", " ");

            badges.append(decision, execution);
            details.append(title, summary, risk, recipient, date, reasons);
            item.append(details, badges);
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
const accountStatus = document.getElementById("accountStatus");
let approvalApiKey = "";

function csrfToken() {
    const item = document.cookie.split(";").map(v => v.trim()).find(v => v.startsWith("agentguard_csrf="));
    return item ? decodeURIComponent(item.split("=").slice(1).join("=")) : "";
}
function authHeaders(extra = {}) {
    return { "Content-Type": "application/json", "X-CSRF-Token": csrfToken(), ...extra };
}
async function authPost(path, body = {}) {
    const response = await fetch(path, { method: "POST", credentials: "same-origin", headers: authHeaders(), body: JSON.stringify(body) });
    const data = await response.json();
    if (!response.ok) { const detail = data.detail; const message = typeof detail === "string" ? detail : Array.isArray(detail) ? detail.map(item => item.msg || JSON.stringify(item)).join("; ") : detail && typeof detail === "object" ? JSON.stringify(detail) : "Request failed."; throw new Error(message); }
    return data;
}
function showOneTimeKey(data) {
    approvalApiKey = data.approval_key;
    approvalApiKeyInput.value = data.approval_key;
    approvalAuthStatus.textContent = data.warning + " Store it safely; it will not be shown again.";
}
document.getElementById("registerAccount").addEventListener("click", async () => {
    try { const data = await authPost("/auth/register", { email: document.getElementById("accountEmail").value, password: document.getElementById("accountPassword").value }); accountStatus.textContent = data.message; }
    catch (e) { accountStatus.textContent = e.message; }
});
document.getElementById("verifyEmailAccount").addEventListener("click", async () => {
    try { const data = await authPost("/auth/verify-email", { token: document.getElementById("emailVerificationToken").value }); accountStatus.textContent = data.message; }
    catch (e) { accountStatus.textContent = e.message; }
});
document.getElementById("loginAccount").addEventListener("click", async () => {
    try { const data = await authPost("/auth/login", { email: document.getElementById("accountEmail").value, password: document.getElementById("accountPassword").value }); accountStatus.textContent = "Logged in as " + data.user.email; await loadDeveloperApiKeys(); await loadDeveloperAnalytics(); }
    catch (e) { accountStatus.textContent = e.message; }
});
document.getElementById("logoutAccount").addEventListener("click", async () => {
    try { const data = await authPost("/auth/logout"); approvalApiKey = ""; approvalApiKeyInput.value = ""; approvalList.textContent = "Log in to view approvals."; clearDeveloperApiKeys(); clearDeveloperAnalytics(); accountStatus.textContent = data.message; }
    catch (e) { accountStatus.textContent = e.message; }
});
document.getElementById("createApprovalKey").addEventListener("click", async () => {
    try { showOneTimeKey(await authPost("/auth/approval-key")); }
    catch (e) { approvalAuthStatus.textContent = e.message; }
});
document.getElementById("requestKeyRecovery").addEventListener("click", async () => {
    try { const data = await authPost("/auth/approval-key/recovery", { email: document.getElementById("accountEmail").value }); accountStatus.textContent = data.message; }
    catch (e) { accountStatus.textContent = e.message; }
});
document.getElementById("completeKeyRecovery").addEventListener("click", async () => {
    try { showOneTimeKey(await authPost("/auth/approval-key/recover", { token: document.getElementById("recoveryToken").value })); accountStatus.textContent = "Approval Key replaced. Please log in again."; }
    catch (e) { accountStatus.textContent = e.message; }
});
function formatTimestamp(value) {
    if (!value) return "Date unavailable";
    const numeric = Number(value);
    const date = Number.isFinite(numeric) ? new Date(numeric < 1000000000000 ? numeric * 1000 : numeric) : new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}
async function loadApprovals() {
    if (!approvalApiKey) { approvalList.textContent = "Log in and unlock the Approval Center with your personal key."; return; }
    approvalList.textContent = "Loading approvals...";
    try {
        const query = new URLSearchParams({ limit: "50" });
        if (approvalStatus.value) query.set("status", approvalStatus.value);
        const response = await fetch("/approvals?" + query.toString(), { credentials: "same-origin", headers: { "X-Approval-Key": approvalApiKey } });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Could not load approvals.");
        approvalList.replaceChildren();
        if (!data.approvals?.length) { approvalList.textContent = "No approvals found."; return; }
        data.approvals.forEach(approval => {
            const item = document.createElement("div"); item.className = "record-item";
            const details = document.createElement("div"); details.className = "record-details";
            const title = document.createElement("h3"); title.textContent = "Transaction: " + approval.transaction_id;
            const id = document.createElement("p"); id.textContent = "Approval ID: " + approval.approval_id;
            const created = document.createElement("p"); created.textContent = "Created: " + formatTimestamp(approval.created_at);
            const badge = document.createElement("span"); const status = String(approval.status || "UNKNOWN").toLowerCase(); badge.className = "status-badge " + status; badge.textContent = status.toUpperCase();
            details.append(title, id, created); item.append(details, badge); approvalList.appendChild(item);
        });
    } catch (error) { approvalList.textContent = error.message; }
}
async function unlockApprovalCenter() {
    approvalApiKey = approvalApiKeyInput.value.trim();
    if (!approvalApiKey) { approvalAuthStatus.textContent = "Enter your personal Approval Key."; return; }
    try { const response = await fetch("/approvals?limit=1", { credentials: "same-origin", headers: { "X-Approval-Key": approvalApiKey } }); const data = await response.json(); if (!response.ok) throw new Error(data.detail || "Authorization failed."); approvalAuthStatus.textContent = "Approval Center unlocked for your account."; await loadApprovals(); }
    catch (error) { approvalApiKey = ""; approvalAuthStatus.textContent = error.message; }
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

function updateActiveSidebarLink() {
    const currentHash = window.location.hash || "#dashboard";

    sidebarLinks.forEach(link => {
        link.classList.toggle("active", link.getAttribute("href") === currentHash);
    });

    const activeLink = document.querySelector("#mainSidebar nav a.active");
    const activeGroup = activeLink?.closest("details.nav-group");

    if (activeGroup) {
        activeGroup.open = true;
    }
}

sidebarLinks.forEach(link => {
    link.addEventListener("click", () => {
        closeMobileMenu();
        updateActiveSidebarLink();
    });
});

window.addEventListener("hashchange", updateActiveSidebarLink);
updateActiveSidebarLink();

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

// Keep duplicated NEAR market carousel cards synchronised with live data.
function syncNearMarketCarouselClones() {
    const track = document.getElementById("nearMarketTrack");
    if (!track) return;

    const cards = Array.from(track.children);
    const originals = cards.filter(
        card => card.getAttribute("aria-hidden") !== "true"
    );
    const clones = cards.filter(
        card => card.getAttribute("aria-hidden") === "true"
    );

    originals.forEach((original, index) => {
        const clone = clones[index];
        if (!clone) return;

        clone.innerHTML = original.innerHTML;
        clone.removeAttribute("id");
        clone.setAttribute("aria-hidden", "true");

        clone.querySelectorAll("[id]").forEach(element => {
            element.removeAttribute("id");
        });
    });
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

        syncNearMarketCarouselClones();

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

        syncNearMarketCarouselClones();
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
            syncNearMarketCarouselClones();
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
        syncNearMarketCarouselClones();

    } catch (error) {
        console.error("NEAR large-buy error:", error);

        if (statusElement.textContent) {
            statusElement.textContent += " | Refresh failed";
        }

        syncNearMarketCarouselClones();
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


    // WALLET BEHAVIOUR SAVED INVESTIGATION HISTORY

    const historyList = document.getElementById("wallet-history-list");
    const historyMessage = document.getElementById("wallet-history-message");
    const historyRefresh = document.getElementById("wallet-history-refresh");
    const historyFirst = document.getElementById("wallet-history-first");
    const historySecond = document.getElementById("wallet-history-second");
    const historyCompare = document.getElementById("wallet-history-compare");
    const historyComparison = document.getElementById("wallet-history-comparison");
    const networkInput = document.getElementById("wallet-behavior-network");

    let savedHistory = [];

    function historyNode(tag, value, className) {
        const node = document.createElement(tag);
        if (value !== undefined && value !== null) {
            node.textContent = String(value);
        }
        if (className) node.className = className;
        return node;
    }

    function updateCompareButton() {
        historyCompare.disabled = !(
            historyFirst.value &&
            historySecond.value &&
            historyFirst.value !== historySecond.value
        );
    }

    function formatHistoryDate(timestamp) {
        const date = new Date(Number(timestamp) * 1000);
        if (Number.isNaN(date.getTime())) return "Date unavailable";
        return date.toLocaleString();
    }

    async function loadWalletBehaviorHistory() {
        const accountId = accountInput.value.trim();
        const network = networkInput.value;

        historyComparison.hidden = true;
        historyComparison.replaceChildren();

        if (!accountId) {
            historyMessage.textContent = "Enter a wallet account to load saved investigations.";
            historyList.replaceChildren(
                historyNode("p", "No wallet account selected.", "near-investigator-empty")
            );
            return;
        }

        historyMessage.textContent = "Loading saved investigations...";
        historyRefresh.disabled = true;

        try {
            const response = await fetch(
                `/near/accounts/${encodeURIComponent(accountId)}/behavior/history?network=${encodeURIComponent(network)}&limit=50`
            );

            const raw = await response.text();
            let payload;

            try {
                payload = JSON.parse(raw);
            } catch {
                throw new Error("The history API returned an invalid response.");
            }

            if (!response.ok) {
                throw new Error(payload.detail || "Unable to load investigation history.");
            }

            savedHistory = Array.isArray(payload.history) ? payload.history : [];
            historyList.replaceChildren();

            historyFirst.replaceChildren(
                historyNode("option", "Select a report")
            );
            historySecond.replaceChildren(
                historyNode("option", "Select a report")
            );

            if (!savedHistory.length) {
                historyList.appendChild(
                    historyNode(
                        "p",
                        "No saved investigations found for this wallet and network.",
                        "near-investigator-empty"
                    )
                );
            }

            savedHistory.forEach((record) => {
                const card = historyNode("article", null, "wallet-history-card");
                const details = historyNode("div", null, "wallet-history-card-details");

                details.append(
                    historyNode("strong", `Report #${record.id}`),
                    historyNode("span", formatHistoryDate(record.created_at)),
                    historyNode(
                        "span",
                        `Risk: ${record.risk_score}/100 ? ${record.risk_level}`
                    ),
                    historyNode(
                        "span",
                        `${record.transaction_count} supplied transaction(s)`
                    )
                );

                const viewButton = historyNode("button", "View Report", "wallet-behavior-secondary");
                viewButton.type = "button";
                viewButton.addEventListener("click", () => viewWalletBehaviorReport(record.id));

                card.append(details, viewButton);
                historyList.appendChild(card);

                const label = `#${record.id} ? ${record.risk_level} (${record.risk_score}/100) ? ${formatHistoryDate(record.created_at)}`;

                const firstOption = historyNode("option", label);
                firstOption.value = String(record.id);
                historyFirst.appendChild(firstOption);

                const secondOption = historyNode("option", label);
                secondOption.value = String(record.id);
                historySecond.appendChild(secondOption);
            });

            historyMessage.textContent =
                `${savedHistory.length} saved investigation(s) ? ${accountId} ? ${network}`;

            updateCompareButton();

        } catch (error) {
            historyMessage.textContent = error.message || "Unable to load history.";
            historyList.replaceChildren(
                historyNode("p", historyMessage.textContent, "near-investigator-empty")
            );
        } finally {
            historyRefresh.disabled = false;
        }
    }

    async function viewWalletBehaviorReport(reportId) {
        historyMessage.textContent = `Loading report #${reportId}...`;

        try {
            const response = await fetch(
                `/near/behavior/report/${encodeURIComponent(reportId)}`
            );

            const raw = await response.text();
            let payload;

            try {
                payload = JSON.parse(raw);
            } catch {
                throw new Error("The report API returned an invalid response.");
            }

            if (!response.ok) {
                throw new Error(payload.detail || "Unable to retrieve this report.");
            }

            if (!payload.record || !payload.record.report) {
                throw new Error("The saved report is incomplete.");
            }

            renderReport(payload.record.report);
            results.scrollIntoView({ behavior: "smooth", block: "start" });
            historyMessage.textContent = `Displaying saved report #${reportId}.`;

        } catch (error) {
            historyMessage.textContent = error.message || "Unable to open saved report.";
        }
    }

    async function compareWalletBehaviorHistory() {
        const firstId = historyFirst.value;
        const secondId = historySecond.value;

        if (!firstId || !secondId || firstId === secondId) {
            historyMessage.textContent = "Select two different reports to compare.";
            return;
        }

        historyCompare.disabled = true;
        historyMessage.textContent = "Comparing saved investigations...";

        try {
            const query = new URLSearchParams({
                first_id: firstId,
                second_id: secondId
            });

            const response = await fetch(
                `/near/behavior/history/compare?${query.toString()}`
            );

            const raw = await response.text();
            let payload;

            try {
                payload = JSON.parse(raw);
            } catch {
                throw new Error("The comparison API returned an invalid response.");
            }

            if (!response.ok) {
                throw new Error(payload.detail || "Unable to compare these reports.");
            }

            const older = payload.older;
            const newer = payload.newer;
            const changes = payload.changes;

            historyComparison.replaceChildren();

            historyComparison.append(
                historyNode("h4", "Investigation Comparison"),
                historyNode("p", `${payload.account_id} ? ${payload.network}`),
                historyNode(
                    "p",
                    `First selected report: #${older.id} ? ${older.risk_level} ? ${older.risk_score}/100`
                ),
                historyNode(
                    "p",
                    `Second selected report: #${newer.id} ? ${newer.risk_level} ? ${newer.risk_score}/100`
                ),
                historyNode(
                    "strong",
                    `Risk score change: ${changes.risk_score > 0 ? "+" : ""}${changes.risk_score}`
                ),
                historyNode(
                    "p",
                    `Transaction sample count change: ${changes.transaction_count > 0 ? "+" : ""}${changes.transaction_count}`
                ),
                historyNode(
                    "p",
                    `Risk level changed: ${changes.risk_level_changed ? "Yes" : "No"}`
                ),
                historyNode("p", payload.notice || "", "wallet-history-footnote")
            );

            historyComparison.hidden = false;
            historyMessage.textContent = "Comparison completed.";

        } catch (error) {
            historyMessage.textContent = error.message || "Comparison failed.";
            historyComparison.hidden = true;
        } finally {
            updateCompareButton();
        }
    }

    historyRefresh.addEventListener("click", loadWalletBehaviorHistory);
    historyCompare.addEventListener("click", compareWalletBehaviorHistory);
    historyFirst.addEventListener("change", updateCompareButton);
    historySecond.addEventListener("change", updateCompareButton);

    accountInput.addEventListener("change", loadWalletBehaviorHistory);
    networkInput.addEventListener("change", loadWalletBehaviorHistory);


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

// ACCOUNT PASSWORD VISIBILITY
(function () {
    const password = document.getElementById("accountPassword");
    const toggle = document.getElementById("toggleAccountPassword");

    if (!password || !toggle) return;

    toggle.addEventListener("click", function () {
        const showing = password.type === "text";

        password.type = showing ? "password" : "text";
        toggle.textContent = showing ? "Show password" : "Hide password";
        toggle.setAttribute("aria-pressed", String(!showing));
    });
})();

// PASSWORD RESET FORM HANDLERS
(function () {
    const requestButton = document.getElementById("requestPasswordReset");
    const completeButton = document.getElementById("completePasswordReset");
    const email = document.getElementById("accountEmail");
    const token = document.getElementById("passwordResetToken");
    const password = document.getElementById("newAccountPassword");
    const confirmation = document.getElementById("confirmAccountPassword");
    const status = document.getElementById("passwordResetStatus");
    const recoveryPanel = document.getElementById("passwordRecoveryPanel");

    function setupVisibility(input, button) {
        if (!input || !button) return;

        button.addEventListener("click", function () {
            const showing = input.type === "text";
            input.type = showing ? "password" : "text";
            button.textContent = showing ? "Show password" : "Hide password";
            button.setAttribute("aria-pressed", String(!showing));
        });
    }

    setupVisibility(
        password,
        document.getElementById("toggleNewAccountPassword")
    );

    setupVisibility(
        confirmation,
        document.getElementById("toggleConfirmAccountPassword")
    );

    if (requestButton) {
        requestButton.addEventListener("click", async function () {
            if (recoveryPanel) recoveryPanel.classList.remove("hidden");
            try {
                const data = await authPost(
                    "/auth/password-reset/request",
                    { email: email.value }
                );
                status.textContent = data.message;
            } catch (error) {
                status.textContent = error.message;
            }
        });
    }

    if (completeButton) {
        completeButton.addEventListener("click", async function () {
            if (password.value !== confirmation.value) {
                status.textContent = "The passwords do not match.";
                return;
            }

            if (password.value.length < 12 || password.value.length > 128) {
                status.textContent =
                    "Password must contain between 12 and 128 characters.";
                return;
            }

            try {
                const data = await authPost(
                    "/auth/password-reset/complete",
                    {
                        token: token.value,
                        password: password.value
                    }
                );

                status.textContent = data.message;
                token.value = "";
                password.value = "";
                confirmation.value = "";
            } catch (error) {
                status.textContent = error.message;
            }
        });
    }
})();


// NEAR MARKET INTELLIGENCE — INTERACTIVE INFINITE CAROUSEL
(() => {
    const track = document.getElementById("nearMarketTrack");
    const prev = document.getElementById("nearMarketPrev");
    const next = document.getElementById("nearMarketNext");
    const dotsContainer = document.getElementById("nearMarketDots");
    const viewport = track?.parentElement;

    if (!track || !viewport) return;

    const originalCards = Array.from(track.children);
    const originalCardCount = originalCards.length;
    const duration = 18000;

    if (originalCardCount < 2) return;

    const stepDuration = duration / originalCardCount;

    originalCards.forEach(card => {
        const clone = card.cloneNode(true);
        clone.removeAttribute("id");
        clone.setAttribute("aria-hidden", "true");
        clone.querySelectorAll("[id]").forEach(el => el.removeAttribute("id"));
        track.appendChild(clone);
    });

    syncNearMarketCarouselClones();

    track.style.animation =
        `agentGuardContinuousSlide ${duration}ms linear infinite`;

    const dots = [];

    if (dotsContainer) {
        dotsContainer.replaceChildren();

        originalCards.forEach((card, index) => {
            const dot = document.createElement("button");

            dot.type = "button";
            dot.className = "near-market-dot";
            dot.setAttribute("aria-label", `Show market card ${index + 1}`);
            dot.addEventListener("click", () => {
                const animation = track.getAnimations()[0];

                if (animation) {
                    animation.currentTime = index * stepDuration;
                    animation.play();
                    updateDots();
                }
            });

            dotsContainer.appendChild(dot);
            dots.push(dot);
        });
    }

    function updateDots() {
        const animation = track.getAnimations()[0];
        if (!animation || !dots.length) return;

        const time = Number(animation.currentTime) || 0;
        const normalizedTime = ((time % duration) + duration) % duration;
        const activeIndex = Math.floor(normalizedTime / stepDuration);

        dots.forEach((dot, index) => {
            const active = index === activeIndex;
            dot.classList.toggle("active", active);

            if (active) {
                dot.setAttribute("aria-current", "true");
            } else {
                dot.removeAttribute("aria-current");
            }
        });
    }

    function moveNearCarousel(direction) {
        const animation = track.getAnimations()[0];

        if (animation) {
            animation.currentTime =
                (Number(animation.currentTime) || 0) +
                direction * stepDuration;

            animation.play();
            updateDots();
        }
    }

    prev?.addEventListener("click", () => moveNearCarousel(-1));
    next?.addEventListener("click", () => moveNearCarousel(1));

    viewport.addEventListener("mouseenter", () => {
        track.style.animationPlayState = "paused";
    });

    viewport.addEventListener("mouseleave", () => {
        track.style.animationPlayState = "running";
    });

    viewport.addEventListener("focusin", () => {
        track.style.animationPlayState = "paused";
    });

    viewport.addEventListener("focusout", () => {
        track.style.animationPlayState = "running";
    });

    updateDots();
    window.setInterval(updateDots, 150);
})();

// ==========================================
// DEVELOPER PLATFORM — API KEY MANAGEMENT
// ==========================================

const developerKeyName = document.getElementById("developerKeyName");
const createDeveloperKeyButton = document.getElementById("createDeveloperKey");
const refreshDeveloperKeysButton = document.getElementById("refreshDeveloperKeys");
const developerKeyStatus = document.getElementById("developerKeyStatus");
const developerKeyList = document.getElementById("developerKeyList");
const developerNewKeyPanel = document.getElementById("developerNewKeyPanel");
const developerNewKey = document.getElementById("developerNewKey");
const developerCopyStatus = document.getElementById("developerCopyStatus");

function developerDate(timestamp) {
    if (!timestamp) return "Never";
    const date = new Date(Number(timestamp) * 1000);
    return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
}

function developerEscape(value) {
    return String(value ?? "").replace(/[&<>"']/g, character => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[character]);
}

function clearDeveloperApiKeys() {
    developerKeyList.replaceChildren();
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.textContent = "Log in to load your API keys.";
    row.appendChild(cell);
    developerKeyList.appendChild(row);

    document.getElementById("developerActiveCount").textContent = "—";
    document.getElementById("developerRevokedCount").textContent = "—";
    document.getElementById("developerLastActivity").textContent = "—";

    developerKeyStatus.textContent = "Log in to manage your developer API keys.";
    developerNewKey.value = "";
    developerNewKeyPanel.classList.add("hidden");
}

async function developerResponse(response) {
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        const detail = data.detail;
        const message = typeof detail === "string"
            ? detail
            : "Request failed with status " + response.status;
        throw new Error(message);
    }

    return data;
}

async function loadDeveloperApiKeys() {
    developerKeyStatus.textContent = "Loading your API keys...";

    try {
        const response = await fetch("/developer/api-keys", {
            method: "GET",
            credentials: "same-origin"
        });

        const data = await developerResponse(response);
        const keys = Array.isArray(data.api_keys) ? data.api_keys : [];

        developerKeyList.replaceChildren();

        let activeCount = 0;
        let revokedCount = 0;
        let latestActivity = 0;

        if (!keys.length) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = 6;
            cell.textContent = "No API keys found. Generate your first key above.";
            row.appendChild(cell);
            developerKeyList.appendChild(row);
        }

        keys.forEach(key => {
            const revoked = Boolean(key.revoked_at);

            if (revoked) {
                revokedCount++;
            } else {
                activeCount++;
            }

            if (key.last_used_at && Number(key.last_used_at) > latestActivity) {
                latestActivity = Number(key.last_used_at);
            }

            const row = document.createElement("tr");

            const values = [
                key.name,
                key.key_prefix,
                developerDate(key.created_at),
                developerDate(key.last_used_at)
            ];

            values.forEach(value => {
                const cell = document.createElement("td");
                cell.textContent = value || "—";
                row.appendChild(cell);
            });

            const statusCell = document.createElement("td");
            const statusBadge = document.createElement("span");
            statusBadge.className = revoked
                ? "developer-key-status revoked"
                : "developer-key-status active";
            statusBadge.textContent = revoked ? "Revoked" : "Active";
            statusCell.appendChild(statusBadge);
            row.appendChild(statusCell);

            const actionCell = document.createElement("td");

            if (!revoked) {
                const revokeButton = document.createElement("button");
                revokeButton.type = "button";
                revokeButton.className = "developer-revoke-button";
                revokeButton.textContent = "Revoke";
                revokeButton.addEventListener("click", () => revokeDeveloperKey(key.id, key.name));
                actionCell.appendChild(revokeButton);
            } else {
                actionCell.textContent = "—";
            }

            row.appendChild(actionCell);
            developerKeyList.appendChild(row);
        });

        document.getElementById("developerActiveCount").textContent = activeCount;
        document.getElementById("developerRevokedCount").textContent = revokedCount;
        document.getElementById("developerLastActivity").textContent =
            latestActivity ? developerDate(latestActivity) : "No activity";

        developerKeyStatus.textContent =
            "Loaded " + keys.length + " API key record(s) for your account.";

    } catch (error) {
        developerKeyStatus.textContent = error.message;
        developerKeyList.replaceChildren();

        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 6;
        cell.textContent = error.message;
        row.appendChild(cell);
        developerKeyList.appendChild(row);
    }
}

async function createDeveloperApiKey() {
    const name = developerKeyName.value.trim();

    if (!name) {
        developerKeyStatus.textContent = "Enter a name for your API key.";
        developerKeyName.focus();
        return;
    }

    createDeveloperKeyButton.disabled = true;
    developerKeyStatus.textContent = "Generating your API key...";

    try {
        const data = await authPost("/developer/api-keys", { name });

        developerNewKey.value = data.api_key;
        developerNewKey.type = "password";
        developerNewKeyPanel.classList.remove("hidden");
        developerCopyStatus.textContent = data.warning ||
            "Copy this key now. It cannot be displayed again.";

        developerKeyName.value = "";
        developerKeyStatus.textContent = "API key created successfully.";

        await loadDeveloperApiKeys();

        developerNewKeyPanel.classList.remove("hidden");

    } catch (error) {
        developerKeyStatus.textContent = error.message;
    } finally {
        createDeveloperKeyButton.disabled = false;
    }
}

async function revokeDeveloperKey(keyId, keyName) {
    if (!window.confirm("Revoke the API key '" + keyName + "'? This cannot be undone.")) {
        return;
    }

    developerKeyStatus.textContent = "Revoking API key...";

    try {
        const response = await fetch("/developer/api-keys/" + encodeURIComponent(keyId), {
            method: "DELETE",
            credentials: "same-origin",
            headers: authHeaders()
        });

        const data = await developerResponse(response);
        developerKeyStatus.textContent = data.message || "API key revoked.";
        await loadDeveloperApiKeys();

    } catch (error) {
        developerKeyStatus.textContent = error.message;
    }
}

createDeveloperKeyButton.addEventListener("click", createDeveloperApiKey);
refreshDeveloperKeysButton.addEventListener("click", loadDeveloperApiKeys);

document.getElementById("toggleDeveloperKey").addEventListener("click", () => {
    const visible = developerNewKey.type === "text";
    developerNewKey.type = visible ? "password" : "text";
    document.getElementById("toggleDeveloperKey").textContent =
        visible ? "Show" : "Hide";
});

document.getElementById("copyDeveloperKey").addEventListener("click", async () => {
    try {
        await navigator.clipboard.writeText(developerNewKey.value);
        developerCopyStatus.textContent = "API key copied. Store it securely.";
    } catch (error) {
        developerCopyStatus.textContent =
            "Clipboard access unavailable. Select and copy the key manually.";
        developerNewKey.type = "text";
        developerNewKey.select();
    }
});

document.getElementById("dismissDeveloperKey").addEventListener("click", () => {
    developerNewKey.value = "";
    developerNewKeyPanel.classList.add("hidden");
    developerNewKey.type = "password";
    developerCopyStatus.textContent = "";
});

document.querySelectorAll(".developer-copy-code").forEach(button => {
    button.addEventListener("click", async () => {
        const target = document.getElementById(button.dataset.copyTarget);
        if (!target) return;

        try {
            await navigator.clipboard.writeText(target.textContent);
            button.textContent = "Copied!";
            window.setTimeout(() => button.textContent = "Copy", 1500);
        } catch (error) {
            button.textContent = "Select text";
        }
    });
});



// DEVELOPER API ANALYTICS

const developerAnalyticsStatus =
    document.getElementById("developerAnalyticsStatus");

const developerAnalyticsEvents =
    document.getElementById("developerAnalyticsEvents");

function clearDeveloperAnalytics() {
    const fields = [
        "analyticsTotalInspections",
        "analyticsPermitted",
        "analyticsApprovalRequired",
        "analyticsRejected",
        "analyticsRateLimits",
        "analyticsDuplicates",
        "analyticsAverageRisk",
        "analyticsHighestRisk"
    ];

    fields.forEach(id => {
        const element = document.getElementById(id);
        if (element) element.textContent = "?";
    });

    if (developerAnalyticsEvents) {
        developerAnalyticsEvents.replaceChildren();

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 6;
        cell.textContent = "Log in to load recent activity.";

        row.appendChild(cell);
        developerAnalyticsEvents.appendChild(row);
    }

    if (developerAnalyticsStatus) {
        developerAnalyticsStatus.textContent =
            "Log in to view your API analytics.";
    }
}

function analyticsValue(value) {
    return value === null || value === undefined
        ? "?"
        : String(value);
}

async function loadDeveloperAnalytics() {
    if (!developerAnalyticsStatus || !developerAnalyticsEvents) return;

    developerAnalyticsStatus.textContent =
        "Loading your developer analytics...";

    try {
        const response = await fetch("/developer/analytics?limit=50", {
            method: "GET",
            credentials: "same-origin"
        });

        const data = await developerResponse(response);
        const analytics = data.analytics || {};
        const summary = analytics.summary || {};

        const values = {
            analyticsTotalInspections: summary.total_inspections,
            analyticsPermitted: summary.permitted,
            analyticsApprovalRequired: summary.approval_required,
            analyticsRejected: summary.rejected,
            analyticsRateLimits: summary.rate_limit_events,
            analyticsDuplicates: summary.duplicate_inspections,
            analyticsAverageRisk: summary.average_risk_score,
            analyticsHighestRisk: summary.highest_risk_score
        };

        Object.entries(values).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (!element) return;

            element.textContent = analyticsValue(value);
        });

        developerAnalyticsEvents.replaceChildren();

        const events = Array.isArray(analytics.recent_events)
            ? analytics.recent_events
            : [];

        if (!events.length) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 6;
            cell.textContent = "No API activity recorded yet.";

            row.appendChild(cell);
            developerAnalyticsEvents.appendChild(row);
        }

        events.forEach(event => {
            const row = document.createElement("tr");

            const eventName = event.event_type === "RATE_LIMIT"
                ? "Rate Limit"
                : event.event_type === "INSPECTION"
                    ? "Inspection"
                    : analyticsValue(event.event_type);

            const decision = event.gateway_status || "?";

            const cells = [
                developerDate(event.created_at),
                event.api_key_name || "Unknown key",
                eventName,
                decision,
                analyticsValue(event.risk_score),
                analyticsValue(event.http_status)
            ];

            cells.forEach(value => {
                const cell = document.createElement("td");
                cell.textContent = String(value);
                row.appendChild(cell);
            });

            developerAnalyticsEvents.appendChild(row);
        });

        developerAnalyticsStatus.textContent =
            "Analytics updated successfully. Showing " +
            events.length + " recent event(s).";

    } catch (error) {
        developerAnalyticsStatus.textContent = error.message;

        developerAnalyticsEvents.replaceChildren();

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 6;
        cell.textContent = error.message;

        row.appendChild(cell);
        developerAnalyticsEvents.appendChild(row);
    }
}

document.getElementById("refreshDeveloperAnalytics")
    .addEventListener("click", loadDeveloperAnalytics);


// Load metadata on page entry. Unauthenticated visitors receive
// the normal login-required response; no raw keys are returned.
loadDeveloperApiKeys();
loadDeveloperAnalytics();


// ==========================================
// AGENTGUARD NEAR WALLET BEHAVIOUR INVESTIGATOR
// ==========================================

(function initializeNearWalletBehavior() {
    const form = document.getElementById("wallet-behavior-form");
    if (!form) return;

    const rows = document.getElementById("wallet-behavior-rows");
    const addButton = document.getElementById("wallet-behavior-add");
    const submitButton = document.getElementById("wallet-behavior-submit");
    const message = document.getElementById("wallet-behavior-message");
    const results = document.getElementById("wallet-behavior-results");
    const status = document.getElementById("wallet-behavior-status");
    const statusDot = document.getElementById("wallet-behavior-status-dot");
    const sampleCount = document.getElementById("wallet-behavior-sample-count");
    const accountInput = document.getElementById("wallet-behavior-account");
    let previousAccountId = accountInput.value.trim();

    const MAX_SAMPLES = 20;

    function element(tag, value, className) {
        const node = document.createElement(tag);
        if (value !== undefined && value !== null) {
            node.textContent = String(value);
        }
        if (className) node.className = className;
        return node;
    }

    function setStatus(label, state) {
        status.textContent = label;
        statusDot.className = "near-investigator-status-dot " + state;
    }

    function updateCount() {
        const count = rows.querySelectorAll(".wallet-behavior-row").length;
        sampleCount.textContent = count + " / " + MAX_SAMPLES + " samples";
        addButton.disabled = count >= MAX_SAMPLES;
    }

    function invalidateReport() {
        if (results.hidden) return;

        results.hidden = true;
        message.textContent = "Your inputs have changed. Investigate again to generate an updated report.";
        setStatus("Results outdated", "");
    }

    function addRow() {
        if (rows.querySelectorAll(".wallet-behavior-row").length >= MAX_SAMPLES) {
            message.textContent = "The maximum is 20 transaction samples.";
            return;
        }

        const row = element("div", null, "wallet-behavior-row");

        const hashField = element("div", null, "near-investigator-field");
        const hashLabel = element("label", "Transaction Hash");
        const hashInput = element("input");
        hashInput.type = "text";
        hashInput.placeholder = "Finalized transaction hash";
        hashInput.maxLength = 50;
        hashInput.autocomplete = "off";
        hashInput.autocapitalize = "off";
        hashInput.spellcheck = false;
        hashInput.required = true;
        hashInput.dataset.field = "hash";
        hashLabel.appendChild(hashInput);
        hashField.appendChild(hashLabel);

        const senderField = element("div", null, "near-investigator-field");
        const senderLabel = element("label", "Sender Account ID");
        const senderInput = element("input");
        senderInput.type = "text";
        senderInput.placeholder = "example.near";
        senderInput.value = accountInput.value.trim();
        senderInput.maxLength = 64;
        senderInput.autocomplete = "off";
        senderInput.autocapitalize = "off";
        senderInput.spellcheck = false;
        senderInput.required = true;
        senderInput.dataset.field = "sender";
        senderLabel.appendChild(senderInput);
        senderField.appendChild(senderLabel);

        const remove = element("button", "Remove", "wallet-behavior-remove");
        remove.type = "button";
        remove.setAttribute("aria-label", "Remove transaction sample");
        remove.addEventListener("click", function () {
            row.remove();
            if (!rows.children.length) addRow();
            updateCount();
            invalidateReport();
        });

        row.append(hashField, senderField, remove);
        rows.appendChild(row);
        updateCount();
    }

    function setText(id, value) {
        document.getElementById(id).textContent =
            value === undefined || value === null ? "--" : String(value);
    }

    function renderMap(containerId, values, emptyText) {
        const container = document.getElementById(containerId);
        container.replaceChildren();

        const entries = Object.entries(values || {});

        if (!entries.length) {
            container.appendChild(element("p", emptyText, "near-investigator-empty"));
            return;
        }

        entries.forEach(([key, value]) => {
            const card = element("div", null, "wallet-behavior-list-item");
            card.append(
                element("span", key.replaceAll("_", " ")),
                element("strong", value)
            );
            container.appendChild(card);
        });
    }

    function renderFindings(findings) {
        const container = document.getElementById("wallet-behavior-findings");
        container.replaceChildren();

        if (!Array.isArray(findings) || !findings.length) {
            container.appendChild(
                element("p", "No weighted behavioural findings were identified in the supplied samples.", "near-investigator-empty")
            );
            return;
        }

        findings.forEach((finding) => {
            const card = element("article", null, "near-investigator-finding");
            const heading = element("div", null, "near-investigator-finding-heading");
            const title = element("h5", finding.title || finding.finding_id || "Finding");
            const badge = element(
                "span",
                finding.severity || "INFO",
                "near-investigator-severity"
            );

            heading.append(title, badge);
            card.appendChild(heading);

            card.appendChild(
                element("p", "Indicator weight: " + (finding.weight ?? 0))
            );

            if (finding.transaction_hash) {
                card.appendChild(
                    element("small", "Transaction: " + finding.transaction_hash)
                );
            }

            if (Array.isArray(finding.transaction_hashes)) {
                card.appendChild(
                    element("small", "Related samples: " + finding.transaction_hashes.length)
                );
            }

            if (finding.evidence) {
                const details = element("details", null, "near-investigator-evidence");
                details.appendChild(element("summary", "View evidence"));
                details.appendChild(
                    element("pre", JSON.stringify(finding.evidence, null, 2))
                );
                card.appendChild(details);
            }

            container.appendChild(card);
        });
    }

    function renderReport(data) {
        const assessment = data.behavioural_assessment || {};
        const activity = data.activity_profile || {};
        const receipts = activity.receipt_summary || {};

        setText("wallet-behavior-score", assessment.risk_score ?? 0);
        setText("wallet-behavior-risk", assessment.risk_level);
        setText("wallet-behavior-confidence", data.confidence);
        setText("wallet-behavior-transactions", data.transaction_count);
        setText("wallet-behavior-sample-status", data.sample_status);
        setText(
            "wallet-behavior-completeness",
            data.investigation_complete ? "Complete" : "Limited"
        );
        setText("wallet-behavior-verdict", data.threat_verdict);
        setText("wallet-behavior-counterparty-count", activity.unique_counterparties ?? 0);
        setText("wallet-behavior-high-impact", activity.high_impact_findings ?? 0);
        setText("wallet-behavior-incomplete", data.incomplete_transaction_count ?? 0);
        setText("wallet-behavior-indicators", assessment.anomaly_count ?? 0);

        setText("wallet-behavior-receipts-total", receipts.total ?? 0);
        setText("wallet-behavior-receipts-success", receipts.successful ?? 0);
        setText("wallet-behavior-receipts-failed", receipts.failed ?? 0);
        setText("wallet-behavior-receipts-unresolved", receipts.unresolved ?? 0);

        const counterparties = document.getElementById("wallet-behavior-counterparties");
        counterparties.replaceChildren();

        const accounts = Object.entries(activity.counterparty_interactions || {});
        if (!accounts.length) {
            counterparties.appendChild(
                element("p", "No other involved accounts identified.", "near-investigator-empty")
            );
        } else {
            accounts.forEach(([account, count]) => {
                const badge = element(
                    "span",
                    account + " · " + count + " interaction(s)",
                    "near-investigator-account"
                );
                counterparties.appendChild(badge);
            });
        }

        renderMap(
            "wallet-behavior-contract-actions",
            activity.contract_action_counts,
            "No contract actions identified in the supplied samples."
        );

        renderFindings(assessment.findings);

        const limitations = document.getElementById("wallet-behavior-limitations");
        limitations.replaceChildren();

        (data.scope_limitations || []).forEach((item) => {
            limitations.appendChild(element("li", item));
        });

        if (!limitations.children.length) {
            limitations.appendChild(element("li", "No scope limitation details returned."));
        }

        results.hidden = false;
    }

    accountInput.addEventListener("input", function () {
        const currentAccountId = accountInput.value.trim();

        rows.querySelectorAll('[data-field="sender"]').forEach((sender) => {
            if (!sender.value.trim() || sender.value.trim() === previousAccountId) {
                sender.value = currentAccountId;
            }
        });

        previousAccountId = currentAccountId;
        invalidateReport();
    });

    form.addEventListener("input", invalidateReport);
    form.addEventListener("change", invalidateReport);

    addButton.addEventListener("click", addRow);

    form.addEventListener("submit", async function (event) {
        event.preventDefault();

        const accountId = document.getElementById("wallet-behavior-account").value.trim();
        const network = document.getElementById("wallet-behavior-network").value;

        const transactionRows = Array.from(
            rows.querySelectorAll(".wallet-behavior-row")
        );

        const transactions = transactionRows.map((row) => ({
            transaction_hash: row.querySelector('[data-field="hash"]').value.trim(),
            sender_account_id: row.querySelector('[data-field="sender"]').value.trim()
        }));

        if (!accountId) {
            message.textContent = "Enter the wallet account ID.";
            return;
        }

        if (!transactions.length || transactions.some(
            (item) => !item.transaction_hash || !item.sender_account_id
        )) {
            message.textContent = "Complete every transaction hash and sender account field.";
            return;
        }

        if (transactions.length > MAX_SAMPLES) {
            message.textContent = "A maximum of 20 transaction samples is allowed.";
            return;
        }

        const hashes = transactions.map((item) => item.transaction_hash);
        if (new Set(hashes).size !== hashes.length) {
            message.textContent = "Duplicate transaction hashes are not allowed.";
            return;
        }

        submitButton.disabled = true;
        submitButton.textContent = "Investigating...";
        addButton.disabled = true;
        results.hidden = true;

        message.textContent = "Retrieving finalized transactions and building the wallet behaviour profile...";
        setStatus("Investigation in progress", "is-loading");

        try {
            const endpoint =
                "/near/accounts/" + encodeURIComponent(accountId) +
                "/behavior?network=" + encodeURIComponent(network);

            const response = await fetch(endpoint, {
                method: "POST",
                cache: "no-store",
                headers: {
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ transactions })
            });

            const responseText = await response.text();
            let payload = {};

            try {
                payload = responseText ? JSON.parse(responseText) : {};
            } catch {
                throw new Error("The server returned an unreadable response. Please try again.");
            }

            if (!response.ok) {
                throw new Error(
                    (typeof payload.detail === "string" ? payload.detail : null) ||
                    "Wallet behaviour investigation failed."
                );
            }

            if (
                payload.analysis_type !== "deterministic_wallet_behavior_analysis" ||
                !payload.behavioural_assessment ||
                !payload.activity_profile
            ) {
                throw new Error("The API returned an unexpected wallet analysis response.");
            }

            renderReport(payload);

            await loadWalletBehaviorHistory();

            message.textContent =
                "Wallet behaviour investigation completed using supplied finalized NEAR transactions.";

            setStatus("Investigation complete", "is-live");

        } catch (error) {
            console.error("Wallet behaviour investigation failed:", error);
            message.textContent = error.message || "Unable to investigate this wallet.";
            setStatus("Investigation failed", "is-error");

        } finally {
            submitButton.disabled = false;
            submitButton.textContent = "Investigate Wallet Behaviour";
            updateCount();
        }
    });

    addRow();
})();
