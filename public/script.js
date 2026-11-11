// Suspicious Message Classification - Full-Stack Client Logic

document.addEventListener("DOMContentLoaded", () => {
    // Input & Action Elements
    const messageInput = document.getElementById("messageInput");
    const charCount = document.getElementById("charCount");
    const checkBtn = document.getElementById("checkBtn");
    const clearBtn = document.getElementById("clearBtn");
    const errorBox = document.getElementById("errorBox");

    // Result Card Elements
    const resultSection = document.getElementById("resultSection");
    const resultCategoryBadge = document.getElementById("resultCategoryBadge");
    const resultTitle = document.getElementById("resultTitle");
    const scoreNumber = document.getElementById("scoreNumber");
    const gaugeRing = document.getElementById("gaugeRing");

    const statusBanner = document.getElementById("statusBanner");
    const bannerIcon = document.getElementById("bannerIcon");
    const bannerHeadline = document.getElementById("bannerHeadline");
    const bannerAdvice = document.getElementById("bannerAdvice");

    const detectedCount = document.getElementById("detectedCount");
    const warningsList = document.getElementById("warningsList");
    const reportActionRow = document.getElementById("reportActionRow");
    const reportThisMessageBtn = document.getElementById("reportThisMessageBtn");

    // Telemetry Stats Elements
    const statTotalScanned = document.getElementById("statTotalScanned");
    const statFraudDetected = document.getElementById("statFraudDetected");
    const statSuspicious = document.getElementById("statSuspicious");
    const statSafe = document.getElementById("statSafe");

    // Tab Navigation Elements
    const tabScannerBtn = document.getElementById("tabScannerBtn");
    const tabHistoryBtn = document.getElementById("tabHistoryBtn");
    const scannerTabView = document.getElementById("scannerTabView");
    const historyTabView = document.getElementById("historyTabView");
    const historyTableBody = document.getElementById("historyTableBody");
    const refreshHistoryBtn = document.getElementById("refreshHistoryBtn");

    // Phone Alert Overlay Elements
    const phoneAlertOverlay = document.getElementById("phoneAlertOverlay");
    const alertSnippetText = document.getElementById("alertSnippetText");
    const alertDismissBtn = document.getElementById("alertDismissBtn");
    const alertReportNowBtn = document.getElementById("alertReportNowBtn");

    // Report Scam Modal Elements
    const reportModal = document.getElementById("reportModal");
    const openReportModalBtn = document.getElementById("openReportModalBtn");
    const closeReportModalBtn = document.getElementById("closeReportModalBtn");
    const reportForm = document.getElementById("reportForm");
    const reportSender = document.getElementById("reportSender");
    const reportCategory = document.getElementById("reportCategory");
    const reportMessage = document.getElementById("reportMessage");
    const reportStatusMsg = document.getElementById("reportStatusMsg");

    // Sound toggle state
    let soundEnabled = true;
    const soundToggle = document.getElementById("soundToggle");
    const soundIcon = document.getElementById("soundIcon");

    soundToggle.addEventListener("click", () => {
        soundEnabled = !soundEnabled;
        if (soundEnabled) {
            soundIcon.textContent = "🔔";
            soundToggle.innerHTML = `<span>🔔</span> Sound ON`;
        } else {
            soundIcon.textContent = "🔕";
            soundToggle.innerHTML = `<span>🔕</span> Sound OFF`;
        }
    });

    // Synthesize warning siren using Web Audio API
    function playEmergencyAlertSound() {
        if (!soundEnabled) return;
        try {
            const AudioContext = window.AudioContext || window.webkitAudioContext;
            if (!AudioContext) return;
            const ctx = new AudioContext();

            const osc = ctx.createOscillator();
            const gain = ctx.createGain();

            osc.type = "sawtooth";
            osc.frequency.setValueAtTime(650, ctx.currentTime);
            osc.frequency.linearRampToValueAtTime(880, ctx.currentTime + 0.15);
            osc.frequency.linearRampToValueAtTime(650, ctx.currentTime + 0.3);
            osc.frequency.linearRampToValueAtTime(920, ctx.currentTime + 0.45);
            osc.frequency.linearRampToValueAtTime(650, ctx.currentTime + 0.6);

            gain.gain.setValueAtTime(0.2, ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.7);

            osc.connect(gain);
            gain.connect(ctx.destination);

            osc.start();
            osc.stop(ctx.currentTime + 0.75);
        } catch (e) {
            console.warn("Audio alert failed:", e);
        }
    }

    // Quick Test Scenarios
    const SAMPLES = {
        scam1: "URGENT: Your SBI Bank account has been temporarily locked due to pending KYC verification. Please click here https://sbi-kyc-verify-alert.com/login and submit your Account Number and OTP immediately to avoid permanent deactivation.",
        scam2: "Congratulations! You have WON the International Jackpot Prize of $50,000! Claim your reward now by clicking the link and entering your details immediately.",
        scam3: "Exciting Work From Home Job Offer! Earn $500 daily typing simple data. Just pay a small registration fee of $15 to get started immediately. Click here to pay.",
        safe: "Hi Rahul, are you free for the project discussion tomorrow at 11 AM? Please let me know."
    };

    document.querySelectorAll(".sample-chip").forEach(chip => {
        chip.addEventListener("click", () => {
            const key = chip.getAttribute("data-sample");
            if (SAMPLES[key]) {
                messageInput.value = SAMPLES[key];
                updateCharCount();
                clearError();
            }
        });
    });

    function updateCharCount() {
        charCount.textContent = messageInput.value.length;
    }
    messageInput.addEventListener("input", updateCharCount);

    function showError(msg) {
        errorBox.textContent = msg;
        errorBox.classList.remove("hidden");
    }

    function clearError() {
        errorBox.textContent = "";
        errorBox.classList.add("hidden");
    }

    // Telemetry Statistics Fetcher
    async function fetchTelemetryStats() {
        try {
            const res = await fetch("/api/stats");
            if (res.ok) {
                const stats = await res.json();
                statTotalScanned.textContent = stats.total_scanned;
                statFraudDetected.textContent = stats.fraud_detected;
                statSuspicious.textContent = stats.suspicious_detected;
                statSafe.textContent = stats.safe_messages;
            }
        } catch (e) {
            console.error("Telemetry fetch failed:", e);
        }
    }

    // Fetch and populate backend audit history table
    async function fetchAuditHistory() {
        try {
            historyTableBody.innerHTML = `<tr><td colspan="6" class="empty-state">Loading latest database logs...</td></tr>`;
            const res = await fetch("/api/history?limit=25");
            if (!res.ok) throw new Error("Failed to load logs");
            const data = await res.json();
            const logs = data.history || [];

            if (logs.length === 0) {
                historyTableBody.innerHTML = `<tr><td colspan="6" class="empty-state">No messages analyzed yet. Scan a message to record the first entry!</td></tr>`;
                return;
            }

            historyTableBody.innerHTML = "";
            logs.forEach(item => {
                const tr = document.createElement("tr");

                let badgeClass = "badge-safe";
                if (item.status === "FRAUD") badgeClass = "badge-fraud";
                else if (item.status === "SUSPICIOUS") badgeClass = "badge-suspicious";

                const warningsText = item.warnings && item.warnings.length > 0
                    ? item.warnings.slice(0, 2).join(", ") + (item.warnings.length > 2 ? ` (+${item.warnings.length - 2} more)` : "")
                    : "None (Clean)";

                const snippet = item.message_text.length > 55
                    ? item.message_text.slice(0, 55) + "..."
                    : item.message_text;

                tr.innerHTML = `
                    <td>#${item.id}</td>
                    <td><span class="table-badge ${badgeClass}">${item.status}</span></td>
                    <td><strong>${item.score}</strong>/10</td>
                    <td><code>${escapeHtml(snippet)}</code></td>
                    <td>${escapeHtml(warningsText)}</td>
                    <td style="color: #9ca3af; font-size: 11px;">${item.created_at || 'Just now'}</td>
                `;
                historyTableBody.appendChild(tr);
            });
        } catch (e) {
            historyTableBody.innerHTML = `<tr><td colspan="6" class="empty-state" style="color: #f87171;">Error fetching history from backend database.</td></tr>`;
        }
    }

    function escapeHtml(str) {
        if (!str) return "";
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }

    // Tab Switch Handlers
    tabScannerBtn.addEventListener("click", () => {
        tabScannerBtn.classList.add("active");
        tabHistoryBtn.classList.remove("active");
        scannerTabView.classList.remove("hidden");
        historyTabView.classList.add("hidden");
    });

    tabHistoryBtn.addEventListener("click", () => {
        tabHistoryBtn.classList.add("active");
        tabScannerBtn.classList.remove("active");
        historyTabView.classList.remove("hidden");
        scannerTabView.classList.add("hidden");
        fetchAuditHistory();
    });

    refreshHistoryBtn.addEventListener("click", fetchAuditHistory);

    // Dismiss Alert
    alertDismissBtn.addEventListener("click", () => {
        phoneAlertOverlay.classList.add("hidden");
    });

    alertReportNowBtn.addEventListener("click", () => {
        phoneAlertOverlay.classList.add("hidden");
        openReportWithContent(messageInput.value);
    });

    reportThisMessageBtn.addEventListener("click", () => {
        openReportWithContent(messageInput.value);
    });

    // Phone overlay dismiss on click outside
    phoneAlertOverlay.addEventListener("click", (e) => {
        if (e.target === phoneAlertOverlay) {
            phoneAlertOverlay.classList.add("hidden");
        }
    });

    // Check message action
    async function handleCheckMessage() {
        clearError();
        const text = messageInput.value.trim();

        if (!text) {
            showError("Please paste or type a message to check.");
            messageInput.focus();
            return;
        }

        checkBtn.disabled = true;
        checkBtn.innerHTML = `<span>⏳</span><span>Analyzing...</span>`;

        try {
            const response = await fetch("/api/check", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ message: text })
            });

            const data = await response.json();

            if (!response.ok) {
                showError(data.error || "An error occurred while evaluating the message.");
                return;
            }

            renderResults(data, text);
            // Refresh telemetry stats after scan
            fetchTelemetryStats();
        } catch (err) {
            showError("Could not reach classification backend. Please verify the server is running.");
            console.error(err);
        } finally {
            checkBtn.disabled = false;
            checkBtn.innerHTML = `<span class="btn-icon">🔍</span><span>Check Message</span>`;
        }
    }

    function renderResults(data, originalText) {
        resultSection.classList.remove("hidden");

        const score = data.score || 0;
        const status = data.status || "SAFE";
        const warnings = data.warnings || [];
        const advice = data.advice || "";

        scoreNumber.textContent = score;

        gaugeRing.className = "risk-gauge";
        statusBanner.className = "status-banner";

        warningsList.innerHTML = "";
        detectedCount.textContent = `${warnings.length} Indicator${warnings.length === 1 ? '' : 's'}`;

        if (status === "FRAUD" || score >= 6) {
            gaugeRing.classList.add("gauge-fraud");
            statusBanner.classList.add("banner-fraud");
            resultCategoryBadge.textContent = "CRITICAL THREAT";
            resultCategoryBadge.style.color = "#f87171";
            resultTitle.textContent = "🚨 FRAUD MESSAGE DETECTED";

            bannerIcon.textContent = "🛑";
            bannerHeadline.textContent = "DANGER: HIGH-RISK FRAUD PATTERNS DETECTED";
            bannerAdvice.textContent = advice;
            reportActionRow.classList.remove("hidden");

            // Open Phone Emergency Red Alert
            alertSnippetText.textContent = originalText.length > 90 ? originalText.slice(0, 90) + "..." : originalText;
            phoneAlertOverlay.classList.remove("hidden");
            playEmergencyAlertSound();

        } else if (status === "SUSPICIOUS" || score >= 3) {
            gaugeRing.classList.add("gauge-suspicious");
            statusBanner.classList.add("banner-suspicious");
            resultCategoryBadge.textContent = "ELEVATED RISK";
            resultCategoryBadge.style.color = "#fbbf24";
            resultTitle.textContent = "⚠️ SUSPICIOUS MESSAGE DETECTED";

            bannerIcon.textContent = "⚠️";
            bannerHeadline.textContent = "WARNING: SUSPICIOUS PATTERNS DETECTED";
            bannerAdvice.textContent = advice;
            reportActionRow.classList.remove("hidden");

            // Trigger Phone Red Alert Modal as user instructed
            alertSnippetText.textContent = originalText.length > 90 ? originalText.slice(0, 90) + "..." : originalText;
            phoneAlertOverlay.classList.remove("hidden");
            playEmergencyAlertSound();

        } else {
            gaugeRing.classList.add("gauge-safe");
            statusBanner.classList.add("banner-safe");
            resultCategoryBadge.textContent = "LOW RISK";
            resultCategoryBadge.style.color = "#34d399";
            resultTitle.textContent = "✅ MESSAGE APPEARS SAFE";

            bannerIcon.textContent = "🛡️";
            bannerHeadline.textContent = "CLEAN: NO THREAT SIGNALS DETECTED";
            bannerAdvice.textContent = advice;
            reportActionRow.classList.add("hidden");

            phoneAlertOverlay.classList.add("hidden");
        }

        // Populate warnings list
        if (warnings.length > 0) {
            warnings.forEach(warn => {
                const li = document.createElement("li");
                li.innerHTML = `<span>⚠️</span><span>${escapeHtml(warn)}</span>`;
                warningsList.appendChild(li);
            });
        } else {
            const li = document.createElement("li");
            li.className = "safe-item";
            li.innerHTML = `<span>✔️</span><span>No phishing, fake payment, OTP, or scam patterns found in text.</span>`;
            warningsList.appendChild(li);
        }

        resultSection.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    // Clear action
    clearBtn.addEventListener("click", () => {
        messageInput.value = "";
        updateCharCount();
        clearError();
        resultSection.classList.add("hidden");
        phoneAlertOverlay.classList.add("hidden");
        messageInput.focus();
    });

    checkBtn.addEventListener("click", handleCheckMessage);

    messageInput.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            handleCheckMessage();
        }
    });

    // Report Scam Modal logic
    function openReportWithContent(text) {
        reportMessage.value = text || "";
        reportStatusMsg.classList.add("hidden");
        reportModal.classList.remove("hidden");
    }

    openReportModalBtn.addEventListener("click", () => {
        openReportWithContent(messageInput.value);
    });

    closeReportModalBtn.addEventListener("click", () => {
        reportModal.classList.add("hidden");
    });

    reportModal.addEventListener("click", (e) => {
        if (e.target === reportModal) {
            reportModal.classList.add("hidden");
        }
    });

    reportForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const msg = reportMessage.value.trim();
        const cat = reportCategory.value;
        const sender = reportSender.value.trim();

        if (!msg) return;

        try {
            const res = await fetch("/api/report", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    message: msg,
                    category: cat,
                    sender_info: sender || "Unknown"
                })
            });

            const data = await res.json();
            if (res.ok) {
                reportStatusMsg.textContent = "✅ Scam message successfully reported and stored in database.";
                reportStatusMsg.className = "report-status success";
                reportStatusMsg.classList.remove("hidden");
                fetchTelemetryStats();
                setTimeout(() => {
                    reportModal.classList.add("hidden");
                }, 1400);
            } else {
                reportStatusMsg.textContent = data.error || "Submission failed.";
                reportStatusMsg.className = "report-status error";
                reportStatusMsg.classList.remove("hidden");
            }
        } catch (err) {
            reportStatusMsg.textContent = "Server communication error.";
            reportStatusMsg.className = "report-status error";
            reportStatusMsg.classList.remove("hidden");
        }
    });

    // Initial load
    fetchTelemetryStats();
});
