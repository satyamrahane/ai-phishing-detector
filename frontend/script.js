/**
 * script.js — AI Phishing Detector Frontend Logic
 * ================================================
 * API endpoint: POST http://127.0.0.1:5000/scan
 */

const API_BASE = "http://127.0.0.1:5000";

// In-page scan history (complements server-side /logs)
const scanHistory = [];

// ── Helper: classify score into a severity tier ─────────────────────────────
function getTier(score) {
    if (score <= 40) return "safe";
    if (score <= 70) return "warn";
    return "danger";
}

// ── Helper: pick an emoji icon for each reason string ───────────────────────
function iconForReason(reason) {
    const r = reason.toLowerCase();
    if (r.includes("keyword")) return "🔑";
    if (r.includes("https")) return "🔓";
    if (r.includes("long")) return "📏";
    if (r.includes("subdomain")) return "🌐";
    if (r.includes("registered") ||
        r.includes("domain")) return "📅";
    if (r.includes("ml model") ||
        r.includes("probability")) return "🤖";
    return "⚠️";
}

// ── Helper: human-friendly timestamp ────────────────────────────────────────
function nowTimestamp() {
    return new Date().toLocaleTimeString("en-IN", {
        hour: "2-digit", minute: "2-digit", second: "2-digit"
    });
}

// ── Set scan button loading state ───────────────────────────────────────────
function setLoading(loading) {
    const btn = document.getElementById("scanBtn");
    const icon = document.getElementById("btnIcon");
    const text = document.getElementById("btnText");
    btn.disabled = loading;

    if (loading) {
        icon.outerHTML = `<span id="btnIcon"><span class="spinner"></span></span>`;
        text.textContent = "Scanning…";
    } else {
        document.getElementById("btnIcon").outerHTML = `<span id="btnIcon">🔍</span>`;
        text.textContent = "Scan";
    }
}

// ── Show error ───────────────────────────────────────────────────────────────
function showError(msg) {
    const box = document.getElementById("errorBox");
    box.textContent = "⚠️  " + msg;
    box.style.display = "block";
}

function clearError() {
    const box = document.getElementById("errorBox");
    box.textContent = "";
    box.style.display = "none";
}

// ── Render result card ───────────────────────────────────────────────────────
function renderResult(url, data) {
    const tier = getTier(data.risk_score);
    const labels = { safe: "Safe", warn: "Suspicious", danger: "Phishing" };

    // Show result area
    document.getElementById("resultArea").style.display = "block";

    // Score number
    const scoreEl = document.getElementById("scoreNumber");
    scoreEl.className = `score-number ${tier}`;
    animateNumber(scoreEl, 0, data.risk_score, 700);

    // Status badge
    const badge = document.getElementById("statusBadge");
    badge.textContent = labels[tier];
    badge.className = `badge ${tier}`;

    // Meter bar colours
    const meterColors = {
        safe: "linear-gradient(90deg, #10b981, #34d399)",
        warn: "linear-gradient(90deg, #f59e0b, #fbbf24)",
        danger: "linear-gradient(90deg, #ef4444, #f87171)",
    };

    // Animate meter
    const meterFill = document.getElementById("meterFill");
    meterFill.style.background = meterColors[tier];
    setTimeout(() => {
        meterFill.style.width = data.risk_score + "%";
    }, 50);

    // Scanned URL
    document.getElementById("scannedUrl").textContent = url;

    // Reasons list
    const list = document.getElementById("reasonsList");
    list.innerHTML = "";
    if (!data.reasons || data.reasons.length === 0) {
        const li = document.createElement("li");
        li.innerHTML = `<span class="icon">✅</span> No suspicious signals detected`;
        list.appendChild(li);
    } else {
        data.reasons.forEach((reason, idx) => {
            const li = document.createElement("li");
            li.style.animationDelay = `${idx * 80}ms`;
            li.innerHTML = `<span class="icon">${iconForReason(reason)}</span>${reason}`;
            list.appendChild(li);
        });
    }
}

// ── Animate number counter ───────────────────────────────────────────────────
function animateNumber(el, from, to, duration) {
    const start = performance.now();
    function step(now) {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        el.textContent = Math.round(from + (to - from) * eased);
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

// ── Update history table ─────────────────────────────────────────────────────
function addToHistory(url, data) {
    const tier = getTier(data.risk_score);
    const labels = { safe: "Safe", warn: "Suspicious", danger: "Phishing" };
    const colors = { safe: "var(--safe)", warn: "var(--warn)", danger: "var(--danger)" };

    scanHistory.unshift({ url, data, time: nowTimestamp() });

    // Show history section
    const section = document.getElementById("historySection");
    section.style.display = "block";

    // Count pill
    document.getElementById("historyCount").textContent =
        scanHistory.length + (scanHistory.length === 1 ? " scan" : " scans");

    // Rebuild table rows
    const tbody = document.getElementById("historyBody");
    tbody.innerHTML = "";
    scanHistory.forEach(entry => {
        const t = getTier(entry.data.risk_score);
        const tr = document.createElement("tr");
        tr.innerHTML = `
      <td class="url-cell" title="${entry.url}">${entry.url}</td>
      <td class="score-cell" style="color:${colors[t]}">${entry.data.risk_score}</td>
      <td><span class="badge ${t}">${labels[t]}</span></td>
      <td style="color:var(--muted);font-size:0.78rem">${entry.time}</td>
    `;
        tbody.appendChild(tr);
    });
}

// ── Main scan function ───────────────────────────────────────────────────────
async function scan() {
    const input = document.getElementById("urlInput");
    const url = input.value.trim();

    clearError();

    if (!url) {
        showError("Please enter a URL before scanning.");
        input.focus();
        return;
    }

    setLoading(true);

    try {
        const response = await fetch(`${API_BASE}/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `Server error (${response.status})`);
        }

        const data = await response.json();
        renderResult(url, data);
        addToHistory(url, data);

    } catch (err) {
        if (err.name === "TypeError" && err.message.includes("fetch")) {
            showError(
                "Cannot reach backend at " + API_BASE + ". " +
                "Make sure Flask is running: python backend/app.py"
            );
        } else {
            showError(err.message);
        }
    } finally {
        setLoading(false);
    }
}

// ── Allow Enter key to trigger scan ─────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("urlInput").addEventListener("keydown", (e) => {
        if (e.key === "Enter") scan();
    });
});
