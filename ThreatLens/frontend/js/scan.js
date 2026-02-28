/* ===========================================
   scan.js — ThreatLens Scan Functions
   Handles file scan + result routing
=========================================== */

const API = "http://127.0.0.1:5000";

/* ── FILE SCAN ── */
async function scanFile() {
    const fileInput = document.getElementById("fileInput");
    const file = fileInput.files[0];
    if (!file) {
        return alert("Please select a file to scan.");
    }

    const btn = document.querySelector(".card:nth-child(1) .primary-btn");
    showLoading(btn, "Scanning...");

    const form = new FormData();
    form.append("file", file);

    // Attach user ID so scan is saved to their history
    const uid = sessionStorage.getItem("uid");
    if (uid) form.append("user_id", uid);

    try {
        const res  = await fetch(`${API}/api/scan/file`, {
            method: "POST",
            body: form
        });

        const data = await res.json();

        if (data.success) {
            sessionStorage.setItem("scanResult", JSON.stringify(data.result));
            window.location.href = "result.html";
        } else {
            alert(data.message || "Scan failed.");
        }
    } catch (err) {
        alert("Cannot reach server. Make sure the backend is running:\n\ncd backend && python app.py");
    } finally {
        resetBtn(btn, "Submit File");
    }
}

/* ── URL / DOMAIN / IP SCAN — stub, will be activated next phase ── */
function scanURL() {
    const value = document.getElementById("urlInput").value.trim();
    if (!value) return alert("Enter a URL, domain, or IP address.");
    alert("URL/Domain scanning is coming in the next phase!\n\nFor now, try the File Scan or Hash Scan.");
}

/* ── HASH SCAN — stub ── */
function scanHash() {
    const hash = document.getElementById("hashInput").value.trim();
    if (!hash) return alert("Enter an MD5, SHA1, or SHA256 hash.");
    alert("Hash scanning is coming in the next phase!\n\nFor now, try the File Scan.");
}

/* ── HELPERS ── */
function showLoading(btn, text) {
    if (!btn) return;
    btn.disabled = true;
    btn.dataset.original = btn.textContent;
    btn.textContent = text;
}

function resetBtn(btn, fallback) {
    if (!btn) return;
    btn.disabled = false;
    btn.textContent = btn.dataset.original || fallback;
}
