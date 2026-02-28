"""
backend/services/file_service.py
Orchestrates multi-engine file scanning and aggregates results.
4 engines: Static Analysis, YARA, VirusTotal, AlienVault OTX, Hybrid Analysis
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

from backend.engines.static_analysis import analyze_file
from backend.engines.yara_engine import scan_with_yara
from backend.threat_intel.virustotal import scan_file_vt
from backend.threat_intel.alienvault_otx import lookup_file_hash as otx_lookup
from backend.threat_intel.hybrid_analysis import submit_file_ha


def scan_file(file_data: bytes, filename: str = "", user_id: int = None) -> dict:

    # ── Engine 1: Static Analysis ────────────────────────────────────────
    static = analyze_file(file_data, filename)
    sha256 = static.get("hashes", {}).get("sha256", "")

    # ── Engine 2: YARA Rules ─────────────────────────────────────────────
    yara = scan_with_yara(file_data)

    # ── Engine 3: VirusTotal ─────────────────────────────────────────────
    vt = scan_file_vt(file_data, filename)

    # ── Engine 4: AlienVault OTX ─────────────────────────────────────────
    otx = otx_lookup(sha256) if sha256 else {"engine": "AlienVault OTX", "status": "unavailable"}

    # ── Engine 5: Hybrid Analysis ────────────────────────────────────────
    ha = submit_file_ha(file_data, filename)

    # ── Aggregate Verdict ────────────────────────────────────────────────
    scores = {"Clean": 0, "Potentially Unwanted": 1, "Suspicious": 2, "Malicious": 3}

    active_verdicts = [
        static.get("verdict", "Clean"),
        yara.get("verdict", "Clean"),
    ]
    # Only count API engines if they returned real results
    for engine in [vt, otx, ha]:
        if engine.get("status") not in ("unavailable", "pending", "submitted", "not_found", "clean"):
            active_verdicts.append(engine.get("verdict", "Clean"))

    final_verdict = max(active_verdicts, key=lambda v: scores.get(v, 0))

    # ── Threat Score ─────────────────────────────────────────────────────
    threat_score = static.get("threat_score", 0)

    # YARA: +25 per matched rule
    if yara.get("matched_count", 0) > 0:
        threat_score = min(threat_score + 25 * yara["matched_count"], 100)

    # VT: if 5+ engines flag it, minimum 85
    if vt.get("malicious", 0) >= 5:
        threat_score = max(threat_score, 85)
    elif vt.get("malicious", 0) >= 1:
        threat_score = max(threat_score, 40)

    # OTX: pulse count boosts score
    pulse_count = otx.get("pulse_count", 0)
    if pulse_count >= 5:   threat_score = max(threat_score, 80)
    elif pulse_count >= 1: threat_score = max(threat_score, 35)

    # Hybrid Analysis: if sandbox says malicious, minimum 75
    if ha.get("verdict") == "Malicious":
        threat_score = max(threat_score, 75)
    elif ha.get("verdict") == "Suspicious":
        threat_score = max(threat_score, 45)

    threat_score = min(int(threat_score), 100)

    risk_map = {
        "Clean": "Low", "Potentially Unwanted": "Medium",
        "Suspicious": "High", "Malicious": "Critical"
    }
    final_risk = risk_map.get(final_verdict, "Low")

    # ── Detection Flags ──────────────────────────────────────────────────
    all_flags = list(static.get("flags", []))

    for m in yara.get("matches", []):
        all_flags.append(f"[YARA] {m['rule']}: {m['description']}")

    if vt.get("threat_names"):
        all_flags.append(f"[VirusTotal] Threat: {', '.join(vt['threat_names'][:3])}")

    if otx.get("pulse_count", 0) > 0:
        all_flags.append(f"[OTX] Referenced in {otx['pulse_count']} threat intelligence pulse(s)")
    if otx.get("malware_families"):
        all_flags.append(f"[OTX] Malware family: {', '.join(otx['malware_families'][:3])}")
    if otx.get("adversaries"):
        all_flags.append(f"[OTX] Known adversary: {', '.join(otx['adversaries'][:2])}")

    if ha.get("verdict") in ("Malicious", "Suspicious"):
        all_flags.append(f"[Sandbox] Behavioral verdict: {ha['verdict']}")
    if ha.get("network"):
        all_flags.append(f"[Sandbox] Network activity detected: {len(ha['network'])} connection(s)")
    if ha.get("signatures"):
        all_flags.append(f"[Sandbox] {len(ha['signatures'])} behavioral signature(s) matched")

    # ── Final Result ─────────────────────────────────────────────────────
    return {
        "filename":    filename,
        "file_size":   len(file_data),
        "file_type":   static.get("file_type", "Unknown"),
        "hashes":      static.get("hashes", {}),
        "entropy":     static.get("entropy", 0),
        "verdict":     final_verdict,
        "risk":        final_risk,
        "threat_score": threat_score,
        "flags":       all_flags,
        "engines": {
            "static_analysis": static,
            "yara":            yara,
            "virustotal":      vt,
            "otx":             otx,
            "hybrid_analysis": ha,
        },
        "summary": {
            "total_engines":  5,
            "yara_matches":   yara.get("matched_count", 0),
            "vt_detections":  vt.get("detections", "N/A"),
            "otx_pulses":     otx.get("pulse_count", 0),
            "ha_verdict":     ha.get("verdict", "N/A"),
        }
    }
