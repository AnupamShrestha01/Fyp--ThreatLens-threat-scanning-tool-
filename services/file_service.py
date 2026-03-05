"""
backend/services/file_service.py
4 engines: Static Analysis, YARA, VirusTotal (+ VT Behavior), AlienVault OTX
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

from backend.engines.static_analysis import analyze_file
from backend.engines.yara_engine import scan_with_yara
from backend.threat_intel.virustotal import scan_file_vt
from backend.threat_intel.alienvault_otx import lookup_file_hash as otx_lookup


def scan_file(file_data: bytes, filename: str = "", user_id: int = None) -> dict:

    # ── Engine 1: Static Analysis ─────────────────────────────────────────
    try:
        static = analyze_file(file_data, filename)
    except Exception as e:
        static = {"engine": "Static Analysis", "status": "error", "error": str(e),
                  "verdict": "Clean", "threat_score": 0, "flags": [], "hashes": {}, "entropy": 0, "file_type": "Unknown"}

    sha256 = static.get("hashes", {}).get("sha256", "")

    # ── Engine 2: YARA Rules ──────────────────────────────────────────────
    try:
        yara = scan_with_yara(file_data)
    except Exception as e:
        yara = {"engine": "YARA", "status": "error", "error": str(e),
                "verdict": "Clean", "matched_count": 0, "matches": []}

    # ── Engine 3: VirusTotal + Behavior ──────────────────────────────────
    try:
        vt = scan_file_vt(file_data, filename)
    except Exception as e:
        vt = {"engine": "VirusTotal", "status": "unavailable", "error": str(e)}

    # Always pop behavior safely — vt may or may not have it
    behavior = vt.pop("behavior", None) if isinstance(vt, dict) else None
    if not behavior:
        behavior = {"engine": "VT Behavior", "status": "not_found"}

    # ── Engine 4: AlienVault OTX ──────────────────────────────────────────
    try:
        otx = otx_lookup(sha256) if sha256 else {"engine": "AlienVault OTX", "status": "unavailable"}
    except Exception as e:
        otx = {"engine": "AlienVault OTX", "status": "unavailable", "error": str(e)}

    # ── Aggregate Verdict ─────────────────────────────────────────────────
    scores = {"Clean": 0, "Potentially Unwanted": 1, "Suspicious": 2, "Malicious": 3}
    active_verdicts = [
        static.get("verdict", "Clean"),
        yara.get("verdict", "Clean"),
    ]
    for engine in [vt, otx, behavior]:
        if not isinstance(engine, dict): continue
        if engine.get("status") not in ("unavailable", "pending", "submitted", "not_found", "clean", "error"):
            v = engine.get("verdict", "Clean")
            if v in scores:
                active_verdicts.append(v)

    final_verdict = max(active_verdicts, key=lambda v: scores.get(v, 0))

    # ── Threat Score ──────────────────────────────────────────────────────
    threat_score = static.get("threat_score", 0)
    if yara.get("matched_count", 0) > 0:
        threat_score = min(threat_score + 25 * yara["matched_count"], 100)
    if vt.get("malicious", 0) >= 5:
        threat_score = max(threat_score, 85)
    elif vt.get("malicious", 0) >= 1:
        threat_score = max(threat_score, 40)
    pulse_count = otx.get("pulse_count", 0)
    if pulse_count >= 5:   threat_score = max(threat_score, 80)
    elif pulse_count >= 1: threat_score = max(threat_score, 35)
    if behavior.get("verdict") == "Malicious":
        threat_score = max(threat_score, 75)
    elif behavior.get("verdict") == "Suspicious":
        threat_score = max(threat_score, 45)
    threat_score = min(int(threat_score), 100)

    risk_map = {"Clean": "Low", "Potentially Unwanted": "Medium",
                "Suspicious": "High", "Malicious": "Critical"}
    final_risk = risk_map.get(final_verdict, "Low")

    # ── Detection Flags ───────────────────────────────────────────────────
    all_flags = list(static.get("flags", []))
    for m in (yara.get("matches") or []):
        if isinstance(m, dict):
            all_flags.append(f"[YARA] {m.get('rule','')}: {m.get('description','')}")
    if vt.get("threat_names"):
        all_flags.append(f"[VirusTotal] Threat: {', '.join(vt['threat_names'][:3])}")
    if otx.get("pulse_count", 0) > 0:
        all_flags.append(f"[OTX] Referenced in {otx['pulse_count']} threat intelligence pulse(s)")
    if otx.get("malware_families"):
        all_flags.append(f"[OTX] Malware family: {', '.join(otx['malware_families'][:3])}")
    if otx.get("adversaries"):
        all_flags.append(f"[OTX] Known adversary: {', '.join(otx['adversaries'][:2])}")
    if behavior.get("verdict") in ("Malicious", "Suspicious"):
        all_flags.append(f"[Sandbox] Behavioral verdict: {behavior['verdict']}")
    if behavior.get("network"):
        all_flags.append(f"[Sandbox] Network activity: {len(behavior['network'])} connection(s)")
    if behavior.get("signatures"):
        all_flags.append(f"[Sandbox] {len(behavior['signatures'])} behavioral tag(s) found")
    if behavior.get("mitre_attcks"):
        all_flags.append(f"[Sandbox] MITRE ATT&CK: {', '.join(behavior['mitre_attcks'][:3])}")

    return {
        "filename":     filename,
        "file_size":    len(file_data),
        "file_type":    static.get("file_type", "Unknown"),
        "hashes":       static.get("hashes", {}),
        "entropy":      static.get("entropy", 0),
        "verdict":      final_verdict,
        "risk":         final_risk,
        "threat_score": threat_score,
        "flags":        all_flags,
        "engines": {
            "static_analysis": static,
            "yara":            yara,
            "virustotal":      vt,
            "otx":             otx,
            "behavior":        behavior,
        },
        "summary": {
            "total_engines": 4,
            "yara_matches":  yara.get("matched_count", 0),
            "vt_detections": vt.get("detections", "N/A"),
            "otx_pulses":    otx.get("pulse_count", 0),
        }
    }
