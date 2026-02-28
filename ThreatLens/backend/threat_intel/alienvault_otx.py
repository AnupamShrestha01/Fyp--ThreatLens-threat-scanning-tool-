"""
backend/threat_intel/alienvault_otx.py
AlienVault OTX — file hash lookup
Free API key: https://otx.alienvault.com
"""
import os, json, urllib.request, urllib.error

OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
OTX_BASE    = "https://otx.alienvault.com/api/v1"

def _otx_get(endpoint):
    if not OTX_API_KEY:
        return {"error": "OTX_API_KEY not configured"}
    try:
        req = urllib.request.Request(
            OTX_BASE + endpoint,
            headers={"X-OTX-API-KEY": OTX_API_KEY, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}

def lookup_file_hash(sha256):
    data = _otx_get(f"/indicators/file/{sha256}/general")
    if "error" in data:
        return {"engine": "AlienVault OTX", "status": "unavailable", "error": data["error"]}

    pulse_info  = data.get("pulse_info", {})
    pulse_count = pulse_info.get("count", 0)
    pulses      = pulse_info.get("pulses", [])

    tags, adversaries, malware_families, threat_names = [], [], [], []
    for p in pulses[:10]:
        tags += p.get("tags", [])
        adv   = p.get("adversary", "")
        if adv: adversaries.append(adv)
        for mf in p.get("malware_families", []):
            n = mf.get("display_name") or mf.get("id", "")
            if n: malware_families.append(n)
        threat_names.append(p.get("name", ""))

    tags             = list(set(tags))[:10]
    adversaries      = list(set(adversaries))[:5]
    malware_families = list(set(malware_families))[:5]
    threat_names     = [t for t in threat_names if t][:5]

    verdict = "Clean"
    if pulse_count >= 5:   verdict = "Malicious"
    elif pulse_count >= 1: verdict = "Suspicious"

    return {
        "engine":           "AlienVault OTX",
        "status":           "found" if pulse_count > 0 else "clean",
        "verdict":          verdict,
        "pulse_count":      pulse_count,
        "threat_names":     threat_names,
        "tags":             tags,
        "adversaries":      adversaries,
        "malware_families": malware_families,
        "pulses": [
            {
                "name":        p.get("name", ""),
                "description": p.get("description", "")[:120],
                "author":      p.get("author_name", ""),
                "created":     p.get("created", "")[:10],
                "tags":        p.get("tags", [])[:5],
            }
            for p in pulses[:5]
        ],
    }
