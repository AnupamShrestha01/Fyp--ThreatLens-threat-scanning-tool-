"""
backend/threat_intel/hybrid_analysis.py
Hybrid Analysis (CrowdStrike) — sandbox behavioral analysis
Free API key: https://www.hybrid-analysis.com/signup
"""
import os, json, time, urllib.request, urllib.error, urllib.parse

HA_API_KEY = os.environ.get("HA_API_KEY", "")
HA_BASE    = "https://www.hybrid-analysis.com/api/v2"

def _ha_request(endpoint, method="GET", data=None, is_form=False):
    if not HA_API_KEY:
        return {"error": "HA_API_KEY not configured"}
    headers = {
        "api-key":  HA_API_KEY,
        "User-Agent": "ThreatLens/1.0",
        "Accept":   "application/json",
    }
    if is_form and data:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(data).encode()
    try:
        req = urllib.request.Request(HA_BASE + endpoint, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read().decode()
        except: pass
        return {"error": f"HTTP {e.code}", "body": body}
    except Exception as e:
        return {"error": str(e)}

def lookup_hash_ha(sha256):
    """Quick hash search — instant, no submission needed."""
    result = _ha_request("/search/hash", method="POST",
                         data={"hash": sha256}, is_form=True)
    if "error" in result:
        return {"engine": "Hybrid Analysis", "status": "unavailable", "error": result["error"]}
    if not result or (isinstance(result, list) and len(result) == 0):
        return {"engine": "Hybrid Analysis", "status": "not_found"}

    # Take first result
    r = result[0] if isinstance(result, list) else result
    return _parse_ha_report(r)

def submit_file_ha(file_data, filename):
    """Submit file to sandbox for analysis."""
    if not HA_API_KEY:
        return {"engine": "Hybrid Analysis", "status": "unavailable", "error": "HA_API_KEY not configured"}

    # Try hash lookup first
    import hashlib
    sha256 = hashlib.sha256(file_data).hexdigest()
    quick  = lookup_hash_ha(sha256)
    if quick.get("status") == "found":
        return quick

    # Submit to sandbox (environment 300 = Linux, 120 = Windows 10)
    boundary = "----HABoundary9z"
    body  = f'--{boundary}\r\n'.encode()
    body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
    body += b'Content-Type: application/octet-stream\r\n\r\n'
    body += file_data
    body += f'\r\n--{boundary}\r\n'.encode()
    body += b'Content-Disposition: form-data; name="environment_id"\r\n\r\n110'
    body += f'\r\n--{boundary}--\r\n'.encode()

    headers_extra = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    headers = {
        "api-key": HA_API_KEY,
        "User-Agent": "ThreatLens/1.0",
        "Accept": "application/json",
        **headers_extra
    }
    try:
        req = urllib.request.Request(HA_BASE + "/submit/file", data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            submit_result = json.loads(r.read().decode())
    except Exception as e:
        return {"engine": "Hybrid Analysis", "status": "unavailable", "error": str(e)}

    job_id = submit_result.get("job_id") or submit_result.get("sha256", "")
    if not job_id:
        return {"engine": "Hybrid Analysis", "status": "submitted", "message": "Submitted to sandbox"}

    # Poll for completion
    for _ in range(5):
        time.sleep(10)
        poll = _ha_request(f"/report/{job_id}/summary")
        state = poll.get("state", "")
        if state == "SUCCESS":
            return _parse_ha_report(poll)
        if state == "ERROR":
            break

    return {"engine": "Hybrid Analysis", "status": "pending",
            "message": "Sandbox analysis in progress — check back in 2-3 minutes"}

def _parse_ha_report(r):
    """Parse HA report into structured result."""
    verdict_map = {"malicious": "Malicious", "suspicious": "Suspicious",
                   "no specific threat": "Clean", "whitelisted": "Clean"}
    raw_verdict = (r.get("verdict") or "").lower()
    verdict     = verdict_map.get(raw_verdict, "Clean")

    # Network activity
    network = []
    for host in (r.get("hosts") or [])[:8]:
        network.append({"type": "IP", "value": host})
    for domain in (r.get("domains") or [])[:8]:
        network.append({"type": "Domain", "value": domain})
    for url in (r.get("contacted_urls") or [])[:5]:
        u = url if isinstance(url, str) else url.get("url", "")
        if u: network.append({"type": "URL", "value": u})

    # File activity
    file_activity = []
    for f in (r.get("extracted_files") or [])[:8]:
        name = f if isinstance(f, str) else f.get("name", str(f))
        file_activity.append(name)

    # Process activity
    processes = []
    for p in (r.get("processes") or [])[:8]:
        if isinstance(p, dict):
            processes.append({
                "name":    p.get("name", ""),
                "command": p.get("command_line", "")[:80],
            })
        else:
            processes.append({"name": str(p), "command": ""})

    # Signatures / behaviors
    signatures = []
    for s in (r.get("signatures") or [])[:10]:
        if isinstance(s, dict):
            signatures.append({
                "name":        s.get("name", ""),
                "description": s.get("description", "")[:100],
                "severity":    s.get("threat_level_human", "medium"),
            })

    return {
        "engine":         "Hybrid Analysis",
        "status":         "found",
        "verdict":        verdict,
        "threat_score":   r.get("threat_score", 0),
        "av_detect":      r.get("av_detect", 0),
        "environment":    r.get("environment_description", "Sandbox"),
        "analysis_time":  r.get("analysis_start_time", "")[:19],
        "network":        network,
        "file_activity":  file_activity,
        "processes":      processes,
        "signatures":     signatures,
        "mitre_attcks":   [
            a.get("technique", "") for a in (r.get("mitre_attcks") or [])[:6]
            if isinstance(a, dict)
        ],
        "tags":           (r.get("type_short") or [])[:6],
    }
