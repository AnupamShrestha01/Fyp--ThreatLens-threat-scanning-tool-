"""
backend/threat_intel/virustotal.py
VirusTotal v3 API — full vendor table + file scan
"""
import os
import json
import urllib.request
import urllib.error

VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_BASE    = "https://www.virustotal.com/api/v3"


def _vt_request(endpoint, method="GET", data=None, headers_extra=None):
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not configured"}
    headers = {"x-apikey": VT_API_KEY, "accept": "application/json"}
    if headers_extra:
        headers.update(headers_extra)
    url = VT_BASE + endpoint
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read().decode()
        except: pass
        return {"error": f"HTTP {e.code}: {e.reason}", "body": body}
    except Exception as e:
        return {"error": str(e)}


def _parse_vt_response(result):
    """Parse full VT analysis result into structured vendor table."""
    try:
        attrs  = result["data"]["attributes"]
        stats  = attrs.get("last_analysis_stats", {})
        engines_raw = attrs.get("last_analysis_results", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        total      = sum(stats.values())
        detections = malicious + suspicious

        # Build full vendor table — ALL engines
        vendor_table = []
        for engine_name, engine_data in engines_raw.items():
            category = engine_data.get("category", "undetected")
            result_name = engine_data.get("result") or ""
            method = engine_data.get("method", "")
            version = engine_data.get("engine_version", "")
            vendor_table.append({
                "vendor":   engine_name,
                "category": category,         # malicious / suspicious / undetected / type-unsupported / timeout
                "result":   result_name,
                "method":   method,
                "version":  version,
            })

        # Sort: malicious first, suspicious, then undetected
        order = {"malicious": 0, "suspicious": 1, "type-unsupported": 2, "timeout": 3, "undetected": 4}
        vendor_table.sort(key=lambda x: order.get(x["category"], 5))

        verdict = "Clean"
        if malicious >= 5:   verdict = "Malicious"
        elif malicious >= 1: verdict = "Suspicious"
        elif suspicious >= 3: verdict = "Suspicious"

        # Threat names from flagging engines
        threat_names = list({
            v.get("result") for v in engines_raw.values()
            if v.get("result") and v.get("category") in ("malicious", "suspicious")
        })

        return {
            "engine":        "VirusTotal",
            "status":        "found",
            "verdict":       verdict,
            "detections":    f"{detections}/{total}",
            "malicious":     malicious,
            "suspicious":    suspicious,
            "undetected":    undetected,
            "total_engines": total,
            "threat_names":  threat_names[:8],
            "vendor_table":  vendor_table,      # ← full table for display
            "file_type":     attrs.get("type_description", ""),
            "first_seen":    attrs.get("first_submission_date", ""),
            "last_analysis": attrs.get("last_analysis_date", ""),
            "tags":          attrs.get("tags", []),
        }
    except Exception as e:
        return {"engine": "VirusTotal", "status": "parse_error", "error": str(e)}


def lookup_hash(sha256):
    result = _vt_request(f"/files/{sha256}")
    if "error" in result:
        return {"engine": "VirusTotal", "status": "unavailable", "error": result["error"]}
    return _parse_vt_response(result)


def scan_file_vt(file_data, filename="file"):
    """Hash lookup first, upload if not found."""
    import hashlib
    sha256 = hashlib.sha256(file_data).hexdigest()

    # Try hash lookup first (instant, no quota cost)
    lookup = lookup_hash(sha256)
    if lookup.get("status") == "found":
        return lookup

    if not VT_API_KEY:
        return {"engine": "VirusTotal", "status": "unavailable", "error": "API key not configured"}

    # Upload file
    boundary = "----ThreatLensBoundary7x"
    body  = f'--{boundary}\r\n'.encode()
    body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
    body += b'Content-Type: application/octet-stream\r\n\r\n'
    body += file_data
    body += f'\r\n--{boundary}--\r\n'.encode()

    upload = _vt_request(
        "/files", method="POST", data=body,
        headers_extra={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )

    if "error" in upload:
        return {"engine": "VirusTotal", "status": "upload_failed", "error": upload["error"]}

    analysis_id = upload.get("data", {}).get("id", "")
    if not analysis_id:
        return {"engine": "VirusTotal", "status": "submitted",
                "message": "File submitted. Check back shortly."}

    # Poll for result (up to 4 tries)
    import time
    for _ in range(4):
        time.sleep(8)
        poll = _vt_request(f"/analyses/{analysis_id}")
        status = poll.get("data", {}).get("attributes", {}).get("status", "")
        if status == "completed":
            # Now do hash lookup to get full engine results
            return lookup_hash(sha256)

    return {"engine": "VirusTotal", "status": "pending",
            "message": "Analysis submitted — results pending. Retry in ~1 minute."}
