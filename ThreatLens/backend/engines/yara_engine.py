"""
backend/engines/yara_engine.py
YARA rule scanning with pure Python fallback (no yara-python dependency).
Parses .yar files and matches string/regex conditions manually.
"""
import os
import re
import glob

YARA_DIR = os.path.join(os.path.dirname(__file__), "../../yara_rules")


def _load_yara_rules(rules_dir: str) -> list:
    """Load and parse .yar rule files into dicts."""
    rules = []
    for path in glob.glob(os.path.join(rules_dir, "*.yar")):
        try:
            with open(path, "r", errors="replace") as f:
                content = f.read()
            # Very basic YARA parser — extracts rule name, strings, severity
            for rule_match in re.finditer(
                r'rule\s+(\w+)\s*\{(.*?)\}', content, re.DOTALL
            ):
                rule_name = rule_match.group(1)
                rule_body = rule_match.group(2)

                # Get meta description
                desc_m = re.search(r'description\s*=\s*"([^"]+)"', rule_body)
                sev_m  = re.search(r'severity\s*=\s*"([^"]+)"', rule_body)
                description = desc_m.group(1) if desc_m else rule_name
                severity    = sev_m.group(1) if sev_m else "medium"

                # Get strings section
                strings_section = re.search(r'strings:(.*?)condition:', rule_body, re.DOTALL)
                patterns = []
                if strings_section:
                    for line in strings_section.group(1).splitlines():
                        line = line.strip()
                        # Handle regex patterns: /pattern/  nocase
                        m = re.match(r'\$\w+\s*=\s*/([^/]+)/(\s*nocase)?', line)
                        if m:
                            pat = m.group(1)
                            nocase = bool(m.group(2))
                            patterns.append({"type": "regex", "pattern": pat, "nocase": nocase})
                            continue
                        # Handle plain strings: "value"  nocase
                        m = re.match(r'\$\w+\s*=\s*"([^"]+)"(\s*nocase)?', line)
                        if m:
                            patterns.append({"type": "string", "pattern": m.group(1), "nocase": bool(m.group(2))})

                rules.append({
                    "name": rule_name,
                    "description": description,
                    "severity": severity,
                    "patterns": patterns,
                    "condition_raw": re.search(r'condition:(.*?)$', rule_body, re.DOTALL).group(1).strip() if re.search(r'condition:(.*?)$', rule_body, re.DOTALL) else ""
                })
        except Exception:
            pass
    return rules


def _match_rule(rule: dict, data: bytes) -> bool:
    """Check if data matches a YARA rule (simplified condition: any 2 patterns)."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = ""

    matched = 0
    for p in rule["patterns"]:
        try:
            if p["type"] == "regex":
                flags = re.IGNORECASE if p["nocase"] else 0
                if re.search(p["pattern"], text, flags):
                    matched += 1
            else:
                needle = p["pattern"]
                if p["nocase"]:
                    if needle.lower() in text.lower():
                        matched += 1
                else:
                    if needle in text or needle.encode() in data:
                        matched += 1
        except Exception:
            pass

    cond = rule.get("condition_raw", "").lower()
    # Simplified condition evaluation
    if "any of them" in cond:
        return matched >= 1
    m = re.search(r'(\d+)\s+of\s+them', cond)
    if m:
        return matched >= int(m.group(1))
    # Default: at least 1 match
    return matched >= 1


def scan_with_yara(file_data: bytes) -> dict:
    """Scan file bytes against all YARA rules. Returns results dict."""
    rules = _load_yara_rules(YARA_DIR)
    matches = []

    for rule in rules:
        if _match_rule(rule, file_data):
            matches.append({
                "rule": rule["name"],
                "description": rule["description"],
                "severity": rule["severity"],
            })

    return {
        "engine": "YARA Engine",
        "rules_loaded": len(rules),
        "matches": matches,
        "matched_count": len(matches),
        "verdict": "Malicious" if matches else "Clean",
    }
