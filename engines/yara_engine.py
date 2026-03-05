"""
backend/engines/yara_engine.py

Improved YARA-like scanning engine (pure Python fallback).
Supports:
- String matching
- Regex matching
- Byte pattern matching { 4D 5A }
- any of them
- all of them
- X of them
- $pattern at 0
- Severity scoring
"""

import os
import re
import glob

YARA_DIR = os.path.join(os.path.dirname(__file__), "../../yara_rules")


# -----------------------------
# LOAD YARA RULES
# -----------------------------
def _load_yara_rules(rules_dir: str) -> list:
    rules = []

    for path in glob.glob(os.path.join(rules_dir, "*.yar")):
        try:
            with open(path, "r", errors="replace") as f:
                content = f.read()

            for rule_match in re.finditer(r'rule\s+(\w+)\s*\{(.*?)\}', content, re.DOTALL):
                rule_name = rule_match.group(1)
                rule_body = rule_match.group(2)

                desc_m = re.search(r'description\s*=\s*"([^"]+)"', rule_body)
                sev_m = re.search(r'severity\s*=\s*"([^"]+)"', rule_body)

                description = desc_m.group(1) if desc_m else rule_name
                severity = sev_m.group(1) if sev_m else "medium"

                patterns = []

                strings_section = re.search(r'strings:(.*?)condition:', rule_body, re.DOTALL)
                if strings_section:
                    for line in strings_section.group(1).splitlines():
                        line = line.strip()

                        # BYTE pattern { 4D 5A }
                        m = re.match(r'\$\w+\s*=\s*\{([0-9A-Fa-f\s]+)\}', line)
                        if m:
                            hex_pattern = m.group(1).replace(" ", "")
                            patterns.append({
                                "type": "bytes",
                                "pattern": hex_pattern
                            })
                            continue

                        # REGEX pattern /pattern/ nocase
                        m = re.match(r'\$\w+\s*=\s*/([^/]+)/(\s*nocase)?', line)
                        if m:
                            patterns.append({
                                "type": "regex",
                                "pattern": m.group(1),
                                "nocase": bool(m.group(2))
                            })
                            continue

                        # STRING pattern "value" nocase
                        m = re.match(r'\$\w+\s*=\s*"([^"]+)"(\s*nocase)?', line)
                        if m:
                            patterns.append({
                                "type": "string",
                                "pattern": m.group(1),
                                "nocase": bool(m.group(2))
                            })

                condition_match = re.search(r'condition:(.*?)$', rule_body, re.DOTALL)
                condition_raw = condition_match.group(1).strip() if condition_match else ""

                rules.append({
                    "name": rule_name,
                    "description": description,
                    "severity": severity.lower(),
                    "patterns": patterns,
                    "condition_raw": condition_raw
                })

        except Exception:
            continue

    return rules


# -----------------------------
# MATCH RULE
# -----------------------------
def _match_rule(rule: dict, data: bytes) -> bool:
    matched_patterns = []

    for p in rule["patterns"]:
        try:
            # BYTE MATCH
            if p["type"] == "bytes":
                byte_seq = bytes.fromhex(p["pattern"])
                if byte_seq in data:
                    matched_patterns.append(p)

            # STRING MATCH (binary safe)
            elif p["type"] == "string":
                needle = p["pattern"].encode()
                if p.get("nocase"):
                    if needle.lower() in data.lower():
                        matched_patterns.append(p)
                else:
                    if needle in data:
                        matched_patterns.append(p)

            # REGEX MATCH
            elif p["type"] == "regex":
                text = data.decode("utf-8", errors="ignore")
                flags = re.IGNORECASE if p.get("nocase") else 0
                if re.search(p["pattern"], text, flags):
                    matched_patterns.append(p)

        except Exception:
            continue

    matched_count = len(matched_patterns)
    total_patterns = len(rule["patterns"])
    cond = rule.get("condition_raw", "").lower()

    # CONDITION HANDLING

    if "any of them" in cond:
        return matched_count >= 1

    if "all of them" in cond:
        return matched_count == total_patterns

    m = re.search(r'(\d+)\s+of\s+them', cond)
    if m:
        return matched_count >= int(m.group(1))

    # $pattern at 0
    m = re.search(r'\$(\w+)\s+at\s+0', cond)
    if m:
        pattern_name = m.group(1)
        for p in rule["patterns"]:
            if p["type"] == "string":
                if data.startswith(p["pattern"].encode()):
                    return True
            elif p["type"] == "bytes":
                byte_seq = bytes.fromhex(p["pattern"])
                if data.startswith(byte_seq):
                    return True
        return False

    # Default
    return matched_count >= 1


# -----------------------------
# MAIN SCAN FUNCTION
# -----------------------------
def scan_with_yara(file_data: bytes) -> dict:
    rules = _load_yara_rules(YARA_DIR)
    matches = []
    risk_score = 0

    for rule in rules:
        if _match_rule(rule, file_data):
            matches.append({
                "rule": rule["name"],
                "description": rule["description"],
                "severity": rule["severity"],
            })

            # Severity scoring
            if rule["severity"] == "high":
                risk_score += 50
            elif rule["severity"] == "medium":
                risk_score += 25
            else:
                risk_score += 10

    if risk_score >= 50:
        verdict = "Malicious"
    elif risk_score > 0:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    return {
        "engine": "YARA Fallback Engine",
        "rules_loaded": len(rules),
        "matches": matches,
        "matched_count": len(matches),
        "risk_score": risk_score,
        "verdict": verdict,
    }