import json
from typing import List, Dict, Any

def normalize_severity(sev: str) -> str:
    if not sev:
        return "MEDIUM"
    s = str(sev).strip().upper()
    if "CRIT" in s:
        return "CRITICAL"
    if "HIGH" in s:
        return "HIGH"
    if "MED" in s:
        return "MEDIUM"
    if "LOW" in s:
        return "LOW"
    return "INFO"

def parse_checkov(data: Any, repo: str) -> List[Dict[str, Any]]:
    findings = []
    
    # Checkov can output a single dict or a list of dicts (multi-framework)
    framework_runs = data if isinstance(data, list) else [data]

    for run in framework_runs:
        if not isinstance(run, dict):
            continue
        
        results = run.get("results", {})
        failed_checks = results.get("failed_checks", [])

        for check in failed_checks:
            file_line_range = check.get("file_line_range", [])
            line_str = f"{file_line_range[0]}-{file_line_range[1]}" if len(file_line_range) >= 2 else str(file_line_range[0]) if file_line_range else ""
            
            code_lines = check.get("code_block", [])
            snippet = "\n".join([f"{num}: {line}" for num, line in code_lines]) if code_lines else ""

            findings.append({
                "tool": "checkov",
                "repository": repo,
                "title": check.get("check_name", "Checkov Finding"),
                "description": f"Resource {check.get('resource', '')} failed check {check.get('check_id', '')}",
                "severity": normalize_severity(check.get("severity") or check.get("bc_severity") or "MEDIUM"),
                "rule_id": check.get("check_id", ""),
                "file_path": check.get("file_path", ""),
                "line_number": line_str,
                "resource_name": check.get("resource", ""),
                "guideline_url": check.get("guideline", ""),
                "code_snippet": snippet
            })
    return findings

def parse_trivy(data: Any, repo: str) -> List[Dict[str, Any]]:
    findings = []
    if not isinstance(data, dict):
        return findings

    results = data.get("Results", [])
    for res in results:
        target = res.get("Target", "")

        # 1. Misconfigurations (IaC & Cloud)
        for mis in res.get("Misconfigurations", []):
            code_lines = mis.get("Code", {}).get("Lines", [])
            snippet = "\n".join([f"{l.get('Number', '')}: {l.get('Content', '')}" for l in code_lines]) if code_lines else ""

            findings.append({
                "tool": "trivy",
                "repository": repo,
                "title": mis.get("Title", mis.get("ID", "Trivy Misconfiguration")),
                "description": mis.get("Description", mis.get("Message", "")),
                "severity": normalize_severity(mis.get("Severity", "MEDIUM")),
                "rule_id": mis.get("ID", mis.get("AVDID", "")),
                "file_path": target,
                "line_number": str(mis.get("Resolution", {}).get("StartLine", "") or (code_lines[0].get("Number") if code_lines else "")),
                "resource_name": mis.get("Resolution", {}).get("Resource", ""),
                "guideline_url": mis.get("PrimaryURL", f"https://avd.aquasec.com/misconfig/{mis.get('ID', '').lower()}"),
                "code_snippet": snippet
            })

        # 2. Vulnerabilities (CVEs)
        for vuln in res.get("Vulnerabilities", []):
            findings.append({
                "tool": "trivy",
                "repository": repo,
                "title": f"{vuln.get('PkgName', '')} {vuln.get('InstalledVersion', '')} - {vuln.get('VulnerabilityID', '')}",
                "description": vuln.get("Description", vuln.get("Title", "")),
                "severity": normalize_severity(vuln.get("Severity", "MEDIUM")),
                "rule_id": vuln.get("VulnerabilityID", ""),
                "file_path": target,
                "line_number": "",
                "resource_name": vuln.get("PkgName", ""),
                "guideline_url": vuln.get("PrimaryURL", ""),
                "code_snippet": f"Fixed Version: {vuln.get('FixedVersion', 'N/A')}"
            })
            
        # 3. Secrets (Trivy secret scanning)
        for secret in res.get("Secrets", []):
            findings.append({
                "tool": "trivy",
                "repository": repo,
                "title": f"Exposed Secret: {secret.get('Title', secret.get('RuleID', 'Secret'))}",
                "description": f"Category: {secret.get('Category', '')}",
                "severity": normalize_severity(secret.get("Severity", "CRITICAL")),
                "rule_id": secret.get("RuleID", "Secret"),
                "file_path": target,
                "line_number": str(secret.get("StartLine", "")),
                "resource_name": secret.get("Target", ""),
                "guideline_url": "",
                "code_snippet": secret.get("Match", "")
            })

    return findings

def parse_trufflehog(raw_content: str, repo: str) -> List[Dict[str, Any]]:
    findings = []
    lines = raw_content.strip().split("\n")
    
    for line in lines:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        
        detector = item.get("DetectorName", item.get("detector_name", "Secret Detector"))
        verified = item.get("Verified", item.get("verified", False))
        raw = item.get("Raw", item.get("raw", ""))
        redacted = item.get("Redacted", item.get("redacted", ""))
        
        src_meta = item.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
        file_path = src_meta.get("file", item.get("path", ""))
        line_num = str(src_meta.get("line", ""))
        commit = src_meta.get("commit", "")

        findings.append({
            "tool": "trufflehog",
            "repository": repo,
            "title": f"Leaked Secret: {detector} ({'VERIFIED ACTIVE' if verified else 'Unverified'})",
            "description": f"Commit: {commit}\nVerified: {verified}",
            "severity": "CRITICAL" if verified else "HIGH",
            "rule_id": detector,
            "file_path": file_path,
            "line_number": line_num,
            "resource_name": commit,
            "guideline_url": "https://trufflesecurity.com",
            "code_snippet": f"Secret: {redacted or raw}"
        })

    return findings
