import json
from typing import List, Dict, Any

def normalize_severity(sev: Any) -> str:
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
    framework_runs = data if isinstance(data, list) else [data]

    for run in framework_runs:
        if not isinstance(run, dict):
            continue
        
        results = run.get("results", {})
        if not isinstance(results, dict):
            continue

        failed_checks = results.get("failed_checks", [])
        if not isinstance(failed_checks, list):
            continue

        for check in failed_checks:
            if not isinstance(check, dict):
                continue
            
            file_line_range = check.get("file_line_range") or []
            line_str = f"{file_line_range[0]}-{file_line_range[1]}" if len(file_line_range) >= 2 else str(file_line_range[0]) if file_line_range else ""
            
            code_lines = check.get("code_block") or []
            snippet = "\n".join([f"{num}: {line}" for num, line in code_lines]) if isinstance(code_lines, list) else ""

            findings.append({
                "tool": "checkov",
                "repository": repo,
                "title": check.get("check_name") or "Checkov Finding",
                "description": f"Resource {check.get('resource', '')} failed check {check.get('check_id', '')}",
                "severity": normalize_severity(check.get("severity") or check.get("bc_severity") or "MEDIUM"),
                "rule_id": check.get("check_id") or "",
                "file_path": check.get("file_path") or "",
                "line_number": line_str,
                "resource_name": check.get("resource") or "",
                "guideline_url": check.get("guideline") or "",
                "code_snippet": snippet
            })
    return findings

def parse_trivy(data: Any, repo: str) -> List[Dict[str, Any]]:
    findings = []
    if not isinstance(data, dict):
        return findings

    results = data.get("Results") or []
    for res in results:
        if not isinstance(res, dict):
            continue
        target = res.get("Target") or ""

        # 1. Misconfigurations (IaC & Cloud)
        for mis in (res.get("Misconfigurations") or []):
            if not isinstance(mis, dict):
                continue
            
            code_obj = mis.get("Code") or {}
            code_lines = code_obj.get("Lines") if isinstance(code_obj, dict) else []
            snippet = "\n".join([f"{l.get('Number', '')}: {l.get('Content', '')}" for l in code_lines]) if isinstance(code_lines, list) else ""
            
            cause_meta = mis.get("CauseMetadata") or {}
            resource_name = cause_meta.get("Resource") if isinstance(cause_meta, dict) else ""
            
            line_num = str(code_lines[0].get("Number", "")) if isinstance(code_lines, list) and code_lines else ""

            findings.append({
                "tool": "trivy",
                "repository": repo,
                "title": mis.get("Title") or mis.get("ID") or "Trivy Misconfiguration",
                "description": mis.get("Description") or mis.get("Message") or (mis.get("Resolution") if isinstance(mis.get("Resolution"), str) else ""),
                "severity": normalize_severity(mis.get("Severity") or "MEDIUM"),
                "rule_id": mis.get("ID") or mis.get("AVDID") or "",
                "file_path": target,
                "line_number": line_num,
                "resource_name": resource_name,
                "guideline_url": mis.get("PrimaryURL") or f"https://avd.aquasec.com/misconfig/{str(mis.get('ID', '')).lower()}",
                "code_snippet": snippet
            })

        # 2. Vulnerabilities (CVEs)
        for vuln in (res.get("Vulnerabilities") or []):
            if not isinstance(vuln, dict):
                continue
            findings.append({
                "tool": "trivy",
                "repository": repo,
                "title": f"{vuln.get('PkgName', '')} {vuln.get('InstalledVersion', '')} - {vuln.get('VulnerabilityID', '')}",
                "description": vuln.get("Description") or vuln.get("Title") or "",
                "severity": normalize_severity(vuln.get("Severity") or "MEDIUM"),
                "rule_id": vuln.get("VulnerabilityID") or "",
                "file_path": target,
                "line_number": "",
                "resource_name": vuln.get("PkgName") or "",
                "guideline_url": vuln.get("PrimaryURL") or "",
                "code_snippet": f"Fixed Version: {vuln.get('FixedVersion', 'N/A')}"
            })
            
        # 3. Secrets
        for secret in (res.get("Secrets") or []):
            if not isinstance(secret, dict):
                continue
            findings.append({
                "tool": "trivy",
                "repository": repo,
                "title": f"Exposed Secret: {secret.get('Title') or secret.get('RuleID') or 'Secret'}",
                "description": f"Category: {secret.get('Category', '')}",
                "severity": normalize_severity(secret.get("Severity") or "CRITICAL"),
                "rule_id": secret.get("RuleID") or "Secret",
                "file_path": target,
                "line_number": str(secret.get("StartLine") or ""),
                "resource_name": secret.get("Target") or "",
                "guideline_url": "",
                "code_snippet": secret.get("Match") or ""
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
        
        if not isinstance(item, dict):
            continue

        detector = item.get("DetectorName") or item.get("detector_name") or "Secret Detector"
        verified = item.get("Verified") if item.get("Verified") is not None else item.get("verified", False)
        raw = item.get("Raw") or item.get("raw") or ""
        redacted = item.get("Redacted") or item.get("redacted") or ""
        
        src_meta = item.get("SourceMetadata") or {}
        git_meta = src_meta.get("Data", {}).get("Git", {}) if isinstance(src_meta, dict) else {}
        file_path = git_meta.get("file") or item.get("path") or ""
        line_num = str(git_meta.get("line") or "")
        commit = git_meta.get("commit") or ""

        findings.append({
            "tool": "trufflehog",
            "repository": repo,
            "title": f"Leaked Secret: {detector} ({'VERIFIED ACTIVE' if verified else 'Unverified'})",
            "description": f"Commit: {commit}\nVerified: {verified}",
            "severity": "CRITICAL" if verified else "HIGH",
            "rule_id": str(detector),
            "file_path": file_path,
            "line_number": line_num,
            "resource_name": commit,
            "guideline_url": "https://trufflesecurity.com",
            "code_snippet": f"Secret: {redacted or raw}"
        })

    return findings
