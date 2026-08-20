import json
import os
import shutil
import tempfile
import subprocess
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional, List
import requests
from fastapi import FastAPI, Depends, UploadFile, File, Form, HTTPException, Request, BackgroundTasks, Body
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text, case

from .database import init_db, get_db, Scan, Finding, engine
from .parsers import parse_checkov, parse_trivy, parse_trufflehog, parse_gitleaks

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="DefectDojo Lite - DevSecOps Portal", version="2.0.0", lifespan=lifespan)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(BASE_DIR, "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

def normalize_repo_name(name: str) -> str:
    if not name:
        return "unknown"
    n = name.strip().rstrip("/").split("/")[-1].replace(".git", "")
    if n == "tf-essential-module":
        return "tf-essentials-module"
    return n

@app.get("/api/health")
def health():
    db_status = "connected"
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"error: {str(e)}"

    return {
        "status": "ok",
        "database": db_status,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/upload")
async def upload_scan(
    file: UploadFile = File(...),
    tool: str = Form(...), # checkov, trivy, trufflehog, gitleaks
    repository: str = Form(...),
    branch: Optional[str] = Form("main"),
    commit_sha: Optional[str] = Form(""),
    db: Session = Depends(get_db)
):
    tool = tool.lower().strip()
    repository = normalize_repo_name(repository)

    valid_tools = ["checkov", "trivy", "trufflehog", "gitleaks"]
    if tool not in valid_tools:
        raise HTTPException(status_code=400, detail=f"Supported tools: {', '.join(valid_tools)}")

    content_bytes = await file.read()
    content_str = content_bytes.decode("utf-8", errors="ignore")

    raw_findings = []
    if tool == "checkov":
        try:
            data = json.loads(content_str)
            raw_findings = parse_checkov(data, repository)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse Checkov JSON: {str(e)}")
    elif tool == "trivy":
        try:
            data = json.loads(content_str)
            raw_findings = parse_trivy(data, repository)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse Trivy JSON: {str(e)}")
    elif tool == "trufflehog":
        raw_findings = parse_trufflehog(content_str, repository)
    elif tool == "gitleaks":
        try:
            data = json.loads(content_str)
            raw_findings = parse_gitleaks(data, repository)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse Gitleaks JSON: {str(e)}")

    # Deactivate previous active findings for this (repo, tool)
    db.query(Finding).filter(
        Finding.repository == repository,
        Finding.tool == tool,
        Finding.is_active == True
    ).update({"is_active": False})

    # Count severities
    crit = sum(1 for f in raw_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in raw_findings if f["severity"] == "HIGH")
    med = sum(1 for f in raw_findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in raw_findings if f["severity"] == "LOW")

    # Create Scan Record
    scan = Scan(
        tool=tool,
        repository=repository,
        branch=branch or "main",
        commit_sha=commit_sha or "",
        status="COMPLETED",
        triggered_by="CI",
        total_findings=len(raw_findings),
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        created_at=datetime.utcnow()
    )
    db.add(scan)
    db.flush()

    # Bulk insert new active findings
    finding_objs = [
        Finding(
            scan_id=scan.id,
            tool=f["tool"],
            repository=f["repository"],
            title=f["title"],
            description=f["description"],
            severity=f["severity"],
            rule_id=f["rule_id"],
            file_path=f["file_path"],
            line_number=f["line_number"],
            resource_name=f["resource_name"],
            guideline_url=f["guideline_url"],
            code_snippet=f["code_snippet"],
            status="ACTIVE",
            is_active=True,
            created_at=datetime.utcnow()
        )
        for f in raw_findings
    ]
    if finding_objs:
        db.add_all(finding_objs)

    db.commit()
    return {
        "status": "success",
        "scan_id": scan.id,
        "tool": tool,
        "repository": repository,
        "total_findings": len(raw_findings),
        "critical": crit,
        "high": high,
        "medium": med,
        "low": low
    }

class TriggerGithubScanRequest(BaseModel):
    owner: str = "PipeOpsHQ"
    repository: str
    branch: str = "main"
    workflow_id: str = "security-scan.yml"
    github_token: Optional[str] = None

@app.post("/api/scans/trigger-github")
def trigger_github_workflow(req: TriggerGithubScanRequest, db: Session = Depends(get_db)):
    """Triggers GitHub Actions workflow via workflow_dispatch API."""
    token = req.github_token or os.getenv("GITHUB_TOKEN")
    if not token:
        raise HTTPException(
            status_code=400, 
            detail="GitHub Token is required. Set GITHUB_TOKEN env var or provide it in request."
        )

    url = f"https://api.github.com/repos/{req.owner}/{req.repository}/actions/workflows/{req.workflow_id}/dispatches"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    payload = {"ref": req.branch}

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=10)
        if resp.status_code == 204:
            scan = Scan(
                tool="all",
                repository=normalize_repo_name(req.repository),
                branch=req.branch,
                status="RUNNING",
                triggered_by="GITHUB_DISPATCH",
                logs=f"Triggered workflow {req.workflow_id} on branch {req.branch}",
                created_at=datetime.utcnow()
            )
            db.add(scan)
            db.commit()

            return {
                "status": "success",
                "message": f"Successfully triggered {req.workflow_id} on {req.owner}/{req.repository} ({req.branch})",
                "scan_id": scan.id
            }
        else:
            raise HTTPException(status_code=resp.status_code, detail=f"GitHub API Error: {resp.text}")
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Failed to reach GitHub API: {str(e)}")

class UpdateFindingStatusRequest(BaseModel):
    status: str # ACTIVE, MITIGATED, FALSE_POSITIVE, RISK_ACCEPTED
    notes: Optional[str] = ""

@app.patch("/api/findings/{finding_id}/status")
def update_finding_status(finding_id: int, req: UpdateFindingStatusRequest, db: Session = Depends(get_db)):
    valid_statuses = ["ACTIVE", "MITIGATED", "FALSE_POSITIVE", "RISK_ACCEPTED"]
    new_status = req.status.upper().strip()
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Choose from: {valid_statuses}")

    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = new_status
    if new_status != "ACTIVE":
        finding.is_active = False
    else:
        finding.is_active = True

    if req.notes:
        finding.notes = req.notes

    db.commit()
    return {"status": "success", "finding_id": finding.id, "new_status": finding.status}

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    total_findings = db.query(Finding).filter(Finding.is_active == True).count()
    crit = db.query(Finding).filter(Finding.is_active == True, Finding.severity == "CRITICAL").count()
    high = db.query(Finding).filter(Finding.is_active == True, Finding.severity == "HIGH").count()
    med = db.query(Finding).filter(Finding.is_active == True, Finding.severity == "MEDIUM").count()
    low = db.query(Finding).filter(Finding.is_active == True, Finding.severity == "LOW").count()

    mitigated = db.query(Finding).filter(Finding.status == "MITIGATED").count()
    false_pos = db.query(Finding).filter(Finding.status == "FALSE_POSITIVE").count()
    risk_accepted = db.query(Finding).filter(Finding.status == "RISK_ACCEPTED").count()

    tool_counts = db.query(Finding.tool, func.count(Finding.id)).filter(Finding.is_active == True).group_by(Finding.tool).all()
    repo_counts = db.query(Finding.repository, func.count(Finding.id)).filter(Finding.is_active == True).group_by(Finding.repository).all()

    return {
        "total": total_findings,
        "critical": crit,
        "high": high,
        "medium": med,
        "low": low,
        "status_counts": {
            "active": total_findings,
            "mitigated": mitigated,
            "false_positive": false_pos,
            "risk_accepted": risk_accepted
        },
        "by_tool": {t: c for t, c in tool_counts},
        "by_repo": {r: c for r, c in repo_counts},
        "total_scans": db.query(Scan).count()
    }

@app.get("/api/findings")
def get_findings(
    tool: Optional[str] = None,
    repository: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    query = db.query(Finding)

    if status and status != "ALL":
        query = query.filter(Finding.status == status.upper())
    else:
        query = query.filter(Finding.is_active == True)

    if tool and tool != "ALL":
        query = query.filter(Finding.tool == tool.lower())
    if repository and repository != "ALL":
        query = query.filter(Finding.repository == repository)
    if severity and severity != "ALL":
        query = query.filter(Finding.severity == severity.upper())
    if search:
        s = f"%{search}%"
        query = query.filter(
            (Finding.title.ilike(s)) |
            (Finding.rule_id.ilike(s)) |
            (Finding.file_path.ilike(s)) |
            (Finding.resource_name.ilike(s))
        )

    total_matched = query.count()
    results = query.order_by(
        case(
            (Finding.severity == 'CRITICAL', 1),
            (Finding.severity == 'HIGH', 2),
            (Finding.severity == 'MEDIUM', 3),
            (Finding.severity == 'LOW', 4),
            else_=5
        ),
        desc(Finding.created_at)
    ).offset(offset).limit(limit).all()

    return {
        "total": total_matched,
        "limit": limit,
        "offset": offset,
        "findings": [
            {
                "id": f.id,
                "scan_id": f.scan_id,
                "tool": f.tool,
                "repository": f.repository,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "rule_id": f.rule_id,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "resource_name": f.resource_name,
                "guideline_url": f.guideline_url,
                "code_snippet": f.code_snippet,
                "status": f.status or "ACTIVE",
                "notes": f.notes or "",
                "created_at": f.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            for f in results
        ]
    }

@app.get("/api/scans")
def get_scans(limit: int = 100, db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(desc(Scan.created_at)).limit(limit).all()
    return [
        {
            "id": s.id,
            "tool": s.tool,
            "repository": s.repository,
            "branch": s.branch,
            "commit_sha": s.commit_sha,
            "status": s.status or "COMPLETED",
            "triggered_by": s.triggered_by or "CI",
            "logs": s.logs or "",
            "total_findings": s.total_findings,
            "critical": s.critical_count,
            "high": s.high_count,
            "medium": s.medium_count,
            "low": s.low_count,
            "created_at": s.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }
        for s in scans
    ]

@app.get("/api/export/csv")
def export_csv(db: Session = Depends(get_db)):
    findings = db.query(Finding).filter(Finding.is_active == True).all()
    lines = ["ID,Severity,Tool,Repository,Rule ID,Title,File Path,Resource,Status,Created At"]
    for f in findings:
        title = f.title.replace('"', '""') if f.title else ""
        lines.append(f'"{f.id}","{f.severity}","{f.tool}","{f.repository}","{f.rule_id}","{title}","{f.file_path}","{f.resource_name}","{f.status}","{f.created_at}"')
    
    csv_content = "\n".join(lines)
    return Response(content=csv_content, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=sec_dashboard_findings.csv"})

@app.get("/", response_class=HTMLResponse)
def serve_dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})
