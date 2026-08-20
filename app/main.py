import json
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, Depends, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text, case

from .database import init_db, get_db, Scan, Finding, engine
from .parsers import parse_checkov, parse_trivy, parse_trufflehog

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="DefectDojo Lite - DevSecOps Portal", version="1.0.0", lifespan=lifespan)

# Setup template and static folders
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(BASE_DIR, "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

def normalize_repo_name(name: str) -> str:
    if not name:
        return "unknown"
    n = name.strip().rstrip("/")
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
    tool: str = Form(...), # checkov, trivy, trufflehog
    repository: str = Form(...),
    branch: Optional[str] = Form("main"),
    commit_sha: Optional[str] = Form(""),
    db: Session = Depends(get_db)
):
    tool = tool.lower().strip()
    repository = normalize_repo_name(repository)

    if tool not in ["checkov", "trivy", "trufflehog"]:
        raise HTTPException(status_code=400, detail="Supported tools: checkov, trivy, trufflehog")

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

    # Deactivate previous active findings for this (repo, tool) so scans don't duplicate
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

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    # Normalize any legacy findings repo name
    db.query(Finding).filter(Finding.repository == "tf-essential-module").update({"repository": "tf-essentials-module"})
    db.query(Scan).filter(Scan.repository == "tf-essential-module").update({"repository": "tf-essentials-module"})
    db.commit()

    total_findings = db.query(Finding).filter(Finding.is_active == True).count()
    crit = db.query(Finding).filter(Finding.is_active == True, Finding.severity == "CRITICAL").count()
    high = db.query(Finding).filter(Finding.is_active == True, Finding.severity == "HIGH").count()
    med = db.query(Finding).filter(Finding.is_active == True, Finding.severity == "MEDIUM").count()
    low = db.query(Finding).filter(Finding.is_active == True, Finding.severity == "LOW").count()

    # Tool breakdown
    tool_counts = db.query(Finding.tool, func.count(Finding.id)).filter(Finding.is_active == True).group_by(Finding.tool).all()
    # Repo breakdown
    repo_counts = db.query(Finding.repository, func.count(Finding.id)).filter(Finding.is_active == True).group_by(Finding.repository).all()

    return {
        "total": total_findings,
        "critical": crit,
        "high": high,
        "medium": med,
        "low": low,
        "by_tool": {t: c for t, c in tool_counts},
        "by_repo": {r: c for r, c in repo_counts},
        "total_scans": db.query(Scan).count()
    }

@app.get("/api/findings")
def get_findings(
    tool: Optional[str] = None,
    repository: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    query = db.query(Finding).filter(Finding.is_active == True)

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
            "total_findings": s.total_findings,
            "critical": s.critical_count,
            "high": s.high_count,
            "medium": s.medium_count,
            "low": s.low_count,
            "created_at": s.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }
        for s in scans
    ]

@app.get("/", response_class=HTMLResponse)
def serve_dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})
