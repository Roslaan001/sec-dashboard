import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, ForeignKey, Index
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sec_dashboard.db")

# Normalize postgres:// to postgresql:// for SQLAlchemy compatibility
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Handle engine args for SQLite vs Postgres
connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    tool = Column(String(50), nullable=False, index=True) # checkov, trivy, trufflehog
    repository = Column(String(255), nullable=False, index=True)
    branch = Column(String(100), default="main")
    commit_sha = Column(String(100), default="")
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    tool = Column(String(50), nullable=False, index=True)
    repository = Column(String(255), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, default="")
    severity = Column(String(20), default="MEDIUM", index=True) # CRITICAL, HIGH, MEDIUM, LOW, INFO
    rule_id = Column(String(100), default="", index=True) # CKV_AWS_*, AVD-*, DetectorName
    file_path = Column(String(500), default="")
    line_number = Column(String(50), default="")
    resource_name = Column(String(255), default="")
    guideline_url = Column(String(500), default="")
    code_snippet = Column(Text, default="")
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")

Index("idx_finding_repo_tool", Finding.repository, Finding.tool)
Index("idx_finding_severity", Finding.severity)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
