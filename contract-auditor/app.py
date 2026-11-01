from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import fitz
from docx import Document as DocxDocument
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).parent
DATA_DIR = ROOT / "data"
UPLOAD_DIR = ROOT / "uploads"
WEB_DIR = ROOT / "web"
DB_PATH = DATA_DIR / "auditor.sqlite3"
MAX_BYTES = 20 * 1024 * 1024
ALLOWED = {".pdf", ".docx", ".txt", ".md"}


class RiskAnalysis(BaseModel):
    severity: str = Field(description="LOW, MEDIUM, HIGH, or CRITICAL")
    risk_score: int = Field(ge=1, le=10)
    issue_title: str
    explanation: str
    suggested_fix: str
    category: str = "General"


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def init_db() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    UPLOAD_DIR.mkdir(exist_ok=True)
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS documents (
          id TEXT PRIMARY KEY, filename TEXT NOT NULL, file_hash TEXT NOT NULL,
          upload_status TEXT NOT NULL, created_at TEXT NOT NULL, error TEXT
        );
        CREATE TABLE IF NOT EXISTS clauses (
          id TEXT PRIMARY KEY, document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
          clause_number INTEGER NOT NULL, raw_text TEXT NOT NULL, category TEXT
        );
        CREATE TABLE IF NOT EXISTS risk_flags (
          id TEXT PRIMARY KEY, clause_id TEXT NOT NULL REFERENCES clauses(id) ON DELETE CASCADE,
          severity TEXT NOT NULL, risk_score INTEGER NOT NULL, issue_title TEXT NOT NULL,
          explanation TEXT NOT NULL, suggested_fix TEXT, category TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_summaries (
          id TEXT PRIMARY KEY, document_id TEXT UNIQUE NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
          overall_risk_score INTEGER NOT NULL, executive_summary TEXT NOT NULL,
          critical_flag_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_clauses_document ON clauses(document_id);
        CREATE INDEX IF NOT EXISTS idx_flags_clause ON risk_flags(clause_id);
        """)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="ClearClause | Contract & Policy Auditor", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


def extract_text(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        with fitz.open(path) as pdf:
            return "\n\n".join(page.get_text("text") for page in pdf)
    if suffix == ".docx":
        doc = DocxDocument(path)
        return "\n\n".join(p.text for p in doc.paragraphs if p.text.strip())
    return path.read_text(encoding="utf-8", errors="replace")


def split_clauses(text: str) -> list[str]:
    text = re.sub(r"\r", "", text)
    # Preserve numbered headings and paragraph boundaries as reviewable units.
    blocks = [re.sub(r"\s+", " ", part).strip() for part in re.split(r"\n\s*\n|(?=\n\s*(?:\d+(?:\.\d+)*[.)]?\s+|[A-Z][A-Z \-/]{4,}:))", text)]
    blocks = [b for b in blocks if len(b) >= 35]
    if len(blocks) < 2:
        blocks = [s.strip() for s in re.split(r"(?<=[.!?])\s+(?=[A-Z])", re.sub(r"\s+", " ", text)) if len(s.strip()) >= 35]
    # Avoid pathological giant clauses from PDFs with poor line breaks.
    output: list[str] = []
    for block in blocks:
        if len(block) <= 2400:
            output.append(block)
        else:
            output.extend(block[i:i + 1800] for i in range(0, len(block), 1800))
    return output[:250]


RULES = [
    ("liability", "Uncapped liability", "HIGH", 8, r"unlimited liability|without limitation|no limitation of liability|in no event.*limit", "This wording may leave one party responsible for losses without a clear financial ceiling.", "Add a mutual cap tied to fees paid in the prior 12 months, with narrowly defined exceptions."),
    ("indemnification", "One-sided indemnity", "HIGH", 8, r"indemnif(?:y|ies|ication).{0,100}(?:any and all|all claims|regardless)|defend and hold harmless", "The indemnity appears broad and may require payment of claims outside the party's control.", "Limit indemnity to third-party claims caused by the indemnifying party's breach, negligence, or misconduct."),
    ("data rights", "Broad data use or sale", "CRITICAL", 10, r"sell.{0,45}(?:personal|customer|user) data|share.{0,45}(?:personal|customer|user) data|license.{0,60}(?:perpetual|irrevocable).{0,50}data|use.{0,50}data.{0,50}any purpose", "The provider may be able to use, share, or monetize personal or customer data beyond service delivery.", "Restrict processing to providing the service; prohibit sale and require consent for any other use."),
    ("termination", "Unilateral termination", "MEDIUM", 6, r"terminate.{0,70}(?:at any time|for any reason|without cause|without notice)", "One party may end the agreement at its discretion, potentially without notice or a remedy for prepaid fees.", "Require reasonable advance notice and a pro-rata refund of unused prepaid fees."),
    ("renewal", "Automatic renewal", "MEDIUM", 5, r"automatically renew|auto-renew|automatic renewal", "The agreement may renew unless the customer catches a notice window.", "Provide a clear reminder before renewal and allow cancellation through the renewal date."),
    ("pricing", "Unilateral price changes", "HIGH", 7, r"(?:change|increase|modify).{0,50}(?:fees|price|pricing) at any time|fees may increase", "Pricing can apparently change without a clear limit or a right to exit.", "Require advance notice and let the customer terminate before a price increase takes effect."),
    ("disputes", "Mandatory arbitration or class waiver", "MEDIUM", 6, r"binding arbitration|waive.{0,40}class action|class action waiver", "This may limit access to court or collective remedies.", "Make arbitration optional or preserve small-claims and legally available collective remedies."),
    ("privacy", "Broad retention or deletion gap", "HIGH", 7, r"retain.{0,60}(?:indefinitely|as long as|any purpose)|no obligation to delete|not required to delete", "The document may not set a meaningful limit for keeping personal data or require deletion.", "Set a defined retention period and require deletion or return after the service ends."),
    ("warranty", "Broad warranty disclaimer", "MEDIUM", 6, r"as is|all warranties.{0,30}disclaim|without warranty", "The provider disclaims warranties broadly, which can leave service quality expectations unclear.", "Preserve express commitments for security, service availability, and conformity with documentation."),
]


def rule_analysis(text: str) -> RiskAnalysis:
    for category, title, severity, score, pattern, explanation, fix in RULES:
        if re.search(pattern, text, re.I | re.S):
            return RiskAnalysis(category=category.title(), issue_title=title, severity=severity, risk_score=score, explanation=explanation, suggested_fix=fix)
    return RiskAnalysis(category="General", issue_title="No common risk pattern found", severity="LOW", risk_score=2,
                        explanation="The initial screen did not find one of the common risk patterns it checks. This is not a guarantee that the clause is safe.",
                        suggested_fix="Confirm this clause matches the business deal and review it with qualified counsel.")


async def analyze_clause(text: str) -> RiskAnalysis:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return rule_analysis(text)
    try:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=api_key)
        response = await client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"), temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": "You are a cautious contract risk reviewer, not a lawyer. Identify concrete risks in the clause. Return JSON with severity (LOW/MEDIUM/HIGH/CRITICAL), risk_score integer 1-10, issue_title, explanation, suggested_fix, category. Do not invent terms absent from the clause. If no material issue, say so."},
                {"role": "user", "content": text[:12000]},
            ],
        )
        payload = json.loads(response.choices[0].message.content or "{}")
        return RiskAnalysis.model_validate(payload)
    except Exception:
        # Keep audits usable if the configured provider is unavailable or returns invalid output.
        return rule_analysis(text)


async def run_audit(doc_id: str) -> None:
    with connect() as db:
        row = db.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
        if not row:
            return
        db.execute("UPDATE documents SET upload_status='PROCESSING', error=NULL WHERE id=?", (doc_id,))
    try:
        path = UPLOAD_DIR / f"{doc_id}{Path(row['filename']).suffix.lower()}"
        text = await asyncio.to_thread(extract_text, path)
        clauses = split_clauses(text)
        if not clauses:
            raise ValueError("No readable text was found. This file may be image-only; OCR is not included yet.")
        results = await asyncio.gather(*(analyze_clause(c) for c in clauses))
        with connect() as db:
            db.execute("DELETE FROM clauses WHERE document_id=?", (doc_id,))
            scores = []
            flags = 0
            for idx, (clause, result) in enumerate(zip(clauses, results), 1):
                clause_id = str(uuid.uuid4())
                db.execute("INSERT INTO clauses VALUES (?,?,?,?,?)", (clause_id, doc_id, idx, clause, result.category))
                scores.append(result.risk_score)
                if result.risk_score >= 7:
                    flags += 1
                db.execute("INSERT INTO risk_flags VALUES (?,?,?,?,?,?,?,?)", (str(uuid.uuid4()), clause_id, result.severity, result.risk_score,
                    result.issue_title, result.explanation, result.suggested_fix, result.category))
            overall = round(sum(scores) / max(len(scores), 1) * 10)
            summary = f"Reviewed {len(clauses)} clauses. The screening found {flags} high-priority item(s). Overall score: {overall}/100, where higher means more review attention is warranted."
            db.execute("INSERT OR REPLACE INTO audit_summaries VALUES (?,?,?,?,?)", (str(uuid.uuid4()), doc_id, overall, summary, flags))
            db.execute("UPDATE documents SET upload_status='COMPLETED' WHERE id=?", (doc_id,))
    except Exception as exc:
        with connect() as db:
            db.execute("UPDATE documents SET upload_status='FAILED', error=? WHERE id=?", (str(exc)[:500], doc_id))


@app.get("/")
def home():
    return FileResponse(WEB_DIR / "index.html")


@app.post("/api/v1/upload")
async def upload(background: BackgroundTasks, file: UploadFile = File(...)):
    filename = Path(file.filename or "document").name
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED:
        raise HTTPException(415, "Upload a PDF, DOCX, TXT, or Markdown file.")
    content = await file.read(MAX_BYTES + 1)
    if not content:
        raise HTTPException(400, "The uploaded file is empty.")
    if len(content) > MAX_BYTES:
        raise HTTPException(413, "Files must be 20 MB or smaller.")
    digest = hashlib.sha256(content).hexdigest()
    doc_id = str(uuid.uuid4())
    (UPLOAD_DIR / f"{doc_id}{suffix}").write_bytes(content)
    with connect() as db:
        db.execute("INSERT INTO documents VALUES (?,?,?,?,?,NULL)", (doc_id, filename, digest, "PENDING", datetime.now(timezone.utc).isoformat()))
    background.add_task(run_audit, doc_id)
    return {"document_id": doc_id, "filename": filename, "upload_status": "PENDING"}


@app.get("/api/v1/documents")
def documents():
    with connect() as db:
        rows = db.execute("SELECT id,filename,upload_status,created_at,error FROM documents ORDER BY created_at DESC LIMIT 50").fetchall()
    return [dict(r) for r in rows]


@app.get("/api/v1/audit/{doc_id}")
def audit_status(doc_id: str):
    with connect() as db:
        row = db.execute("SELECT id,filename,upload_status,created_at,error FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Document not found")
    return dict(row)


@app.get("/api/v1/report/{doc_id}")
def report(doc_id: str):
    with connect() as db:
        doc = db.execute("SELECT id,filename,upload_status,created_at,error FROM documents WHERE id=?", (doc_id,)).fetchone()
        if not doc:
            raise HTTPException(404, "Document not found")
        summary = db.execute("SELECT overall_risk_score,executive_summary,critical_flag_count FROM audit_summaries WHERE document_id=?", (doc_id,)).fetchone()
        clauses = db.execute("SELECT * FROM clauses WHERE document_id=? ORDER BY clause_number", (doc_id,)).fetchall()
        output = []
        for clause in clauses:
            flag = db.execute("SELECT severity,risk_score,issue_title,explanation,suggested_fix,category FROM risk_flags WHERE clause_id=?", (clause["id"],)).fetchone()
            output.append({"id": clause["id"], "clause_number": clause["clause_number"], "raw_text": clause["raw_text"], "category": clause["category"], "finding": dict(flag) if flag else None})
    return {"document": dict(doc), "summary": dict(summary) if summary else None, "clauses": output}


@app.delete("/api/v1/documents/{doc_id}")
def delete_document(doc_id: str):
    with connect() as db:
        row = db.execute("SELECT filename FROM documents WHERE id=?", (doc_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Document not found")
        suffix = Path(row["filename"]).suffix.lower()
        db.execute("DELETE FROM documents WHERE id=?", (doc_id,))
    (UPLOAD_DIR / f"{doc_id}{suffix}").unlink(missing_ok=True)
    return {"deleted": True}
