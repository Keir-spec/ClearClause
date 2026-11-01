# ClearClause — Contract & Policy Auditor

A local-first document screening app that extracts contract clauses, highlights common risk patterns, and presents suggested questions and safer wording in a dashboard. It supports PDF, DOCX, TXT, and Markdown uploads up to 20 MB.

## Run locally

Requires Python 3.10 or newer.

```powershell
cd contract-auditor
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The first run creates a SQLite database and local upload directory. To try the sample, upload `samples/sample-terms.txt`.

## Optional LLM analysis

Without configuration, the app uses a small transparent rule-based screening set. To enable structured OpenAI-compatible analysis, copy `.env.example` to `.env`, set `OPENAI_API_KEY` and optionally `OPENAI_MODEL`, then load those variables into the shell before starting Uvicorn. The app falls back to its rule-based analyzer if the provider is unavailable or returns invalid data.

## API

- `POST /api/v1/upload` — upload a supported document; starts a background audit.
- `GET /api/v1/audit/{document_id}` — read processing status.
- `GET /api/v1/report/{document_id}` — retrieve summary, clauses, and findings.
- `GET /api/v1/documents` — list recent documents.
- `DELETE /api/v1/documents/{document_id}` — delete a document and its findings.
- Interactive API documentation: `/docs`.

## Notes and limitations

This is a runnable prototype, not a legal service. Scores are a screening signal, not a determination of enforceability or safety. The built-in analyzer uses pattern matching and can miss context or produce false positives. Optional LLM calls send clause text to the configured provider; check that provider's data handling terms before using confidential documents. Local files and SQLite data remain in `uploads/` and `data/` until deleted. Scanned image-only PDFs are not OCR processed. The vector database/RAG and true multi-agent architecture from the concept brief are intentionally not prerequisites for this first runnable implementation.
