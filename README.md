## AI SOC Copilot (Sellable v1)

AI SOC Copilot is a **Tier‑1 triage + investigation assistant** for security alerts. It helps a SOC analyst move from raw alert text → triage summary → investigation timeline → actions → **auditable report**.

### What makes this “product‑ready”
- **Case management**: alerts become persisted cases (SQLite via Prisma).
- **Audit trail**: every triage/report action can be recorded per case.
- **Ingestion**: a webhook endpoint to ingest alerts from external systems (SIEM/SOAR) without UI clicks.
- **Human‑in‑the‑loop**: recommendations can be reviewed/approved by an analyst (UI workflow).

## Local setup

### Prereqs
- Node.js + npm

### Configure env
Copy `.env.example` to `.env` and set at least:
- **`DATABASE_URL`**: `file:./dev.db`
- **`OPENAI_API_KEY`** (optional): enables richer responses on the `/api/soc-copilot/*` routes
- **`INGEST_WEBHOOK_SECRET`**: required for `/api/ingest/webhook`

### Install + migrate + run

```bash
npm install
npx prisma migrate dev --name init
npm run dev
```

Open `http://localhost:3000`.

## API endpoints (v1)

### Cases
- `GET /api/cases` — list cases
- `POST /api/cases` — create case
- `GET /api/cases/:id` — case details (messages + reports)
- `PATCH /api/cases/:id` — update status/title/summary
- `GET /api/cases/:id/audit` — audit events

### Copilot actions (persist when `caseId` provided)
- `POST /api/soc-copilot` — triage chat; if `caseId` is included, stores user+assistant messages and a `TRIAGE_RUN` audit event
- `POST /api/soc-copilot/report` — generates markdown report; if `caseId` is included, stores report and a `REPORT_GENERATED` audit event

### Ingestion webhook (SIEM/SOAR friendly)
`POST /api/ingest/webhook`
- Header: `Authorization: Bearer <INGEST_WEBHOOK_SECRET>`
- Body example:

```json
{
  "title": "Impossible travel sign-in",
  "summary": "Sentinel: Impossible travel sign-in for user j.doe@company.com — Brazil and Germany within 28 minutes.",
  "severity": "High",
  "source": "Microsoft Sentinel",
  "riskScore": 85,
  "raw": { "any": "original payload you want to store" }
}
```

Response: `{ "caseId": "..." }`

## Demo script (for selling)
1. Click **Sample incidents** to create a case and run triage.
2. Generate the **Investigation Report** (stored under the case).
3. Hit the ingestion webhook from Postman to create a new case automatically.

## Notes
- This repo uses SQLite for speed of iteration. For production, swap to Postgres and add auth/SSO + role-based access.
- Don’t commit secrets. Keep `OPENAI_API_KEY` and `INGEST_WEBHOOK_SECRET` in environment variables.
