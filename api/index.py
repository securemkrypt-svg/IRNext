import os
import time
import uuid
import asyncio
from datetime import datetime, timezone
from typing import Optional
import httpx
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from google import genai
from google.genai.errors import APIError

load_dotenv()

app = FastAPI(title="MKRYPT SOC Portfolio Engine", version="3.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 1. Configuration ---
TENANT_ID = os.getenv("AZURE_TENANT_ID", "").strip()
CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "").strip()
SUB_ID = os.getenv("AZURE_SUBSCRIPTION_ID", "f1dcd00a-9833-4213-aedb-0554242f1c7e").strip()
RG = os.getenv("AZURE_RESOURCE_GROUP", "SENTINEL-LAB").strip()
WS_NAME = os.getenv("AZURE_WORKSPACE_NAME", "").strip()
WS_ID = os.getenv("AZURE_WORKSPACE_ID", "").strip()
GEMINI_KEY = os.getenv("GEMINI_API_KEY", "").strip()
VM_ADMIN_SECRET = os.getenv("VM_ADMIN_SECRET", "MKRYPT-OPS-2026").strip()

TURSO_URL = os.getenv("TURSO_DATABASE_URL", "").strip().replace("libsql://", "https://").rstrip("/")
TURSO_TOKEN = os.getenv("TURSO_AUTH_TOKEN", "").strip()

ARM_BASE = f"https://management.azure.com/subscriptions/{SUB_ID}/resourceGroups/{RG}"
SENTINEL_BASE = (
    f"{ARM_BASE}/providers/Microsoft.OperationalInsights/workspaces/{WS_NAME}"
    f"/providers/Microsoft.SecurityInsights"
)
SENTINEL_API_VER = "2025-09-01"
COMPUTE_API_VER = "2024-07-01"
SLA_BY_SEVERITY = {"High": 15, "Medium": 60, "Low": 240, "Informational": 480}

gemini_client = genai.Client(api_key=GEMINI_KEY) if GEMINI_KEY else None

# --- 2. Turso HTTP Pipeline Client ---
_db_initialized = False

def _encode_args(params: Optional[list]) -> list[dict]:
    args = []
    for p in (params or []):
        if p is None:
            args.append({"type": "null"})
        elif isinstance(p, bool):
            args.append({"type": "integer", "value": "1" if p else "0"})
        elif isinstance(p, int):
            args.append({"type": "integer", "value": str(p)})
        elif isinstance(p, float):
            args.append({"type": "float", "value": p})
        else:
            args.append({"type": "text", "value": str(p)})
    return args

def _decode_rows(result_obj: dict) -> list[dict]:
    cols = [c["name"] for c in result_obj.get("cols", [])]
    decoded = []
    for row in result_obj.get("rows", []):
        item = {}
        for i, cell in enumerate(row):
            ctype, val = cell.get("type"), cell.get("value")
            if ctype == "null":
                item[cols[i]] = None
            elif ctype == "integer":
                item[cols[i]] = int(val)
            elif ctype == "float":
                item[cols[i]] = float(val)
            else:
                item[cols[i]] = val
        decoded.append(item)
    return decoded

async def turso_batch(statements: list[tuple[str, Optional[list]]]) -> list[list[dict]]:
    if not TURSO_URL or not TURSO_TOKEN:
        raise HTTPException(status_code=500, detail="Turso credentials missing")
    requests = [{"type": "execute", "stmt": {"sql": sql, "args": _encode_args(params)}} for sql, params in statements]
    requests.append({"type": "close"})
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{TURSO_URL}/v2/pipeline",
            headers={"Authorization": f"Bearer {TURSO_TOKEN}", "Content-Type": "application/json"},
            json={"requests": requests},
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Turso HTTP error: {resp.text}")
        outputs = []
        for r in resp.json().get("results", [])[:-1]:
            if r.get("type") == "error":
                raise HTTPException(status_code=502, detail=f"Turso SQL error: {r.get('error', {}).get('message')}")
            outputs.append(_decode_rows(r.get("response", {}).get("result", {})))
        return outputs

async def turso_exec(sql: str, params: Optional[list] = None) -> list[dict]:
    results = await turso_batch([(sql, params)])
    return results[0] if results else []

async def ensure_db():
    global _db_initialized
    if _db_initialized:
        return
    await turso_batch([
        ("CREATE TABLE IF NOT EXISTS analysts (id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, email TEXT NOT NULL)", None),
        ("CREATE TABLE IF NOT EXISTS ticket_state (incident_id TEXT PRIMARY KEY, incident_number INTEGER, assigned_to TEXT DEFAULT 'T1-Triage-Bin', snow_state TEXT DEFAULT 'New', ai_analysis TEXT, updated_at TEXT)", None),
        ("CREATE TABLE IF NOT EXISTS work_notes (id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, author TEXT NOT NULL, note TEXT NOT NULL, synced_to_sentinel INTEGER DEFAULT 1, created_at TEXT NOT NULL)", None),
        ("CREATE TABLE IF NOT EXISTS ir_lifecycle (incident_id TEXT PRIMARY KEY, ticket_number TEXT, title TEXT, severity TEXT DEFAULT 'Medium', assignee TEXT DEFAULT 'T1-Triage-Bin', current_stage TEXT DEFAULT 'Assignment', created_utc TEXT, assigned_utc TEXT, acknowledged_utc TEXT, contained_utc TEXT, eradicated_utc TEXT, resolved_utc TEXT, sla_minutes INTEGER DEFAULT 60, last_justification TEXT)", None),
        ("INSERT OR IGNORE INTO analysts (id, name, role, email) VALUES (?, ?, ?, ?)", ["bin", "T1-Triage-Bin", "Unassigned Queue", "soc-queue@mkrypt.local"]),
        ("INSERT OR IGNORE INTO analysts (id, name, role, email) VALUES (?, ?, ?, ?)", ["mohan", "Mohan Krishna", "Senior Threat Detection Engineer", "mohan@mkrypt.local"]),
        ("INSERT OR IGNORE INTO analysts (id, name, role, email) VALUES (?, ?, ?, ?)", ["analyst1", "Tier-1 SOC Analyst", "Incident Responder", "t1-soc@mkrypt.local"]),
    ])
    try:
        await turso_exec("ALTER TABLE ticket_state ADD COLUMN snow_state TEXT DEFAULT 'New'")
    except Exception:
        pass
    _db_initialized = True

# --- 3. Azure OAuth2 & Fast KQL Runner ---
_token_cache = {}

async def get_azure_token(scope: str) -> str:
    now = time.time()
    cached = _token_cache.get(scope)
    if cached and cached["expires_at"] > now + 60:
        return cached["token"]
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, data={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "scope": scope, "grant_type": "client_credentials"})
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Azure OAuth2 failed: {resp.text}")
        payload = resp.json()
        _token_cache[scope] = {"token": payload["access_token"], "expires_at": now + int(payload.get("expires_in", 3599))}
        return payload["access_token"]

async def run_kql(query: str, timespan: str = "P7D") -> list[dict]:
    try:
        token = await get_azure_token("https://api.loganalytics.io/.default")
        url = f"https://api.loganalytics.io/v1/workspaces/{WS_ID}/query"
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(url, headers={"Authorization": f"Bearer {token}"}, json={"query": query, "timespan": timespan})
            if resp.status_code != 200:
                return []
            tables = resp.json().get("tables", [])
            if not tables:
                return []
            cols = [c["name"] for c in tables[0]["columns"]]
            return [dict(zip(cols, row)) for row in tables[0]["rows"]]
    except Exception:
        return []

# --- 4. Schemas ---
class AnalystRegisterRequest(BaseModel):
    name: str
    role: str = "L2 Incident Responder"
    email: str

class AssignRequest(BaseModel):
    assignee: str

class StageTransitionRequest(BaseModel):
    assignee: str
    target_stage: str
    justification: str
    classification: str = "TruePositive"
    classification_reason: str = "SuspiciousActivity"
    created_utc: Optional[str] = None
    severity: str = "Medium"
    title: Optional[str] = None
    ticket_number: Optional[str] = None

class WorkNoteRequest(BaseModel):
    author: str = "SOC Analyst"
    note: str
    new_status: Optional[str] = None
    classification: str = "TruePositive"

class KqlQueryRequest(BaseModel):
    query: str
    timespan: str = "PT24H"

# --- 5. Health & Analysts ---
@app.get("/api/health")
async def health_check():
    return {"status": "online", "resource_group": RG, "workspace_configured": bool(WS_NAME and WS_ID), "gemini_configured": bool(GEMINI_KEY), "turso_configured": bool(TURSO_URL and TURSO_TOKEN)}

@app.get("/api/analysts")
async def list_analysts():
    await ensure_db()
    return await turso_exec("SELECT * FROM analysts ORDER BY name")

@app.post("/api/analysts")
async def register_analyst(body: AnalystRegisterRequest):
    await ensure_db()
    name, email = body.name.strip(), body.email.strip()
    if not name or not email:
        raise HTTPException(status_code=400, detail="Name and email are required")
    if await turso_exec("SELECT id FROM analysts WHERE lower(email) = lower(?)", [email]):
        raise HTTPException(status_code=400, detail="Analyst email already registered")
    analyst_id = f"soc-{str(uuid.uuid4())[:6]}"
    await turso_exec("INSERT INTO analysts (id, name, role, email) VALUES (?, ?, ?, ?)", [analyst_id, name, body.role.strip(), email])
    return {"id": analyst_id, "name": name, "role": body.role.strip(), "email": email}

# --- 6. Incidents, Entities, Assign-Once, IR Stage, Notes & AI Triage ---
@app.get("/api/incidents")
async def list_incidents():
    await ensure_db()
    arm_token = await get_azure_token("https://management.azure.com/.default")
    url = f"{SENTINEL_BASE}/incidents?api-version={SENTINEL_API_VER}&$orderby=properties/createdTimeUtc desc&$top=30"
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {arm_token}"})
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)

    items = resp.json().get("value", [])
    now_iso = datetime.now(timezone.utc).isoformat()
    ticket_rows, ir_rows, note_rows = await turso_batch([
        ("SELECT * FROM ticket_state", None),
        ("SELECT * FROM ir_lifecycle", None),
        ("SELECT * FROM work_notes ORDER BY created_at DESC", None),
    ])
    ticket_map = {r["incident_id"]: r for r in ticket_rows}
    ir_map = {r["incident_id"]: r for r in ir_rows}
    notes_by_inc = {}
    for n in note_rows:
        notes_by_inc.setdefault(n["incident_id"], []).append(n)

    new_seeds = []
    for item in items:
        inc_id = item["name"]
        if inc_id not in ticket_map:
            inc_num = item["properties"].get("incidentNumber", 0)
            new_seeds.append(("INSERT OR IGNORE INTO ticket_state (incident_id, incident_number, updated_at) VALUES (?, ?, ?)", [inc_id, inc_num, now_iso]))
            ticket_map[inc_id] = {"incident_id": inc_id, "incident_number": inc_num, "assigned_to": "T1-Triage-Bin", "snow_state": "New", "ai_analysis": None}
    if new_seeds:
        await turso_batch(new_seeds)

    results = []
    for item in items:
        inc_id, props = item["name"], item["properties"]
        inc_num, sev, created_utc = props.get("incidentNumber", 0), props.get("severity", "Medium"), props.get("createdTimeUtc")
        local, ir = ticket_map.get(inc_id, {}), ir_map.get(inc_id, {})
        default_stage = "Resolution" if props.get("status") == "Closed" else "Assignment"
        results.append({
            "incident_id": inc_id,
            "ticket_number": f"INC-{inc_num:05d}",
            "title": props.get("title"),
            "description": props.get("description", ""),
            "severity": sev,
            "sentinel_status": props.get("status"),
            "created_time": created_utc,
            "last_activity": props.get("lastActivityTimeUtc", created_utc),
            "incident_url": props.get("incidentUrl", "https://portal.azure.com"),
            "tactics": props.get("tactics", []),
            "assigned_to": ir.get("assignee") or local.get("assigned_to", "T1-Triage-Bin"),
            "snow_state": local.get("snow_state", "New"),
            "ir_stage": ir.get("current_stage") or default_stage,
            "sla_minutes": ir.get("sla_minutes") or SLA_BY_SEVERITY.get(sev, 60),
            "ir_timestamps": {
                "Assignment": ir.get("assigned_utc"),
                "Acknowledgement": ir.get("acknowledged_utc"),
                "Containment": ir.get("contained_utc"),
                "Eradication": ir.get("eradicated_utc"),
                "Resolution": ir.get("resolved_utc"),
            },
            "ai_analysis": local.get("ai_analysis"),
            "work_notes": notes_by_inc.get(inc_id, []),
            "raw_properties": props,
        })
    return results

@app.get("/api/incidents/{incident_id}/entities")
async def get_incident_entities(incident_id: str):
    arm_token = await get_azure_token("https://management.azure.com/.default")
    url = f"{SENTINEL_BASE}/incidents/{incident_id}/entities?api-version={SENTINEL_API_VER}"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, headers={"Authorization": f"Bearer {arm_token}"})
        if resp.status_code != 200:
            return {"entities": []}
        parsed = []
        for e in resp.json().get("entities", []):
            p = e.get("properties", {})
            val = p.get("address") or p.get("accountName") or p.get("hostName") or p.get("url") or p.get("friendlyName") or e.get("name")
            parsed.append({"kind": e.get("kind", "Entity"), "value": val, "raw": p})
        return {"entities": parsed}

@app.post("/api/incidents/{incident_id}/assign")
async def assign_incident_once(incident_id: str, body: AssignRequest):
    await ensure_db()
    rows = await turso_exec("SELECT assigned_to FROM ticket_state WHERE incident_id = ?", [incident_id])
    if rows and rows[0]["assigned_to"] and rows[0]["assigned_to"] != "T1-Triage-Bin":
        raise HTTPException(status_code=400, detail=f"Already assigned to {rows[0]['assigned_to']} (Assign-Once locked)")
    now_iso = datetime.now(timezone.utc).isoformat()
    await turso_batch([
        ("UPDATE ticket_state SET assigned_to = ?, snow_state = 'In Progress', updated_at = ? WHERE incident_id = ?", [body.assignee, now_iso, incident_id]),
        ("INSERT INTO ir_lifecycle (incident_id, assignee, current_stage, assigned_utc) VALUES (?, ?, 'Assignment', ?) ON CONFLICT(incident_id) DO UPDATE SET assignee = excluded.assignee, assigned_utc = COALESCE(ir_lifecycle.assigned_utc, excluded.assigned_utc)", [incident_id, body.assignee, now_iso]),
    ])
    return {"incident_id": incident_id, "assigned_to": body.assignee}

@app.post("/api/incidents/{incident_id}/stage")
async def transition_ir_stage(incident_id: str, body: StageTransitionRequest):
    await ensure_db()
    if len(body.justification.strip()) < 5:
        raise HTTPException(status_code=400, detail="Proper justification (min 5 characters) is required")
    cols = {"Assignment": "assigned_utc", "Acknowledgement": "acknowledged_utc", "Containment": "contained_utc", "Eradication": "eradicated_utc", "Resolution": "resolved_utc"}
    col = cols.get(body.target_stage)
    if not col:
        raise HTTPException(status_code=400, detail=f"Invalid IR stage: {body.target_stage}")

    now_iso = datetime.now(timezone.utc).isoformat()
    sla_mins = SLA_BY_SEVERITY.get(body.severity, 60)
    comment_id = str(uuid.uuid4())
    note_msg = f"[IR Phase: {body.target_stage}] Assignee: {body.assignee} | Justification: {body.justification.strip()}"
    arm_token = await get_azure_token("https://management.azure.com/.default")
    headers = {"Authorization": f"Bearer {arm_token}", "Content-Type": "application/json"}
    inc_url = f"{SENTINEL_BASE}/incidents/{incident_id}?api-version={SENTINEL_API_VER}"

    async with httpx.AsyncClient(timeout=25) as client:
        c_resp = await client.put(f"{SENTINEL_BASE}/incidents/{incident_id}/comments/{comment_id}?api-version={SENTINEL_API_VER}", headers=headers, json={"properties": {"message": f"[MKRYPT SOC Portal - {body.assignee}] {note_msg}"}})
        if c_resp.status_code not in (200, 201):
            raise HTTPException(status_code=c_resp.status_code, detail=f"Sentinel comment sync failed: {c_resp.text}")
        get_inc = await client.get(inc_url, headers=headers)
        if get_inc.status_code != 200:
            raise HTTPException(status_code=get_inc.status_code, detail=f"Sentinel lookup failed: {get_inc.text}")
        inc_payload = get_inc.json()
        props = inc_payload["properties"]
        if body.target_stage == "Resolution":
            props["status"] = "Closed"
            props["classification"] = body.classification
            props["classificationReason"] = body.classification_reason
            props["classificationComment"] = f"[{body.assignee}] {body.justification.strip()}"
        elif props.get("status") == "New":
            props["status"] = "Active"
        put_inc = await client.put(inc_url, headers=headers, json={"etag": inc_payload.get("etag"), "properties": props})
        if put_inc.status_code not in (200, 201):
            raise HTTPException(status_code=put_inc.status_code, detail=f"Sentinel sync failed: {put_inc.text}")

    await turso_batch([
        ("INSERT INTO ir_lifecycle (incident_id, ticket_number, title, severity, assignee, current_stage, created_utc, sla_minutes, last_justification) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(incident_id) DO UPDATE SET assignee = excluded.assignee, current_stage = excluded.current_stage, last_justification = excluded.last_justification", [incident_id, body.ticket_number, body.title, body.severity, body.assignee, body.target_stage, body.created_utc or now_iso, sla_mins, body.justification.strip()]),
        (f"UPDATE ir_lifecycle SET {col} = COALESCE({col}, ?) WHERE incident_id = ?", [now_iso, incident_id]),
        ("UPDATE ticket_state SET assigned_to = ?, snow_state = ?, updated_at = ? WHERE incident_id = ?", [body.assignee, "Resolved" if body.target_stage == "Resolution" else "In Progress", now_iso, incident_id]),
        ("INSERT INTO work_notes (id, incident_id, author, note, synced_to_sentinel, created_at) VALUES (?, ?, ?, ?, 1, ?)", [comment_id, incident_id, body.assignee, note_msg, now_iso]),
    ])
    return {"status": "Synced to Sentinel", "ir_stage": body.target_stage, "sentinel_status": props["status"]}

@app.post("/api/incidents/{incident_id}/notes")
async def add_bidirectional_work_note(incident_id: str, body: WorkNoteRequest):
    await ensure_db()
    arm_token = await get_azure_token("https://management.azure.com/.default")
    headers = {"Authorization": f"Bearer {arm_token}", "Content-Type": "application/json"}
    comment_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    async with httpx.AsyncClient(timeout=20) as client:
        c_resp = await client.put(f"{SENTINEL_BASE}/incidents/{incident_id}/comments/{comment_id}?api-version={SENTINEL_API_VER}", headers=headers, json={"properties": {"message": f"[MKRYPT SOC Portal - {body.author}] {body.note}"}})
        if c_resp.status_code not in (200, 201):
            raise HTTPException(status_code=c_resp.status_code, detail=f"Sentinel comment failed: {c_resp.text}")

    await turso_exec("INSERT INTO work_notes (id, incident_id, author, note, synced_to_sentinel, created_at) VALUES (?, ?, ?, ?, 1, ?)", [comment_id, incident_id, body.author, body.note, now_iso])
    return {"status": "Synced to Sentinel", "comment_id": comment_id}

class AiInvestigateRequest(BaseModel):
    title: str
    severity: str = "Medium"
    description: str = ""
    entities: list[str] = []
    entity_logs: list[dict] = []
    related_alerts: list[dict] = []


@app.post("/api/incidents/{incident_id}/triage-context")
async def get_triage_context(incident_id: str):
    arm_token = await get_azure_token("https://management.azure.com/.default")
    headers = {"Authorization": f"Bearer {arm_token}"}
    inc_url = f"{SENTINEL_BASE}/incidents/{incident_id}?api-version={SENTINEL_API_VER}"
    ent_url = f"{SENTINEL_BASE}/incidents/{incident_id}/entities?api-version={SENTINEL_API_VER}"

    async with httpx.AsyncClient(timeout=10) as client:
        inc_resp, ent_resp = await asyncio.gather(
            client.get(inc_url, headers=headers),
            client.post(ent_url, headers=headers),
        )
        if inc_resp.status_code != 200:
            raise HTTPException(status_code=inc_resp.status_code, detail=f"Incident lookup failed: {inc_resp.text}")
        inc = inc_resp.json()["properties"]
        raw_entities = ent_resp.json().get("entities", []) if ent_resp.status_code == 200 else []

    entity_values, entity_summary = [], []
    for e in raw_entities:
        kind = e.get("kind", "Entity")
        p = e.get("properties", {})
        val = p.get("address") or p.get("accountName") or p.get("hostName") or p.get("url") or p.get("friendlyName")
        if val:
            clean_val = str(val).replace("'", "''").strip()
            if clean_val and clean_val not in entity_values:
                entity_values.append(clean_val)
                entity_summary.append(f"{kind}: {clean_val}")

    if entity_values:
        kql_list = ", ".join(f"'{v}'" for v in entity_values[:10])
        entity_kql = f"""
        union isfuzzy=true
          (SecurityEvent | where TimeGenerated > ago(24h) | where IpAddress has_any ({kql_list}) or TargetAccount has_any ({kql_list}) or Computer has_any ({kql_list}) | project TimeGenerated, Table="SecurityEvent", Computer, Account=TargetAccount, IP=IpAddress, Detail=Activity),
          (Syslog | where TimeGenerated > ago(24h) | where SyslogMessage has_any ({kql_list}) or Computer has_any ({kql_list}) | project TimeGenerated, Table="Syslog", Computer, Account="", IP="", Detail=SyslogMessage)
        | top 20 by TimeGenerated desc
        """
        related_kql = f"""
        SecurityAlert
        | where TimeGenerated > ago(7d)
        | where Entities has_any ({kql_list}) or AlertName has_any ({kql_list})
        | summarize Count=count(), LastSeen=max(TimeGenerated) by AlertName, AlertSeverity
        | top 10 by Count desc
        """
    else:
        entity_kql = """
        union isfuzzy=true
          (SecurityEvent | where TimeGenerated > ago(1h) | project TimeGenerated, Table="SecurityEvent", Computer, Detail=Activity),
          (Syslog | where TimeGenerated > ago(1h) | project TimeGenerated, Table="Syslog", Computer, Detail=SyslogMessage)
        | top 15 by TimeGenerated desc
        """
        related_kql = "SecurityAlert | where TimeGenerated > ago(24h) | summarize Count=count() by AlertName, AlertSeverity | top 10 by Count desc"

    entity_logs, related_alerts = await asyncio.gather(
        run_kql(entity_kql, "P1D"),
        run_kql(related_kql, "P7D"),
    )

    return {
        "incident_id": incident_id,
        "title": inc.get("title", ""),
        "severity": inc.get("severity", "Medium"),
        "description": inc.get("description", ""),
        "entities": entity_summary,
        "entity_logs": entity_logs,
        "related_alerts": related_alerts,
    }


@app.post("/api/incidents/{incident_id}/ai-investigate")
async def ai_investigate_incident(incident_id: str, body: AiInvestigateRequest):
    await ensure_db()
    if not gemini_client:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY is missing in Vercel environment variables")

    prompt = (
        f"You are a Senior SOC Analyst. Triage Sentinel Incident '{body.title}' "
        f"(Severity: {body.severity}, Description: {body.description}).\n"
        f"Mapped Entities: {', '.join(body.entities) or 'None'}\n\n"
        f"Provide concise sections:\n"
        f"1. Verdict & Confidence\n"
        f"2. Entity-Specific Log Findings (cite exact timestamps, IPs, accounts, hosts)\n"
        f"3. MITRE ATT&CK Mapping\n"
        f"4. Containment & Eradication Steps\n"
        f"5. Targeted KQL Hunt Query\n\n"
        f"Entity-Scoped Logs (Last 24h):\n{body.entity_logs[:20]}\n\n"
        f"Related Alerts for These Entities (Last 7d):\n{body.related_alerts[:10]}"
    )

    analysis_text, last_status, last_error = None, 502, "Unknown Gemini error"
    # Prioritize low-latency models first so serverless execution stays well under 10s
    for model_name in ("gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-3.8-flash"):
        try:
            ai_resp = await asyncio.wait_for(
                asyncio.to_thread(
                    gemini_client.models.generate_content,
                    model=model_name,
                    contents=prompt,
                ),
                timeout=18.0,
            )
            if ai_resp and ai_resp.text:
                analysis_text = ai_resp.text
                break
        except asyncio.TimeoutError:
            last_status = 504
            last_error = f"[{model_name}] Gemini model timed out after 18s"
        except APIError as api_exc:
            last_status = api_exc.code or 502
            last_error = f"[{model_name}] {api_exc.message or str(api_exc)}"
            if last_status in (400, 401, 403, 429):
                break
        except Exception as exc:
            last_status = 500
            last_error = f"[{model_name}] {str(exc)}"

    if not analysis_text:
        raise HTTPException(status_code=last_status, detail=last_error)

    await turso_exec(
        "UPDATE ticket_state SET ai_analysis = ?, updated_at = ? WHERE incident_id = ?",
        [analysis_text, datetime.now(timezone.utc).isoformat(), incident_id],
    )
    return {"incident_id": incident_id, "ai_analysis": analysis_text}
    await ensure_db()
    if not gemini_client:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY is missing in Vercel environment variables")

    arm_token = await get_azure_token("https://management.azure.com/.default")
    headers = {"Authorization": f"Bearer {arm_token}"}
    inc_url = f"{SENTINEL_BASE}/incidents/{incident_id}?api-version={SENTINEL_API_VER}"
    ent_url = f"{SENTINEL_BASE}/incidents/{incident_id}/entities?api-version={SENTINEL_API_VER}"

    async with httpx.AsyncClient(timeout=15) as client:
        inc_resp, ent_resp = await asyncio.gather(
            client.get(inc_url, headers=headers),
            client.post(ent_url, headers=headers),
        )
        if inc_resp.status_code != 200:
            raise HTTPException(status_code=inc_resp.status_code, detail=f"Incident lookup failed: {inc_resp.text}")
        inc = inc_resp.json()["properties"]
        raw_entities = ent_resp.json().get("entities", []) if ent_resp.status_code == 200 else []

    entity_values, entity_summary = [], []
    for e in raw_entities:
        kind = e.get("kind", "Entity")
        p = e.get("properties", {})
        val = p.get("address") or p.get("accountName") or p.get("hostName") or p.get("url") or p.get("friendlyName")
        if val:
            clean_val = str(val).replace("'", "''").strip()
            if clean_val and clean_val not in entity_values:
                entity_values.append(clean_val)
                entity_summary.append(f"{kind}: {clean_val}")

    if entity_values:
        kql_list = ", ".join(f"'{v}'" for v in entity_values[:10])
        entity_kql = f"""
        union isfuzzy=true
          (SecurityEvent | where TimeGenerated > ago(24h) | where IpAddress has_any ({kql_list}) or TargetAccount has_any ({kql_list}) or Computer has_any ({kql_list}) | project TimeGenerated, Table="SecurityEvent", Computer, Account=TargetAccount, IP=IpAddress, Detail=Activity),
          (Syslog | where TimeGenerated > ago(24h) | where SyslogMessage has_any ({kql_list}) or Computer has_any ({kql_list}) | project TimeGenerated, Table="Syslog", Computer, Account="", IP="", Detail=SyslogMessage)
        | top 25 by TimeGenerated desc
        """
        related_kql = f"""
        SecurityAlert
        | where TimeGenerated > ago(7d)
        | where Entities has_any ({kql_list}) or AlertName has_any ({kql_list})
        | summarize Count=count(), LastSeen=max(TimeGenerated) by AlertName, AlertSeverity
        | top 10 by Count desc
        """
    else:
        entity_kql = """
        union isfuzzy=true
          (SecurityEvent | where TimeGenerated > ago(1h) | project TimeGenerated, Table="SecurityEvent", Computer, Detail=Activity),
          (Syslog | where TimeGenerated > ago(1h) | project TimeGenerated, Table="Syslog", Computer, Detail=SyslogMessage)
        | top 15 by TimeGenerated desc
        """
        related_kql = "SecurityAlert | where TimeGenerated > ago(24h) | summarize Count=count() by AlertName, AlertSeverity | top 10 by Count desc"

    entity_logs, related_alerts = await asyncio.gather(
        run_kql(entity_kql, "P1D"),
        run_kql(related_kql, "P7D"),
    )

    safe_title = inc.get("title", "")
    prompt = (
        f"You are a Senior SOC Analyst. Triage Sentinel Incident '{safe_title}' "
        f"(Severity: {inc.get('severity')}, Description: {inc.get('description')}).\n"
        f"Mapped Entities: {', '.join(entity_summary) or 'None'}\n\n"
        f"Provide concise sections:\n"
        f"1. Verdict & Confidence\n"
        f"2. Entity-Specific Log Findings (cite exact timestamps, IPs, accounts, hosts)\n"
        f"3. MITRE ATT&CK Mapping\n"
        f"4. Containment & Eradication Steps\n"
        f"5. Targeted KQL Hunt Query\n\n"
        f"Entity-Scoped Logs (Last 24h):\n{entity_logs}\n\n"
        f"Related Alerts for These Entities (Last 7d):\n{related_alerts}"
    )

    analysis_text, last_status, last_error = None, 502, "Unknown Gemini error"
    for model_name in ("gemini-3.8-flash", "gemini-3.5-flash", "gemini-3.5-flash-lite"):
        try:
            ai_resp = await asyncio.to_thread(
                gemini_client.models.generate_content, model=model_name, contents=prompt
            )
            if ai_resp and ai_resp.text:
                analysis_text = ai_resp.text
                break
        except APIError as api_exc:
            last_status = api_exc.code or 502
            last_error = f"[{model_name}] {api_exc.message or str(api_exc)}"
            # Stop retrying immediately if API key is invalid or quota is exhausted
            if last_status in (400, 401, 403, 429):
                break
        except Exception as exc:
            last_status = 500
            last_error = f"[{model_name}] {str(exc)}"

    if not analysis_text:
        raise HTTPException(status_code=last_status, detail=last_error)

    await turso_exec(
        "UPDATE ticket_state SET ai_analysis = ?, updated_at = ? WHERE incident_id = ?",
        [analysis_text, datetime.now(timezone.utc).isoformat(), incident_id],
    )
    return {"incident_id": incident_id, "ai_analysis": analysis_text}
# --- 7. Metrics, Topology, VMs & KQL ---
@app.get("/api/metrics")
async def get_soc_metrics():
    await ensure_db()
    rows = await turso_exec("SELECT incident_id, ticket_number, title, severity, assignee, current_stage, created_utc, acknowledged_utc, contained_utc, resolved_utc, sla_minutes FROM ir_lifecycle")
    mtta, mtti, mttr, ledger, met, breached, now = [], [], [], [], 0, 0, datetime.now(timezone.utc)
    parse_ts = lambda v: datetime.fromisoformat(v.replace("Z", "+00:00")) if v else None
    for r in rows:
        t0 = parse_ts(r["created_utc"])
        if not t0: continue
        t_ack, t_cnt, t_res = parse_ts(r["acknowledged_utc"]), parse_ts(r["contained_utc"]), parse_ts(r["resolved_utc"])
        ack_m = round(max(0.1, (t_ack - t0).total_seconds() / 60), 1) if t_ack else None
        cnt_m = round(max(0.1, (t_cnt - t0).total_seconds() / 60), 1) if t_cnt else None
        res_m = round(max(0.1, (t_res - t0).total_seconds() / 60), 1) if t_res else None
        elapsed_m = round(max(0.1, ((t_res or now) - t0).total_seconds() / 60), 1)
        if ack_m is not None: mtta.append(ack_m)
        if cnt_m is not None: mtti.append(cnt_m)
        if res_m is not None: mttr.append(res_m)
        sla_m = r["sla_minutes"] or 60
        is_b = (ack_m if ack_m is not None else elapsed_m) > sla_m
        breached += int(is_b); met += int(not is_b)
        ledger.append({"incident_id": r["incident_id"], "ticket_number": r["ticket_number"] or r["incident_id"][:8], "title": r["title"] or r["incident_id"], "severity": r["severity"], "assignee": r["assignee"], "stage": r["current_stage"], "sla_minutes": sla_m, "ack_mins": ack_m, "contain_mins": cnt_m, "resolve_mins": res_m, "sla_status": "BREACHED" if is_b else "WITHIN SLA"})
    total = len(ledger)
    return {"mtta_mins": round(sum(mtta)/len(mtta), 1) if mtta else 0.0, "mtti_mins": round(sum(mtti)/len(mtti), 1) if mtti else 0.0, "mttr_mins": round(sum(mttr)/len(mttr), 1) if mttr else 0.0, "total_tracked": total, "sla_met": met, "sla_breached": breached, "sla_compliance_pct": round((met/total)*100, 1) if total else 100.0, "ledger": ledger}

@app.get("/api/lab/topology")
async def get_lab_topology():
    arm_token = await get_azure_token("https://management.azure.com/.default")
    headers = {"Authorization": f"Bearer {arm_token}"}
    async def vm_status(name: str, ip: str, os_type: str):
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{ARM_BASE}/providers/Microsoft.Compute/virtualMachines/{name}/instanceView?api-version={COMPUTE_API_VER}", headers=headers)
            power = next((s["displayStatus"] for s in r.json().get("statuses", []) if s.get("code", "").startswith("PowerState/")), "Unknown") if r.status_code == 200 else "Unknown"
            return {"name": name, "os": os_type, "private_ip": ip, "power_state": power, "protected": name == "VM-1"}
    vms, hb = await asyncio.gather(asyncio.gather(vm_status("VM-1", "172.16.0.4", "Ubuntu Linux (B2)"), vm_status("Win-Victim-01", "172.16.0.5", "Windows Server 2022")), run_kql("Heartbeat | summarize LastSeen=max(TimeGenerated) by Computer", "PT24H"))
    return {"resource_group": RG, "region": "East Asia", "virtual_machines": vms, "connected_agents_24h": hb}

@app.post("/api/vms/{vm_name}/{action}")
async def control_vm_power(vm_name: str, action: str, x_admin_secret: Optional[str] = Header(default=None)):
    if vm_name not in {"VM-1", "Win-Victim-01"} or action not in {"start", "deallocate"}:
        raise HTTPException(status_code=400, detail="Invalid VM or action")
    if vm_name == "VM-1" and action == "deallocate" and x_admin_secret != VM_ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Admin Secret Key required to deallocate VM-1")
    arm_token = await get_azure_token("https://management.azure.com/.default")
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(f"{ARM_BASE}/providers/Microsoft.Compute/virtualMachines/{vm_name}/{action}?api-version={COMPUTE_API_VER}", headers={"Authorization": f"Bearer {arm_token}"})
        if resp.status_code not in (200, 202):
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return {"vm": vm_name, "action": action, "status": "Accepted"}

@app.post("/api/lab/kql-execute")
async def execute_kql_query(payload: KqlQueryRequest):
    return {"rows": await run_kql(payload.query, payload.timespan)}
