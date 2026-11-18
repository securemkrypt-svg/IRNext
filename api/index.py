import os
import time
import uuid
import json
import sqlite3
import asyncio
from datetime import datetime, timezone
from typing import Optional
import httpx
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from google import genai

try:
    import libsql_client
except ImportError:
    libsql_client = None

load_dotenv()

app = FastAPI(title="MKRYPT SOC Portfolio Engine", version="2.0.0-vercel")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 1. Configuration & Azure Endpoints ---
TENANT_ID = os.getenv("AZURE_TENANT_ID", "").strip()
CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "").strip()
SUB_ID = os.getenv("AZURE_SUBSCRIPTION_ID", "f1dcd00a-9833-4213-aedb-0554245829ee").strip()
RG = os.getenv("AZURE_RESOURCE_GROUP", "SENTINEL-LAB").strip()
WS_NAME = os.getenv("AZURE_WORKSPACE_NAME", "").strip()
WS_ID = os.getenv("AZURE_WORKSPACE_ID", "").strip()
GEMINI_KEY = os.getenv("GEMINI_API_KEY", "").strip()
VM_ADMIN_SECRET = os.getenv("VM_ADMIN_SECRET", "MkryptAdmin@2026").strip()

# Turso Cloud SQLite (Set TURSO_DATABASE_URL & TURSO_AUTH_TOKEN in Vercel Env Vars)
TURSO_URL = os.getenv("TURSO_DATABASE_URL", "").strip()
TURSO_TOKEN = os.getenv("TURSO_AUTH_TOKEN", "").strip()
LOCAL_TMP_DB = "/tmp/mkrypt_soc.db"

ARM_BASE = f"https://management.azure.com/subscriptions/{SUB_ID}/resourceGroups/{RG}"
SENTINEL_BASE = (
    f"{ARM_BASE}/providers/Microsoft.OperationalInsights/workspaces/{WS_NAME}"
    f"/providers/Microsoft.SecurityInsights"
)
SENTINEL_API_VER = "2025-09-01"
COMPUTE_API_VER = "2024-07-01"

gemini_client = genai.Client(api_key=GEMINI_KEY) if GEMINI_KEY else None

SLA_TARGETS = {"High": 30, "Medium": 60, "Low": 240, "Informational": 480}
IR_STAGES = ["Assignment", "Acknowledgement", "Containment", "Eradication", "Resolution"]

# --- 2. Cloud Persistence Layer (Turso HTTP SQLite with /tmp Fallback) ---
async def db_exec(sql: str, params: tuple = ()) -> list[dict]:
    if TURSO_URL and TURSO_TOKEN and libsql_client:
        http_url = TURSO_URL.replace("libsql://", "https://")
        async with libsql_client.create_client(url=http_url, auth_token=TURSO_TOKEN) as client:
            rs = await client.execute(sql, list(params))
            cols = rs.columns
            return [dict(zip(cols, row)) for row in rs.rows]
    else:
        def _sync_run():
            with sqlite3.connect(LOCAL_TMP_DB) as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.execute(sql, params)
                if cur.description:
                    return [dict(r) for r in cur.fetchall()]
                conn.commit()
                return []
        return await asyncio.to_thread(_sync_run)

_db_initialized = False

async def ensure_db():
    global _db_initialized
    if _db_initialized:
        return
    await db_exec("""
        CREATE TABLE IF NOT EXISTS analysts (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT NOT NULL
        )
    """)
    await db_exec("""
        CREATE TABLE IF NOT EXISTS ticket_state (
            incident_id TEXT PRIMARY KEY,
            incident_number INTEGER,
            title TEXT,
            severity TEXT DEFAULT 'Medium',
            created_utc TEXT,
            assigned_to TEXT DEFAULT 'T1-Triage-Bin',
            ir_stage TEXT DEFAULT 'Assignment',
            ir_timestamps TEXT DEFAULT '{}',
            classification TEXT,
            ai_analysis TEXT,
            qa_audit TEXT,
            updated_at TEXT
        )
    """)
    await db_exec("""
        CREATE TABLE IF NOT EXISTS work_notes (
            id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            author TEXT NOT NULL,
            note TEXT NOT NULL,
            stage_tag TEXT DEFAULT 'General',
            screenshot_b64 TEXT,
            screenshot_name TEXT,
            synced_to_sentinel INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)
    seeds = [
        ("bin", "T1-Triage-Bin", "Unassigned Queue", "soc-queue@mkrypt.local"),
        ("mohan", "Mohan Krishna", "Senior Threat Detection Engineer", "mohan@mkrypt.local"),
        ("analyst1", "Tier-1 SOC Analyst", "Incident Responder", "t1-analyst@mkrypt.local"),
    ]
    for aid, name, role, email in seeds:
        await db_exec(
            "INSERT OR IGNORE INTO analysts (id, name, role, email) VALUES (?, ?, ?, ?)",
            (aid, name, role, email),
        )
    _db_initialized = True

# --- 3. Dual-Scope Azure OAuth2 Token Cache & KQL Runner ---
_token_cache = {}

async def get_azure_token(scope: str) -> str:
    now = time.time()
    cached = _token_cache.get(scope)
    if cached and cached["expires_at"] > now + 60:
        return cached["token"]

    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": scope,
        "grant_type": "client_credentials",
    }
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, data=data)
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Azure OAuth2 failed: {resp.text}")
        payload = resp.json()
        _token_cache[scope] = {
            "token": payload["access_token"],
            "expires_at": now + int(payload.get("expires_in", 3599)),
        }
        return payload["access_token"]

async def run_kql(query: str, timespan: str = "P7D") -> list[dict]:
    token = await get_azure_token("https://api.loganalytics.io/.default")
    url = f"https://api.loganalytics.io/v1/workspaces/{WS_ID}/query"
    async with httpx.AsyncClient(timeout=25) as client:
        resp = await client.post(
            url,
            headers={"Authorization": f"Bearer {token}"},
            json={"query": query, "timespan": timespan},
        )
        if resp.status_code != 200:
            return [{"error": resp.text}]
        tables = resp.json().get("tables", [])
        if not tables:
            return []
        cols = [c["name"] for c in tables[0]["columns"]]
        return [dict(zip(cols, row)) for row in tables[0]["rows"]]

# --- 4. Health, Topology & VM Power Toggle Endpoints ---
@app.get("/api/health")
async def health_check():
    return {
        "status": "online",
        "runtime": "vercel-serverless",
        "persistence": "turso-cloud" if (TURSO_URL and TURSO_TOKEN) else "ephemeral-tmp",
        "resource_group": RG,
        "workspace_configured": bool(WS_NAME and WS_ID),
        "gemini_configured": bool(GEMINI_KEY),
    }

@app.get("/api/lab/topology")
async def get_lab_topology():
    arm_token = await get_azure_token("https://management.azure.com/.default")
    headers = {"Authorization": f"Bearer {arm_token}"}

    async def vm_status(vm_name: str, private_ip: str, os_type: str):
        url = f"{ARM_BASE}/providers/Microsoft.Compute/virtualMachines/{vm_name}/instanceView?api-version={COMPUTE_API_VER}"
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url, headers=headers)
            power = "Unknown"
            if r.status_code == 200:
                for st in r.json().get("statuses", []):
                    if st.get("code", "").startswith("PowerState/"):
                        power = st["displayStatus"]
            return {"name": vm_name, "os": os_type, "private_ip": private_ip, "power_state": power}

    vms, heartbeat = await asyncio.gather(
        asyncio.gather(
            vm_status("VM-1", "172.16.0.4", "Ubuntu Linux (B2)"),
            vm_status("Win-Victim-01", "172.16.0.5", "Windows Server 2022 (B2als_v2)"),
        ),
        run_kql("Heartbeat | summarize LastSeen=max(TimeGenerated), Category=any(Category) by Computer", "PT24H"),
    )
    return {
        "resource_group": RG,
        "region": "East Asia",
        "virtual_machines": vms,
        "connected_agents_24h": heartbeat,
    }

@app.post("/api/vms/{vm_name}/{action}")
async def control_vm_power(
    vm_name: str,
    action: str,
    x_admin_secret: Optional[str] = Header(default=""),
):
    if vm_name not in {"VM-1", "Win-Victim-01"} or action not in {"start", "deallocate"}:
        raise HTTPException(status_code=400, detail="Use VM-1 or Win-Victim-01 with start or deallocate")
    if vm_name == "VM-1" and action == "deallocate" and x_admin_secret != VM_ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Invalid VM_ADMIN_SECRET for VM-1 deallocation")

    arm_token = await get_azure_token("https://management.azure.com/.default")
    url = f"{ARM_BASE}/providers/Microsoft.Compute/virtualMachines/{vm_name}/{action}?api-version={COMPUTE_API_VER}"
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(url, headers={"Authorization": f"Bearer {arm_token}"})
        if resp.status_code not in (200, 202):
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return {"vm": vm_name, "action": action, "status": "Accepted"}

@app.get("/api/lab/kql-sandbox")
async def get_kql_sandbox():
    return {
        "portal_url": "https://portal.azure.com",
        "username": os.getenv("SOC_VIEWER_UPN", "soc-viewer@mkrypt.local"),
        "password": os.getenv("SOC_VIEWER_PASS", "ReadOnlySoc@2026"),
        "rbac_roles": ["Microsoft Sentinel Reader", "Log Analytics Reader"],
        "sample_queries": [
            {
                "title": "Failed Logon Brute-Force Hunt",
                "kql": "SecurityEvent | where EventID == 4625 | summarize Attempts=count() by TargetUserName, IpAddress, Computer | where Attempts > 3",
            },
            {
                "title": "Linux SSH Failed Logins",
                "kql": "Syslog | where Facility in ('auth','authpriv') and SyslogMessage has 'Failed password' | summarize Failures=count() by Computer, HostIP",
            },
            {
                "title": "All Connected Hosts Heartbeat",
                "kql": "Heartbeat | summarize LastHeartbeat=max(TimeGenerated) by Computer, OSType, Version",
            },
        ],
    }

class KqlExecRequest(BaseModel):
    query: str
    timespan: str = "PT24H"

@app.post("/api/lab/kql-execute")
async def execute_kql_sandbox(body: KqlExecRequest):
    if not body.query.strip():
        raise HTTPException(status_code=400, detail="KQL query cannot be empty")
    rows = await run_kql(body.query, body.timespan)
    return {"count": len(rows), "rows": rows}

# --- 5. Analysts, 5-Stage IR Lifecycle & Bidirectional Sentinel Sync ---
class AnalystCreate(BaseModel):
    name: str
    role: str = "L2 Incident Responder"
    email: str

class StageTransitionRequest(BaseModel):
    assignee: str
    target_stage: str
    justification: str
    classification: Optional[str] = "TruePositive"
    created_utc: Optional[str] = None
    severity: Optional[str] = "Medium"
    title: Optional[str] = ""
    ticket_number: Optional[str] = ""

class WorkNoteRequest(BaseModel):
    author: str
    note: str
    stage_tag: Optional[str] = "General"
    screenshot_b64: Optional[str] = None
    screenshot_name: Optional[str] = None

@app.get("/api/analysts")
async def list_analysts():
    await ensure_db()
    return await db_exec("SELECT * FROM analysts")

@app.post("/api/analysts")
async def create_analyst(body: AnalystCreate):
    await ensure_db()
    aid = f"analyst-{uuid.uuid4().hex[:6]}"
    await db_exec(
        "INSERT INTO analysts (id, name, role, email) VALUES (?, ?, ?, ?)",
        (aid, body.name.strip(), body.role.strip(), body.email.strip()),
    )
    return {"id": aid, "name": body.name, "role": body.role, "email": body.email}

@app.get("/api/incidents")
async def list_incidents():
    await ensure_db()
    arm_token = await get_azure_token("https://management.azure.com/.default")
    url = f"{SENTINEL_BASE}/incidents?api-version={SENTINEL_API_VER}&$top=30"
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {arm_token}"})
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)

    items = resp.json().get("value", [])
    results = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for item in items:
        inc_id = item["name"]
        props = item["properties"]
        inc_num = props.get("incidentNumber", 0)
        sev = props.get("severity", "Medium")
        title = props.get("title", "")
        created_utc = props.get("createdTimeUtc", now_iso)

        await db_exec(
            """INSERT OR IGNORE INTO ticket_state
               (incident_id, incident_number, title, severity, created_utc, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (inc_id, inc_num, title, sev, created_utc, now_iso),
        )
        rows = await db_exec("SELECT * FROM ticket_state WHERE incident_id = ?", (inc_id,))
        local = rows[0]
        notes = await db_exec(
            "SELECT * FROM work_notes WHERE incident_id = ? ORDER BY created_at ASC",
            (inc_id,),
        )
        try:
            ts_map = json.loads(local.get("ir_timestamps") or "{}")
        except Exception:
            ts_map = {}

        results.append({
            "incident_id": inc_id,
            "ticket_number": f"INC-{inc_num:05d}",
            "title": title,
            "description": props.get("description", ""),
            "severity": sev,
            "sla_minutes": SLA_TARGETS.get(sev, 60),
            "sentinel_status": props.get("status"),
            "created_time": created_utc,
            "tactics": props.get("tactics", []),
            "assigned_to": local.get("assigned_to", "T1-Triage-Bin"),
            "ir_stage": local.get("ir_stage", "Assignment"),
            "ir_timestamps": ts_map,
            "classification": local.get("classification"),
            "ai_analysis": local.get("ai_analysis"),
            "qa_audit": local.get("qa_audit"),
            "work_notes": notes,
        })
    return results

@app.post("/api/incidents/{incident_id}/stage")
async def transition_ir_stage(incident_id: str, body: StageTransitionRequest):
    await ensure_db()
    if body.target_stage not in IR_STAGES:
        raise HTTPException(status_code=400, detail=f"Invalid stage: {body.target_stage}")

    now_iso = datetime.now(timezone.utc).isoformat()
    rows = await db_exec("SELECT * FROM ticket_state WHERE incident_id = ?", (incident_id,))
    if not rows:
        await db_exec(
            "INSERT INTO ticket_state (incident_id, title, severity, created_utc, updated_at) VALUES (?, ?, ?, ?, ?)",
            (incident_id, body.title, body.severity, body.created_utc or now_iso, now_iso),
        )
        rows = await db_exec("SELECT * FROM ticket_state WHERE incident_id = ?", (incident_id,))

    local = rows[0]
    try:
        ts_map = json.loads(local.get("ir_timestamps") or "{}")
    except Exception:
        ts_map = {}
    ts_map[body.target_stage] = now_iso

    # Sync stage comment & Sentinel status (Active / Closed)
    arm_token = await get_azure_token("https://management.azure.com/.default")
    headers = {"Authorization": f"Bearer {arm_token}", "Content-Type": "application/json"}
    comment_id = str(uuid.uuid4())
    formatted_note = f"[IR Phase: {body.target_stage}] {body.justification}"

    async with httpx.AsyncClient(timeout=20) as client:
        c_url = f"{SENTINEL_BASE}/incidents/{incident_id}/comments/{comment_id}?api-version={SENTINEL_API_VER}"
        await client.put(
            c_url,
            headers=headers,
            json={"properties": {"message": f"[MKRYPT SOC - {body.assignee}] {formatted_note}"}},
        )

        sentinel_status = "Closed" if body.target_stage == "Resolution" else "Active"
        inc_url = f"{SENTINEL_BASE}/incidents/{incident_id}?api-version={SENTINEL_API_VER}"
        get_inc = await client.get(inc_url, headers=headers)
        if get_inc.status_code == 200:
            payload = get_inc.json()
            payload["properties"]["status"] = sentinel_status
            if sentinel_status == "Closed":
                payload["properties"]["classification"] = body.classification or "TruePositive"
                payload["properties"]["classificationComment"] = body.justification
            await client.put(inc_url, headers=headers, json=payload)

    await db_exec(
        """UPDATE ticket_state
           SET assigned_to = ?, ir_stage = ?, ir_timestamps = ?, classification = ?, updated_at = ?
           WHERE incident_id = ?""",
        (body.assignee, body.target_stage, json.dumps(ts_map), body.classification, now_iso, incident_id),
    )
    await db_exec(
        """INSERT INTO work_notes (id, incident_id, author, note, stage_tag, synced_to_sentinel, created_at)
           VALUES (?, ?, ?, ?, ?, 1, ?)""",
        (comment_id, incident_id, body.assignee, formatted_note, body.target_stage, now_iso),
    )
    return {"status": "Transitioned", "stage": body.target_stage, "timestamps": ts_map}

@app.post("/api/incidents/{incident_id}/notes")
async def add_bidirectional_work_note(incident_id: str, body: WorkNoteRequest):
    await ensure_db()
    arm_token = await get_azure_token("https://management.azure.com/.default")
    headers = {"Authorization": f"Bearer {arm_token}", "Content-Type": "application/json"}
    comment_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    async with httpx.AsyncClient(timeout=20) as client:
        comment_url = f"{SENTINEL_BASE}/incidents/{incident_id}/comments/{comment_id}?api-version={SENTINEL_API_VER}"
        c_resp = await client.put(
            comment_url,
            headers=headers,
            json={"properties": {"message": f"[MKRYPT SOC ({body.stage_tag}) - {body.author}]: {body.note or 'Attached evidence screenshot'}"}},
        )
        if c_resp.status_code not in (200, 201):
            raise HTTPException(status_code=c_resp.status_code, detail=f"Sentinel comment sync failed: {c_resp.text}")

    await db_exec(
        """INSERT INTO work_notes
           (id, incident_id, author, note, stage_tag, screenshot_b64, screenshot_name, synced_to_sentinel, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)""",
        (comment_id, incident_id, body.author, body.note, body.stage_tag, body.screenshot_b64, body.screenshot_name, now_iso),
    )
    return {
        "id": comment_id,
        "incident_id": incident_id,
        "author": body.author,
        "note": body.note,
        "stage_tag": body.stage_tag,
        "screenshot_b64": body.screenshot_b64,
        "screenshot_name": body.screenshot_name,
        "created_at": now_iso,
    }

# --- 6. Gemini AI Triage & Principal L2 QA Audit ---
async def call_gemini(prompt: str) -> str:
    if not gemini_client:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY is missing in Vercel Environment Variables")
    last_error = ""
    for model_name in ("gemini-2.5-flash", "gemini-2.5-pro"):
        for attempt in range(2):
            try:
                ai_resp = await asyncio.to_thread(
                    gemini_client.models.generate_content,
                    model=model_name,
                    contents=prompt,
                )
                if ai_resp and ai_resp.text:
                    return ai_resp.text
            except Exception as exc:
                last_error = f"{model_name} (attempt {attempt + 1}): {exc}"
                await asyncio.sleep(1.0)
    raise HTTPException(status_code=502, detail=f"Gemini error — {last_error}")

@app.post("/api/incidents/{incident_id}/ai-triage")
async def gemini_ai_triage(incident_id: str):
    await ensure_db()
    arm_token = await get_azure_token("https://management.azure.com/.default")
    inc_url = f"{SENTINEL_BASE}/incidents/{incident_id}?api-version={SENTINEL_API_VER}"
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(inc_url, headers={"Authorization": f"Bearer {arm_token}"})
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        inc = resp.json()["properties"]

    title = inc.get("title", "")
    safe_title = title.replace("'", "''")

    trend_kql = f"""
    SecurityAlert
    | where TimeGenerated > ago(7d) and AlertName has '{safe_title}'
    | make-series AlertCount=count() default=0 on TimeGenerated from ago(7d) to now() step 1d
    | extend (anomalies, score, baseline) = series_decompose_anomalies(AlertCount, 1.5, -1, 'linefit')
    """
    host_pattern_kql = """
    union isfuzzy=true
      (SecurityEvent | where TimeGenerated > ago(1h) | project TimeGenerated, Computer, EventID=tostring(EventID), Detail=Activity),
      (Syslog | where TimeGenerated > ago(1h) | project TimeGenerated, Computer, EventID=Facility, Detail=SyslogMessage)
    | top 20 by TimeGenerated desc
    """
    related_alerts_kql = """
    SecurityAlert
    | where TimeGenerated > ago(24h)
    | summarize Count=count(), Tactics=make_set(Tactics) by AlertName, AlertSeverity, CompromisedEntity
    | top 15 by Count desc
    """

    trend_data, host_events, related_alerts = await asyncio.gather(
        run_kql(trend_kql, "P7D"),
        run_kql(host_pattern_kql, "PT1H"),
        run_kql(related_alerts_kql, "P1D"),
    )

    prompt = f"""
    You are a Senior SOC Incident Responder analyzing a live Microsoft Sentinel incident from a hybrid lab (Windows Server 2022 'Win-Victim-01', Ubuntu 'VM-1', and Windows Host 'MOHAN_KRISHNA').

    INCIDENT METADATA:
    - Title: {title}
    - Severity: {inc.get('severity')}
    - Description: {inc.get('description')}
    - MITRE Tactics: {inc.get('tactics')}

    1. 7-DAY HISTORICAL TREND & ANOMALY DECOMPOSITION:
    {trend_data}

    2. RECENT HOST TELEMETRY PATTERN (Last 1 Hour):
    {host_events}

    3. RELATED ALERTS & ENTITIES (Last 24 Hours):
    {related_alerts}

    Provide a concise, actionable SOC triage report covering:
    1. **Verdict & Confidence** (True Positive / Benign Positive / False Positive)
    2. **Trend & Anomaly Verification**
    3. **Pattern & Related Activity Correlation**
    4. **Tailored KQL Hunt Queries & Containment Steps**
    """

    analysis_text = await call_gemini(prompt)
    await db_exec(
        "UPDATE ticket_state SET ai_analysis = ?, updated_at = ? WHERE incident_id = ?",
        (analysis_text, datetime.now(timezone.utc).isoformat(), incident_id),
    )
    return {"incident_id": incident_id, "ai_analysis": analysis_text}

@app.post("/api/incidents/{incident_id}/audit-score")
async def audit_incident_response(incident_id: str):
    await ensure_db()
    rows = await db_exec("SELECT * FROM ticket_state WHERE incident_id = ?", (incident_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="Ticket state not found")
    local = rows[0]
    notes = await db_exec("SELECT author, stage_tag, note, created_at FROM work_notes WHERE incident_id = ?", (incident_id,))

    prompt = f"""
    You are a Principal L2/L3 SOC Quality Auditor evaluating an incident investigation against NIST SP 800-61r2 standards.
    - Incident: {local.get('title')} (Severity: {local.get('severity')})
    - Assignee: {local.get('assigned_to')}
    - Current Stage: {local.get('ir_stage')}
    - Timestamps: {local.get('ir_timestamps')}
    - Work Notes: {notes}

    Provide a structured QA Audit Scorecard (Score out of 100) evaluating:
    1. SLA & Triage Timeliness
    2. Evidence & IOC Documentation Quality
    3. Containment & Eradication Completeness
    4. Specific Coaching Recommendations
    """
    audit_text = await call_gemini(prompt)
    await db_exec(
        "UPDATE ticket_state SET qa_audit = ?, updated_at = ? WHERE incident_id = ?",
        (audit_text, datetime.now(timezone.utc).isoformat(), incident_id),
    )
    return {"incident_id": incident_id, "qa_audit": audit_text}

# --- 7. IR Metrics & SLA Analytics Ledger (MTTA / MTTI / MTTR) ---
@app.get("/api/metrics")
async def get_ir_metrics():
    await ensure_db()
    rows = await db_exec("SELECT * FROM ticket_state ORDER BY incident_number DESC")
    ack_list, contain_list, resolve_list = [], [], []
    sla_met, sla_breached = 0, 0
    ledger = []

    for r in rows:
        sev = r.get("severity") or "Medium"
        sla_target = SLA_TARGETS.get(sev, 60)
        created_str = r.get("created_utc")
        try:
            ts_map = json.loads(r.get("ir_timestamps") or "{}")
        except Exception:
            ts_map = {}

        def diff_mins(target_iso):
            if not created_str or not target_iso:
                return None
            c_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            t_dt = datetime.fromisoformat(target_iso.replace("Z", "+00:00"))
            return max(0, round((t_dt - c_dt).total_seconds() / 60, 1))

        ack_m = diff_mins(ts_map.get("Acknowledgement"))
        con_m = diff_mins(ts_map.get("Containment"))
        res_m = diff_mins(ts_map.get("Resolution"))

        if ack_m is not None:
            ack_list.append(ack_m)
        if con_m is not None:
            contain_list.append(con_m)
        if res_m is not None:
            resolve_list.append(res_m)

        check_m = ack_m if ack_m is not None else diff_mins(datetime.now(timezone.utc).isoformat())
        if check_m is not None and check_m <= sla_target:
            sla_status = "MET"
            sla_met += 1
        else:
            sla_status = "BREACHED"
            sla_breached += 1

        ledger.append({
            "ticket_number": f"INC-{(r.get('incident_number') or 0):05d}",
            "title": r.get("title"),
            "severity": sev,
            "assignee": r.get("assigned_to"),
            "stage": r.get("ir_stage"),
            "sla_minutes": sla_target,
            "ack_mins": ack_m,
            "contain_mins": con_m,
            "resolve_mins": res_m,
            "sla_status": sla_status,
        })

    avg = lambda arr: round(sum(arr) / len(arr), 1) if arr else 0.0
    total = len(ledger)
    return {
        "mtta_mins": avg(ack_list),
        "mtti_mins": avg(contain_list),
        "mttr_mins": avg(resolve_list),
        "sla_compliance_pct": round((sla_met / total) * 100, 1) if total else 100.0,
        "total_tracked": total,
        "sla_met": sla_met,
        "sla_breached": sla_breached,
        "ledger": ledger,
    }
