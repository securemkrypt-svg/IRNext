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

load_dotenv()

app = FastAPI(title="MKRYPT SOC Portfolio Engine", version="3.0.0-vercel-turso")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 1. Configuration & Azure / Turso Endpoints ---
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

# --- 2. Turso HTTP Pipeline Client (Zero Native Drivers Needed for Vercel) ---
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
            ctype = cell.get("type")
            val = cell.get("value")
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
        raise HTTPException(status_code=500, detail="TURSO_DATABASE_URL or TURSO_AUTH_TOKEN missing in environment")

    requests = [
        {"type": "execute", "stmt": {"sql": sql, "args": _encode_args(params)}}
        for sql, params in statements
    ]
    requests.append({"type": "close"})

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{TURSO_URL}/v2/pipeline",
            headers={"Authorization": f"Bearer {TURSO_TOKEN}", "Content-Type": "application/json"},
            json={"requests": requests},
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Turso HTTP error ({resp.status_code}): {resp.text}")

        data = resp.json()
        outputs = []
        for r in data.get("results", [])[:-1]:  # Exclude the trailing "close" response
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
    _db_initialized = True

# --- 3. Dual-Scope Azure OAuth2 Token Cache & KQL Runner ---
_token_cache = {}

async def get_azure_token(scope: str) -> str:
    now = time.time()
    cached = _token_cache.get(scope)
    if cached and cached["expires_at"] > now + 60:
        return cached["token"]
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            url,
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "scope": scope,
                "grant_type": "client_credentials",
            },
        )
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

# --- 4. Pydantic Request Models ---
class AnalystRegisterRequest(BaseModel):
    name: str
    role: str = "L2 Incident Responder"
    email: str

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

class KqlQueryRequest(BaseModel):
    query: str
    timespan: str = "PT24H"

# --- 5. Health & Local SOC Analyst Roster (Turso Backed) ---
@app.get("/api/health")
async def health_check():
    return {
        "status": "online",
        "resource_group": RG,
        "workspace_configured": bool(WS_NAME and WS_ID),
        "gemini_configured": bool(GEMINI_KEY),
        "turso_configured": bool(TURSO_URL and TURSO_TOKEN),
    }

@app.get("/api/analysts")
async def list_analysts():
    await ensure_db()
    return await turso_exec("SELECT * FROM analysts ORDER BY name")

@app.post("/api/analysts")
async def register_analyst(body: AnalystRegisterRequest):
    await ensure_db()
    name = body.name.strip()
    email = body.email.strip()
    if not name or not email:
        raise HTTPException(status_code=400, detail="Name and email are required")

    existing = await turso_exec("SELECT id FROM analysts WHERE lower(email) = lower(?)", [email])
    if existing:
        raise HTTPException(status_code=400, detail="Analyst email is already registered")

    analyst_id = f"soc-{str(uuid.uuid4())[:6]}"
    await turso_exec(
        "INSERT INTO analysts (id, name, role, email) VALUES (?, ?, ?, ?)",
        [analyst_id, name, body.role.strip(), email],
    )
    return {"id": analyst_id, "name": name, "role": body.role.strip(), "email": email}

# --- 6. Sentinel Incidents, 5-Stage IR Workflow & Bidirectional Closure ---
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

    # Fetch all local state in a single batched Turso request
    ticket_rows, ir_rows, note_rows = await turso_batch([
        ("SELECT * FROM ticket_state", None),
        ("SELECT * FROM ir_lifecycle", None),
        ("SELECT * FROM work_notes ORDER BY created_at DESC", None),
    ])

    ticket_map = {r["incident_id"]: r for r in ticket_rows}
    ir_map = {r["incident_id"]: r for r in ir_rows}
    notes_by_inc: dict[str, list] = {}
    for n in note_rows:
        notes_by_inc.setdefault(n["incident_id"], []).append(n)

    # Seed any newly discovered Sentinel incidents into ticket_state in one batch
    new_seeds = []
    for item in items:
        inc_id = item["name"]
        if inc_id not in ticket_map:
            inc_num = item["properties"].get("incidentNumber", 0)
            new_seeds.append((
                "INSERT OR IGNORE INTO ticket_state (incident_id, incident_number, updated_at) VALUES (?, ?, ?)",
                [inc_id, inc_num, now_iso],
            ))
            ticket_map[inc_id] = {
                "incident_id": inc_id,
                "incident_number": inc_num,
                "assigned_to": "T1-Triage-Bin",
                "snow_state": "New",
                "ai_analysis": None,
            }
    if new_seeds:
        await turso_batch(new_seeds)

    results = []
    for item in items:
        inc_id, props = item["name"], item["properties"]
        inc_num = props.get("incidentNumber", 0)
        sev = props.get("severity", "Medium")
        created_utc = props.get("createdTimeUtc")
        local = ticket_map.get(inc_id, {})
        ir = ir_map.get(inc_id, {})
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
        })
    return results

@app.post("/api/incidents/{incident_id}/stage")
async def transition_ir_stage(incident_id: str, body: StageTransitionRequest):
    await ensure_db()
    if len(body.justification.strip()) < 5:
        raise HTTPException(status_code=400, detail="Proper justification (min 5 characters) is required")

    cols = {
        "Assignment": "assigned_utc",
        "Acknowledgement": "acknowledged_utc",
        "Containment": "contained_utc",
        "Eradication": "eradicated_utc",
        "Resolution": "resolved_utc",
    }
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
        c_resp = await client.put(
            f"{SENTINEL_BASE}/incidents/{incident_id}/comments/{comment_id}?api-version={SENTINEL_API_VER}",
            headers=headers,
            json={"properties": {"message": f"[MKRYPT SOC Portal - {body.assignee}] {note_msg}"}},
        )
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

        put_inc = await client.put(
            inc_url,
            headers=headers,
            json={"etag": inc_payload.get("etag"), "properties": props},
        )
        if put_inc.status_code not in (200, 201):
            raise HTTPException(status_code=put_inc.status_code, detail=f"Sentinel sync failed: {put_inc.text}")

    await turso_batch([
        (
            "INSERT INTO ir_lifecycle (incident_id, ticket_number, title, severity, assignee, current_stage, created_utc, sla_minutes, last_justification) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(incident_id) DO UPDATE SET assignee = excluded.assignee, current_stage = excluded.current_stage, last_justification = excluded.last_justification",
            [incident_id, body.ticket_number, body.title, body.severity, body.assignee, body.target_stage, body.created_utc or now_iso, sla_mins, body.justification.strip()],
        ),
        (f"UPDATE ir_lifecycle SET {col} = COALESCE({col}, ?) WHERE incident_id = ?", [now_iso, incident_id]),
        (
            "UPDATE ticket_state SET assigned_to = ?, snow_state = ?, updated_at = ? WHERE incident_id = ?",
            [body.assignee, "Resolved" if body.target_stage == "Resolution" else "In Progress", now_iso, incident_id],
        ),
        (
            "INSERT INTO work_notes (id, incident_id, author, note, synced_to_sentinel, created_at) VALUES (?, ?, ?, ?, 1, ?)",
            [comment_id, incident_id, body.assignee, note_msg, now_iso],
        ),
    ])

    return {"status": "Synced to Sentinel", "ir_stage": body.target_stage, "sentinel_status": props["status"]}

# --- 7. One-Click Gemini AI Triage (3-Query KQL Context) ---
@app.post("/api/incidents/{incident_id}/ai-triage")
async def gemini_ai_triage(incident_id: str):
    await ensure_db()
    if not gemini_client:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY is missing")

    arm_token = await get_azure_token("https://management.azure.com/.default")
    inc_url = f"{SENTINEL_BASE}/incidents/{incident_id}?api-version={SENTINEL_API_VER}"
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(inc_url, headers={"Authorization": f"Bearer {arm_token}"})
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=f"Incident lookup failed: {resp.text}")
        inc = resp.json()["properties"]

    safe_title = inc.get("title", "").replace("'", "''")
    trend_kql = f"SecurityAlert | where TimeGenerated > ago(7d) and AlertName has '{safe_title}' | make-series AlertCount=count() default=0 on TimeGenerated from ago(7d) to now() step 1d | extend (anomalies, score, baseline) = series_decompose_anomalies(AlertCount)"
    host_pattern_kql = "union isfuzzy=true (SecurityEvent | where TimeGenerated > ago(1h) | project TimeGenerated, Computer, Activity, EventID), (Syslog | where TimeGenerated > ago(1h) | project TimeGenerated, Computer, ProcessName, SyslogMessage) | top 20 by TimeGenerated desc"
    related_alerts_kql = "SecurityAlert | where TimeGenerated > ago(24h) | summarize Count=count(), Tactics=make_set(Tactics) by AlertName, AlertSeverity | top 15 by Count desc"

    trend_data, host_events, related_alerts = await asyncio.gather(
        run_kql(trend_kql, "P7D"),
        run_kql(host_pattern_kql, "PT1H"),
        run_kql(related_alerts_kql, "P1D"),
    )
    prompt = (
        f"Analyze Sentinel incident '{safe_title}' (Severity: {inc.get('severity')}). Provide concise triage:\n"
        f"1. Verdict & Confidence\n2. Trend & Anomaly Verification\n3. Pattern & Related Activity Correlation\n4. Containment Steps.\n\n"
        f"Trend:\n{trend_data}\nHost:\n{host_events}\nRelated:\n{related_alerts}"
    )

    analysis_text = None
    last_error = ""
    for model_name in ("gemini-2.5-flash", "gemini-3.5-flash"):
        try:
            ai_resp = await asyncio.to_thread(
                gemini_client.models.generate_content, model=model_name, contents=prompt
            )
            if ai_resp and ai_resp.text:
                analysis_text = ai_resp.text
                break
        except Exception as exc:
            last_error = str(exc)

    if not analysis_text:
        raise HTTPException(status_code=502, detail=f"Gemini triage error: {last_error}")

    await turso_exec(
        "UPDATE ticket_state SET ai_analysis = ?, updated_at = ? WHERE incident_id = ?",
        [analysis_text, datetime.now(timezone.utc).isoformat(), incident_id],
    )
    return {"incident_id": incident_id, "ai_analysis": analysis_text}

# --- 8. Dynamic SOC Metrics (MTTA, MTTI, MTTR & SLA Compliance) ---
@app.get("/api/metrics")
async def get_soc_metrics():
    await ensure_db()
    rows = await turso_exec(
        "SELECT incident_id, ticket_number, title, severity, assignee, current_stage, created_utc, acknowledged_utc, contained_utc, resolved_utc, sla_minutes FROM ir_lifecycle"
    )
    mtta_vals, mtti_vals, mttr_vals, ledger = [], [], [], []
    sla_met, sla_breached = 0, 0
    now = datetime.now(timezone.utc)
    parse_ts = lambda val: datetime.fromisoformat(val.replace("Z", "+00:00")) if val else None

    for r in rows:
        t0 = parse_ts(r["created_utc"])
        if not t0:
            continue
        t_ack, t_cnt, t_res = parse_ts(r["acknowledged_utc"]), parse_ts(r["contained_utc"]), parse_ts(r["resolved_utc"])
        ack_m = round(max(0.1, (t_ack - t0).total_seconds() / 60), 1) if t_ack else None
        cnt_m = round(max(0.1, (t_cnt - t0).total_seconds() / 60), 1) if t_cnt else None
        res_m = round(max(0.1, (t_res - t0).total_seconds() / 60), 1) if t_res else None
        elapsed_m = round(max(0.1, ((t_res or now) - t0).total_seconds() / 60), 1)

        if ack_m is not None:
            mtta_vals.append(ack_m)
        if cnt_m is not None:
            mtti_vals.append(cnt_m)
        if res_m is not None:
            mttr_vals.append(res_m)

        sla_m = r["sla_minutes"] or 60
        breached = (ack_m if ack_m is not None else elapsed_m) > sla_m
        if breached:
            sla_breached += 1
        else:
            sla_met += 1

        ledger.append({
            "incident_id": r["incident_id"],
            "ticket_number": r["ticket_number"] or r["incident_id"][:8],
            "title": r["title"] or r["incident_id"],
            "severity": r["severity"],
            "assignee": r["assignee"],
            "stage": r["current_stage"],
            "sla_minutes": sla_m,
            "ack_mins": ack_m,
            "contain_mins": cnt_m,
            "resolve_mins": res_m,
            "sla_status": "BREACHED" if breached else "WITHIN SLA",
        })

    total = len(ledger)
    return {
        "mtta_mins": round(sum(mtta_vals) / len(mtta_vals), 1) if mtta_vals else 0.0,
        "mtti_mins": round(sum(mtti_vals) / len(mtti_vals), 1) if mtti_vals else 0.0,
        "mttr_mins": round(sum(mttr_vals) / len(mttr_vals), 1) if mttr_vals else 0.0,
        "total_tracked": total,
        "sla_met": sla_met,
        "sla_breached": sla_breached,
        "sla_compliance_pct": round((sla_met / total) * 100, 1) if total else 100.0,
        "ledger": ledger,
    }

# --- 9. Lab Topology, Secret-Key Protected VM Power Control & KQL Sandbox ---
@app.get("/api/lab/topology")
async def get_lab_topology():
    arm_token = await get_azure_token("https://management.azure.com/.default")
    headers = {"Authorization": f"Bearer {arm_token}"}

    async def vm_status(vm_name: str, private_ip: str, os_type: str):
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"{ARM_BASE}/providers/Microsoft.Compute/virtualMachines/{vm_name}/instanceView?api-version={COMPUTE_API_VER}",
                headers=headers,
            )
            power = "Unknown"
            if r.status_code == 200:
                for st in r.json().get("statuses", []):
                    if st.get("code", "").startswith("PowerState/"):
                        power = st["displayStatus"]
            return {
                "name": vm_name,
                "os": os_type,
                "private_ip": private_ip,
                "power_state": power,
                "protected": vm_name == "VM-1",
            }

    vms, heartbeat = await asyncio.gather(
        asyncio.gather(
            vm_status("VM-1", "172.16.0.4", "Ubuntu Linux (B2)"),
            vm_status("Win-Victim-01", "172.16.0.5", "Windows Server 2022"),
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
async def control_vm_power(vm_name: str, action: str, x_admin_secret: Optional[str] = Header(default=None)):
    if vm_name not in {"VM-1", "Win-Victim-01"} or action not in {"start", "deallocate"}:
        raise HTTPException(status_code=400, detail="Use VM-1 or Win-Victim-01 and start or deallocate")
    if vm_name == "VM-1" and action == "deallocate" and x_admin_secret != VM_ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Admin Secret Key required to deallocate VM-1")

    arm_token = await get_azure_token("https://management.azure.com/.default")
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(
            f"{ARM_BASE}/providers/Microsoft.Compute/virtualMachines/{vm_name}/{action}?api-version={COMPUTE_API_VER}",
            headers={"Authorization": f"Bearer {arm_token}"},
        )
        if resp.status_code not in (200, 202):
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return {"vm": vm_name, "action": action, "status": "Accepted"}

@app.get("/api/lab/kql-sandbox")
async def get_kql_sandbox():
    return {
        "portal_url": "https://portal.azure.com",
        "username": os.getenv("SOC_VIEWER_UPN"),
        "password": os.getenv("SOC_VIEWER_PASS"),
        "rbac_roles": ["Microsoft Sentinel Reader", "Log Analytics Reader"],
        "sample_queries": [
            {"title": "Failed Logon Brute-Force Hunt", "kql": "SecurityEvent | where EventID == 4625 | summarize Attempts=count() by TargetAccount, IpAddress | top 15 by Attempts desc"},
            {"title": "Linux SSH Failed Logins", "kql": "Syslog | where Facility in ('auth','authpriv') and SyslogMessage has 'Failed password' | summarize Count=count() by Computer, ProcessName"},
            {"title": "All Connected Hosts Heartbeat", "kql": "Heartbeat | summarize LastHeartbeat=max(TimeGenerated) by Computer, OSType, ComputerIP"},
        ],
    }

@app.post("/api/lab/kql-execute")
async def execute_kql_query(payload: KqlQueryRequest):
    rows = await run_kql(payload.query, payload.timespan)
    return {"rows": rows}
