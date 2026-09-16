"""HTTP + WebSocket API, and the guard that makes LAN mode safe."""
from __future__ import annotations

import json
import re

from fastapi import (Body, FastAPI, File, Form, HTTPException, Query, Request,
                     Response, UploadFile, WebSocket, WebSocketDisconnect)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import (auth, certs, config, db, diff, glossary, interpret, quiz, report,
               runner, scheduler, tools, validate)
from .tools.base import ScanPlan

app = FastAPI(title=config.APP_NAME, docs_url=None, redoc_url=None)

PUBLIC_PATHS = {"/api/meta", "/api/setup", "/api/login", "/login", "/favicon.ico"}
PUBLIC_PREFIXES = ("/static/",)


@app.on_event("startup")
def _startup() -> None:
    db.init_db()
    auth.purge_expired()
    scheduler.start()


@app.on_event("shutdown")
def _shutdown() -> None:
    scheduler.stop()


# --- auth guard -------------------------------------------------------------
@app.middleware("http")
async def require_session(request: Request, call_next):
    if not config.requires_auth():
        return await call_next(request)
    path = request.url.path
    if path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES):
        return await call_next(request)
    if not auth.user_exists():
        # No account yet: only the setup flow is reachable.
        if path == "/" or path.startswith("/api/setup"):
            return await call_next(request)
        return JSONResponse({"error": "setup_required",
                             "message": "Create the ReconScan account first."}, status_code=401)
    user = auth.session_user(request.cookies.get(auth.COOKIE_NAME))
    if user is None:
        if path == "/":
            return await call_next(request)  # the UI renders its own login screen
        return JSONResponse(
            {"error": "auth_required",
             "message": "Sign in to use ReconScan from another device on the network."},
            status_code=401)
    request.state.user = user
    return await call_next(request)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _user_id(request: Request) -> str | None:
    u = getattr(request.state, "user", None)
    return u["id"] if u else None


# --- meta / auth ------------------------------------------------------------
@app.get("/api/meta")
def meta(request: Request) -> dict:
    user = None
    if config.requires_auth():
        user = auth.session_user(request.cookies.get(auth.COOKIE_NAME))
    return {
        "app": config.APP_NAME,
        "version": config.APP_VERSION,
        "host": config.HOST,
        "port": config.PORT,
        "lan_mode": config.requires_auth(),
        "auth_required": config.requires_auth(),
        "setup_required": config.requires_auth() and not auth.user_exists(),
        "authenticated": (user is not None) or not config.requires_auth(),
        "username": user["username"] if user else None,
        "demo_default": config.DEMO_DEFAULT,
        "tools_installed": runner.tool_availability(),
        "cert_fingerprint": certs.fingerprint() if config.requires_auth() else "",
        "min_password_len": auth.MIN_PASSWORD_LEN,
    }


@app.post("/api/setup")
def setup(request: Request, username: str = Body(...), password: str = Body(...)) -> dict:
    try:
        user = auth.create_user(username, password)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    token = auth.login(username, password, _client_key(request))
    resp = JSONResponse({"ok": True, "username": user["username"]})
    _set_cookie(resp, token, request)
    return resp


@app.post("/api/login")
def login(request: Request, username: str = Body(...), password: str = Body(...)):
    try:
        token = auth.login(username, password, _client_key(request))
    except PermissionError as exc:
        raise HTTPException(401, str(exc)) from exc
    resp = JSONResponse({"ok": True, "username": username})
    _set_cookie(resp, token, request)
    return resp


def _set_cookie(resp: Response, token: str, request: Request) -> None:
    resp.set_cookie(
        auth.COOKIE_NAME, token, httponly=True, samesite="lax",
        secure=request.url.scheme == "https",
        max_age=config.SESSION_TTL_HOURS * 3600, path="/")


@app.post("/api/logout")
def logout(request: Request):
    auth.logout(request.cookies.get(auth.COOKIE_NAME))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE_NAME, path="/")
    return resp


@app.post("/api/password")
def password(request: Request, old: str = Body(...), new: str = Body(...)) -> dict:
    try:
        auth.change_password(old, new)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True, "message": "Password changed. All other sessions were signed out."}


# --- projects ---------------------------------------------------------------
@app.get("/api/projects")
def list_projects() -> list[dict]:
    with db.connect() as conn:
        rows = db.rows_to_list(conn.execute(
            "SELECT p.*, "
            " (SELECT COUNT(*) FROM targets t WHERE t.project_id=p.id) AS target_count,"
            " (SELECT COUNT(*) FROM scans s WHERE s.project_id=p.id) AS scan_count "
            "FROM projects p ORDER BY created_at DESC"))
    return rows


@app.post("/api/projects")
def create_project(request: Request, name: str = Body(...),
                   authorization_note: str = Body(...),
                   acknowledged: bool = Body(False)) -> dict:
    name = (name or "").strip()
    note = (authorization_note or "").strip()
    if not name:
        raise HTTPException(400, "Give the project a name.")
    if len(note) < 15:
        raise HTTPException(400, (
            "Describe what authorizes this testing in at least a sentence - for example "
            "'CS-410 lab 3, instructor-provided VMs 10.10.10.0/24, week of 2026-09-14' or "
            "'my own VirtualBox VM on my laptop'. This is recorded in the report and is the "
            "difference between a penetration test and a crime."))
    if not acknowledged:
        raise HTTPException(400, "You must acknowledge the authorization statement.")
    pid = db.new_id()
    with db.connect() as conn:
        conn.execute("INSERT INTO projects (id, name, authorization_note, created_at)"
                     " VALUES (?,?,?,?)", (pid, name, note, db.now()))
    db.audit("project_created", project_id=pid, user_id=_user_id(request), command=name)
    return {"id": pid, "name": name, "authorization_note": note}


@app.get("/api/projects/{pid}")
def get_project(pid: str) -> dict:
    with db.connect() as conn:
        p = db.row_to_dict(conn.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone())
        if not p:
            raise HTTPException(404, "Project not found.")
        p["targets"] = db.rows_to_list(conn.execute(
            "SELECT * FROM targets WHERE project_id=? ORDER BY created_at", (pid,)))
        p["scans"] = db.rows_to_list(conn.execute(
            "SELECT id, tool, goal, target, status, is_demo, preview, created_at, finished_at,"
            " exit_code FROM scans WHERE project_id=? ORDER BY created_at DESC", (pid,)))
    return p


@app.delete("/api/projects/{pid}")
def delete_project(request: Request, pid: str) -> dict:
    with db.connect() as conn:
        conn.execute("DELETE FROM projects WHERE id=?", (pid,))
    db.audit("project_deleted", project_id=pid, user_id=_user_id(request))
    return {"ok": True}


# --- targets ----------------------------------------------------------------
@app.post("/api/projects/{pid}/targets")
def add_targets(request: Request, pid: str, text: str = Body(""),
                in_scope: bool = Body(True)) -> dict:
    return _ingest_targets(request, pid, text, in_scope)


@app.post("/api/projects/{pid}/targets/upload")
async def upload_targets(request: Request, pid: str, file: UploadFile = File(...),
                         in_scope: bool = Form(True)) -> dict:
    raw = (await file.read())[:2_000_000]
    return _ingest_targets(request, pid, raw.decode("utf-8", "replace"), in_scope)


def _ingest_targets(request: Request, pid: str, text: str, in_scope: bool) -> dict:
    with db.connect() as conn:
        if not conn.execute("SELECT 1 FROM projects WHERE id=?", (pid,)).fetchone():
            raise HTTPException(404, "Project not found.")
        existing = {r["value"] for r in conn.execute(
            "SELECT value FROM targets WHERE project_id=?", (pid,))}

    added: list[dict] = []
    errors: list[dict] = []
    skipped: list[str] = []

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        # Tolerate recon output that carries extra columns or comments.
        line = re.split(r"[,\t]|\s{2,}|\s+#", line)[0].strip().strip('"\'')
        if not line:
            continue
        try:
            value, ttype = validate.validate_target(line)
        except validate.ValidationError as exc:
            errors.append({"line": raw_line.strip()[:120], "error": str(exc)})
            continue
        if value in existing:
            skipped.append(value)
            continue
        existing.add(value)
        tid = db.new_id()
        with db.connect() as conn:
            conn.execute("INSERT INTO targets (id, project_id, value, type, in_scope, created_at)"
                         " VALUES (?,?,?,?,?,?)",
                         (tid, pid, value, ttype, 1 if in_scope else 0, db.now()))
        added.append({"id": tid, "value": value, "type": ttype, "in_scope": in_scope,
                      "hosts": validate.host_count(validate.scan_host_part(value))})

    if added:
        db.audit("targets_added", project_id=pid, user_id=_user_id(request),
                 command=", ".join(t["value"] for t in added[:20]))
    return {"added": added, "errors": errors, "skipped": skipped}


@app.patch("/api/targets/{tid}")
def update_target(tid: str, in_scope: bool = Body(..., embed=True)) -> dict:
    # embed=True: with a single Body parameter FastAPI otherwise expects the bare
    # value as the whole request body, not {"in_scope": ...} as the UI sends.
    with db.connect() as conn:
        conn.execute("UPDATE targets SET in_scope=? WHERE id=?", (1 if in_scope else 0, tid))
    return {"ok": True}


@app.delete("/api/targets/{tid}")
def delete_target(tid: str) -> dict:
    with db.connect() as conn:
        conn.execute("DELETE FROM targets WHERE id=?", (tid,))
    return {"ok": True}


# --- catalog ----------------------------------------------------------------
@app.get("/api/tools")
def get_tools() -> dict:
    return {"tools": tools.catalog(), "guided": tools.GUIDED,
            "installed": runner.tool_availability(),
            "sources": runner.tool_sources(),
            "bundled_dir": str(config.bundled_tools_dir()),
            "platform": config.platform_key()}


@app.get("/api/glossary")
def get_glossary(q: str = Query("")) -> list[dict]:
    return glossary.search(q)


# --- planning + scanning ----------------------------------------------------
def _build_plan(project_id: str, tool_id: str, goal_id: str, target: str,
                opts: dict) -> tuple[ScanPlan, list[str]]:
    with db.connect() as conn:
        if not conn.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone():
            raise HTTPException(404, "Project not found.")
        scope = [r["value"] for r in conn.execute(
            "SELECT value FROM targets WHERE project_id=? AND in_scope=1", (project_id,))]
        excluded = [r["value"] for r in conn.execute(
            "SELECT value FROM targets WHERE project_id=? AND in_scope=0", (project_id,))]
    if not scope:
        raise HTTPException(400, (
            "This project has no in-scope targets yet. Add the systems you are authorized "
            "to test on the Targets screen first - ReconScan will not scan anything that has "
            "not been declared in scope."))
    try:
        validate.check_in_scope(scope, target.strip(), excluded)
        plan = tools.plan(tool_id, goal_id, target.strip(), opts)
    except validate.ValidationError as exc:
        raise HTTPException(400, str(exc)) from exc
    return plan, scope


@app.post("/api/plan")
def make_plan(project_id: str = Body(...), tool: str = Body(...), goal: str = Body(...),
              target: str = Body(...), options: dict = Body(default_factory=dict)) -> dict:
    plan, _ = _build_plan(project_id, tool, goal, target, options or {})
    installed = runner.tool_availability().get(tool, False)
    out = plan.as_json()
    out["tool_installed"] = installed
    if not installed:
        out["notes"] = out["notes"] + [
            f"'{plan.binary}' is not installed on this machine. You can still run this plan "
            f"in Demo mode; for a real scan, install it on the Kali host "
            f"(sudo apt install {plan.binary})."]
    return out


@app.post("/api/scans")
async def start_scan(request: Request, project_id: str = Body(...), tool: str = Body(...),
                     goal: str = Body(...), target: str = Body(...),
                     options: dict = Body(default_factory=dict),
                     demo: bool | None = Body(None)) -> dict:
    plan, _ = _build_plan(project_id, tool, goal, target, options or {})
    is_demo = config.DEMO_DEFAULT if demo is None else bool(demo)
    if not is_demo and not runner.tool_availability().get(tool, False):
        raise HTTPException(400, (
            f"'{plan.binary}' is not installed on this machine, so this scan cannot run for "
            f"real. Install it on the Kali host (sudo apt install {plan.binary}), or run this "
            f"scan in Demo mode to see how it works."))

    sid = db.new_id()
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO scans (id, project_id, tool, goal, target, command_args, preview,"
            " status, is_demo, created_at, options) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (sid, project_id, tool, goal, plan.target, json.dumps(plan.argv), plan.preview,
             "queued", 1 if is_demo else 0, db.now(), json.dumps(options or {})))
    db.audit("scan_started" + (" (demo)" if is_demo else ""), project_id=project_id,
             user_id=_user_id(request), command=plan.preview)
    runner.MANAGER.start(sid, plan, is_demo)
    return {"id": sid, "plan": plan.as_json(), "is_demo": is_demo}


@app.get("/api/scans/{sid}")
def get_scan(sid: str) -> dict:
    with db.connect() as conn:
        scan = db.row_to_dict(conn.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone())
        if not scan:
            raise HTTPException(404, "Scan not found.")
        rows = db.rows_to_list(conn.execute(
            "SELECT * FROM findings WHERE scan_id=?", (sid,)))
    findings = []
    for r in rows:
        data = json.loads(r["data"]) if isinstance(r["data"], str) else r["data"]
        findings.append({
            "id": r["id"], "target": r["target"], "type": r["type"], "data": data,
            "severity": data.get("severity", "info"), "title": data.get("title", ""),
            "interpretation": r["interpretation"],
            "suggested_next_step": r["suggested_next_step"],
        })
    def _port_key(f: dict) -> int:
        # Port findings carry an int; NSE script findings carry "21/tcp" or None.
        raw = f["data"].get("port")
        if isinstance(raw, int):
            return raw
        if isinstance(raw, str) and raw.split("/")[0].isdigit():
            return int(raw.split("/")[0])
        return 0

    findings.sort(key=lambda f: (interpret.SEVERITY_ORDER.get(f["severity"], 5), _port_key(f)))
    run = runner.MANAGER.get(sid)
    if run and run.status in ("running", "queued"):
        scan["status"] = run.status
    scan["findings"] = findings
    scan["summary"] = interpret.summarise(findings)
    return scan


@app.post("/api/scans/{sid}/cancel")
async def cancel_scan(sid: str) -> dict:
    ok = await runner.MANAGER.cancel(sid)
    if not ok:
        raise HTTPException(400, "That scan is not running.")
    return {"ok": True}


@app.delete("/api/scans/{sid}")
def delete_scan(sid: str) -> dict:
    with db.connect() as conn:
        conn.execute("DELETE FROM scans WHERE id=?", (sid,))
    return {"ok": True}


@app.websocket("/ws/scans/{sid}")
async def scan_socket(ws: WebSocket, sid: str) -> None:
    if config.requires_auth():
        user = auth.session_user(ws.cookies.get(auth.COOKIE_NAME))
        if user is None:
            await ws.close(code=4401)
            return
    await ws.accept()
    run, q = await runner.MANAGER.subscribe(sid)
    if run is None:
        # Server restarted, or this scan finished before the socket opened.
        with db.connect() as conn:
            row = conn.execute("SELECT status, stdout FROM scans WHERE id=?", (sid,)).fetchone()
        if row:
            for line in (row["stdout"] or "").splitlines():
                await ws.send_json({"type": "line", "stream": "stdout", "text": line})
            await ws.send_json({"type": "finished", "status": row["status"]})
        await ws.close()
        return
    try:
        while True:
            event = await q.get()
            await ws.send_json(event)
            if event.get("type") == "finished":
                break
    except WebSocketDisconnect:
        pass
    except RuntimeError:
        pass
    finally:
        runner.MANAGER.unsubscribe(sid, q)


# --- scan comparison (Phase 2) ---------------------------------------------
@app.get("/api/projects/{pid}/comparable")
def comparable(pid: str) -> list[dict]:
    return diff.comparable(pid)


@app.get("/api/diff")
def scan_diff(old: str = Query(...), new: str = Query(...)) -> dict:
    if old == new:
        raise HTTPException(400, "Pick two different scans to compare.")
    try:
        return diff.compare(old, new)
    except KeyError as exc:
        raise HTTPException(404, "One of those scans no longer exists.") from exc


# --- saved templates (Phase 2) ---------------------------------------------
@app.get("/api/templates")
def list_templates() -> list[dict]:
    with db.connect() as conn:
        return db.rows_to_list(conn.execute(
            "SELECT * FROM templates ORDER BY use_count DESC, created_at DESC"))


@app.post("/api/templates")
def create_template(request: Request, name: str = Body(...), tool: str = Body(...),
                    goal: str = Body(...), options: dict = Body(default_factory=dict),
                    note: str = Body("")) -> dict:
    name = (name or "").strip()
    if not name:
        raise HTTPException(400, "Give the template a name you will recognise later.")
    try:
        t = tools.tool(tool)
        t.goal(goal)
    except (validate.ValidationError, KeyError) as exc:
        raise HTTPException(400, f"Unknown tool or goal: {exc}") from exc
    tid = db.new_id()
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO templates (id, name, tool, goal, options, note, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (tid, name, tool, goal, json.dumps(options or {}), (note or "").strip(), db.now()))
    db.audit("template_saved", user_id=_user_id(request), command=name)
    return {"id": tid, "name": name}


@app.post("/api/templates/{tid}/used")
def template_used(tid: str) -> dict:
    with db.connect() as conn:
        conn.execute("UPDATE templates SET use_count = use_count + 1 WHERE id=?", (tid,))
    return {"ok": True}


@app.delete("/api/templates/{tid}")
def delete_template(tid: str) -> dict:
    with db.connect() as conn:
        conn.execute("DELETE FROM templates WHERE id=?", (tid,))
    return {"ok": True}


# --- schedules (Phase 2) ----------------------------------------------------
@app.get("/api/projects/{pid}/schedules")
def get_schedules(pid: str) -> list[dict]:
    return scheduler.list_schedules(pid)


@app.post("/api/projects/{pid}/schedules")
def create_schedule(request: Request, pid: str, name: str = Body(""),
                    tool: str = Body(...), goal: str = Body(...), target: str = Body(...),
                    options: dict = Body(default_factory=dict),
                    every_minutes: int = Body(60), is_demo: bool = Body(True),
                    max_runs: int | None = Body(None),
                    start_now: bool = Body(False)) -> dict:
    if not is_demo and not runner.tool_availability().get(tool, False):
        raise HTTPException(400, (
            f"'{tool}' is not installed here, so a real scheduled scan could never run. "
            f"Install it first, or schedule this in Demo mode."))
    try:
        sched = scheduler.create(pid, name, tool, goal, target, options or {},
                                 every_minutes, is_demo, max_runs, start_now)
    except validate.ValidationError as exc:
        raise HTTPException(400, str(exc)) from exc
    db.audit("schedule_created", project_id=pid, user_id=_user_id(request), command=sched["name"])
    return sched


@app.patch("/api/schedules/{sid}")
def patch_schedule(sid: str, enabled: bool = Body(..., embed=True)) -> dict:
    try:
        return scheduler.set_enabled(sid, enabled)
    except KeyError as exc:
        raise HTTPException(404, "Schedule not found.") from exc


@app.delete("/api/schedules/{sid}")
def remove_schedule(sid: str) -> dict:
    scheduler.delete(sid)
    return {"ok": True}


@app.post("/api/schedules/{sid}/run")
async def run_schedule_now(sid: str) -> dict:
    try:
        sched = scheduler.list_one(sid)
    except KeyError as exc:
        raise HTTPException(404, "Schedule not found.") from exc
    scan_id = await scheduler.fire(sched)
    if scan_id is None:
        raise HTTPException(400, (
            "That schedule did not start. Either its previous run is still going, or it was "
            "disabled because its target is no longer in scope - check its status."))
    return {"scan_id": scan_id}


# --- quizzes (Phase 2) ------------------------------------------------------
@app.get("/api/quiz")
def get_quiz(project_id: str = Query(""), topic: str = Query(""),
             count: int = Query(8)) -> dict:
    return {"questions": quiz.build(project_id or None, max(1, min(count, 20)), topic),
            "progress": quiz.progress()}


@app.post("/api/quiz/answer")
def answer_quiz(question_id: str = Body(...), choice: int = Body(...),
                project_id: str = Body("")) -> dict:
    try:
        return quiz.check(question_id, choice, project_id or None)
    except KeyError as exc:
        raise HTTPException(404, "That question is no longer available.") from exc


@app.post("/api/quiz/reset")
def reset_quiz() -> dict:
    quiz.reset()
    return {"ok": True}


# --- audit + reports --------------------------------------------------------
@app.get("/api/projects/{pid}/audit")
def get_audit(pid: str) -> list[dict]:
    with db.connect() as conn:
        return db.rows_to_list(conn.execute(
            "SELECT * FROM audit WHERE project_id=? ORDER BY timestamp DESC LIMIT 500", (pid,)))


@app.get("/api/projects/{pid}/report")
def get_report(pid: str, format: str = Query("md"), raw: bool = Query(False)):
    if format not in report.RENDERERS:
        raise HTTPException(400, f"Unknown format {format!r}. Use md, html, pdf or json.")
    try:
        model = report.build_model(pid, include_raw=raw)
    except KeyError as exc:
        raise HTTPException(404, "Project not found.") from exc
    media, ext, render = report.RENDERERS[format]
    body = render(model)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", model["project"]["name"]).strip("-") or "report"
    return Response(content=body, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="reconscan-{safe}.{ext}"'})


@app.get("/api/projects/{pid}/report/preview", response_class=HTMLResponse)
def preview_report(pid: str, raw: bool = Query(False)):
    try:
        model = report.build_model(pid, include_raw=raw)
    except KeyError as exc:
        raise HTTPException(404, "Project not found.") from exc
    return HTMLResponse(report.to_html(model))


# --- static UI --------------------------------------------------------------
config.WEB_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(config.WEB_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
def index():
    idx = config.WEB_DIR / "index.html"
    if not idx.exists():
        return PlainTextResponse("ReconScan UI files are missing from reconscan/web/.", 500)
    return FileResponse(str(idx))


@app.get("/favicon.ico")
def favicon():
    ico = config.WEB_DIR / "favicon.ico"
    if ico.exists():
        return FileResponse(str(ico), media_type="image/x-icon")
    return Response(status_code=204)
