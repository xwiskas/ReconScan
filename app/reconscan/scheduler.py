"""Scan scheduling (Phase 2).

A schedule fires a scan on an interval without anyone watching. That is useful -
re-scan the lab every hour and diff the results - and it is also the one feature
here that can put packets on a network while you are asleep, so it is built
defensively:

* Scope is re-checked at fire time, not just when the schedule was created. If a
  target is removed from scope, the schedule disables itself rather than running.
* Every fire is written to the audit log, marked as scheduled.
* A schedule never stacks: if the previous run is still going, this tick is skipped.
* Schedules can be capped with a maximum number of runs, and default to Demo mode.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

from . import db, runner, tools, validate

TICK_SECONDS = 20
MIN_INTERVAL_MINUTES = 5
MAX_CONSECUTIVE_ERRORS = 3

_task: asyncio.Task | None = None


def now_dt() -> datetime:
    return datetime.now(timezone.utc)


def next_time(minutes: int, *, from_dt: datetime | None = None) -> str:
    return ((from_dt or now_dt()) + timedelta(minutes=minutes)).isoformat()


def _parse(iso: str) -> datetime:
    try:
        d = datetime.fromisoformat(iso)
    except (ValueError, TypeError):
        return now_dt()
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def list_schedules(project_id: str | None = None) -> list[dict]:
    sql = "SELECT * FROM schedules"
    args: tuple = ()
    if project_id:
        sql += " WHERE project_id=?"
        args = (project_id,)
    sql += " ORDER BY next_run_at"
    with db.connect() as conn:
        rows = db.rows_to_list(conn.execute(sql, args))
    for r in rows:
        r["due_in_seconds"] = max(0, int((_parse(r["next_run_at"]) - now_dt()).total_seconds()))
    return rows


def create(project_id: str, name: str, tool: str, goal: str, target: str,
           options: dict, every_minutes: int, is_demo: bool,
           max_runs: int | None, start_now: bool) -> dict:
    every = validate.validate_int(every_minutes, MIN_INTERVAL_MINUTES, 60 * 24 * 30,
                                  "Interval in minutes")
    if max_runs is not None:
        max_runs = validate.validate_int(max_runs, 1, 1000, "Maximum runs")

    # Build the plan once now so a broken schedule fails here, in front of you,
    # rather than silently at 3am.
    scope, excluded = _scope(project_id)
    validate.check_in_scope(scope, target.strip(), excluded)
    plan = tools.plan(tool, goal, target.strip(), options or {})

    sid = db.new_id()
    first = now_dt().isoformat() if start_now else next_time(every)
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO schedules (id, project_id, name, tool, goal, target, options,"
            " is_demo, every_minutes, max_runs, run_count, enabled, next_run_at, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,0,1,?,?)",
            (sid, project_id, name.strip() or f"{goal} on {target}", tool, goal, plan.target,
             json.dumps(options or {}), 1 if is_demo else 0, every, max_runs, first, db.now()))
    db.audit("schedule_created", project_id=project_id, command=plan.preview)
    return list_one(sid)


def list_one(sid: str) -> dict:
    with db.connect() as conn:
        row = db.row_to_dict(conn.execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone())
    if not row:
        raise KeyError(sid)
    row["due_in_seconds"] = max(0, int((_parse(row["next_run_at"]) - now_dt()).total_seconds()))
    return row


def set_enabled(sid: str, enabled: bool) -> dict:
    with db.connect() as conn:
        conn.execute("UPDATE schedules SET enabled=?, last_error=NULL WHERE id=?",
                     (1 if enabled else 0, sid))
        if enabled:
            row = conn.execute("SELECT every_minutes FROM schedules WHERE id=?", (sid,)).fetchone()
            if row:
                conn.execute("UPDATE schedules SET next_run_at=? WHERE id=?",
                             (next_time(row["every_minutes"]), sid))
    db.audit("schedule_" + ("enabled" if enabled else "paused"))
    return list_one(sid)


def delete(sid: str) -> None:
    with db.connect() as conn:
        conn.execute("DELETE FROM schedules WHERE id=?", (sid,))
    db.audit("schedule_deleted")


def _scope(project_id: str) -> tuple[list[str], list[str]]:
    """(in-scope values, explicitly excluded values) for this project."""
    with db.connect() as conn:
        rows = db.rows_to_list(conn.execute(
            "SELECT value, in_scope FROM targets WHERE project_id=?", (project_id,)))
    return ([r["value"] for r in rows if r["in_scope"]],
            [r["value"] for r in rows if not r["in_scope"]])


def _disable(sid: str, reason: str) -> None:
    with db.connect() as conn:
        conn.execute("UPDATE schedules SET enabled=0, last_error=? WHERE id=?", (reason, sid))
    db.audit("schedule_disabled", command=reason)


def _due() -> list[dict]:
    with db.connect() as conn:
        return db.rows_to_list(conn.execute(
            "SELECT * FROM schedules WHERE enabled=1 AND next_run_at <= ?",
            (now_dt().isoformat(),)))


async def fire(sched: dict) -> str | None:
    """Run one scheduled scan. Returns the new scan id, or None if it was skipped."""
    sid = sched["id"]

    # Do not stack runs: if the previous one is still going, wait for the next tick.
    prev = sched.get("last_scan_id")
    if prev:
        run = runner.MANAGER.get(prev)
        if run and run.status in ("queued", "running"):
            return None

    # Scope is re-checked every time, because the scope can change after the
    # schedule was made. A schedule must never outlive its authorization.
    scope, excluded = _scope(sched["project_id"])
    if not scope:
        _disable(sid, "The project has no in-scope targets any more, so this schedule stopped.")
        return None
    try:
        validate.check_in_scope(scope, sched["target"], excluded)
        opts = sched["options"] if isinstance(sched["options"], dict) else json.loads(sched["options"])
        plan = tools.plan(sched["tool"], sched["goal"], sched["target"], opts)
    except validate.ValidationError as exc:
        _disable(sid, f"Stopped before running: {exc}")
        return None

    is_demo = bool(sched["is_demo"])
    if not is_demo and not runner.tool_availability().get(sched["tool"], False):
        _disable(sid, f"'{plan.binary}' is not installed on this machine, so this schedule "
                      f"cannot run for real.")
        return None

    scan_id = db.new_id()
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO scans (id, project_id, tool, goal, target, command_args, preview,"
            " status, is_demo, created_at, options, schedule_id)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (scan_id, sched["project_id"], sched["tool"], sched["goal"], plan.target,
             json.dumps(plan.argv), plan.preview, "queued", 1 if is_demo else 0,
             db.now(), json.dumps(opts), sid))
        run_count = sched["run_count"] + 1
        finished = sched["max_runs"] is not None and run_count >= sched["max_runs"]
        conn.execute(
            "UPDATE schedules SET last_run_at=?, last_scan_id=?, run_count=?, next_run_at=?,"
            " enabled=?, last_error=NULL WHERE id=?",
            (db.now(), scan_id, run_count, next_time(sched["every_minutes"]),
             0 if finished else 1, sid))
    db.audit("scan_started (scheduled)" + (" (demo)" if is_demo else ""),
             project_id=sched["project_id"], command=plan.preview)
    runner.MANAGER.start(scan_id, plan, is_demo)
    return scan_id


async def _loop() -> None:
    while True:
        try:
            for sched in _due():
                try:
                    await fire(sched)
                except Exception as exc:  # noqa: BLE001 - one bad schedule must not stop the rest
                    _disable(sched["id"], f"Unexpected error while starting: {exc}")
        except Exception:  # noqa: BLE001 - never let the loop die
            pass
        await asyncio.sleep(TICK_SECONDS)


def start() -> None:
    global _task
    if _task is None or _task.done():
        _task = asyncio.create_task(_loop())


def stop() -> None:
    global _task
    if _task and not _task.done():
        _task.cancel()
    _task = None
