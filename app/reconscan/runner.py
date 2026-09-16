"""Execution engine (PRD F5).

Two things matter here:

1. We call asyncio.create_subprocess_exec(*argv) - the argument-array form.
   There is no shell involved at any point, so shell metacharacters in a target
   are inert even if validation were somehow bypassed. We never use shell=True,
   os.system, or string concatenation to build a command.

2. The argv executed is the exact list the ScanPlan produced and the UI showed
   you. Nothing is appended or rewritten between preview and execution.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from . import config, db, fixtures, interpret, tools
from .tools.base import ScanPlan

MAX_LINES = 20000          # keep memory bounded on a huge scan
MAX_OUTPUT_CHARS = 4_000_000


def resolve(binary: str) -> str | None:
    """Where this tool actually lives: bundled copy first, then PATH.

    A binary carried next to the app wins, so a USB stick runs the version you
    put on it rather than whatever the host machine happens to have installed.
    Returns an absolute path, or None if the tool cannot be found at all.
    """
    folder = config.bundled_tools_dir()
    for name in (binary, f"{binary}.exe"):
        candidate = folder / name
        if candidate.is_file():
            return str(candidate)
    return shutil.which(binary)


def is_bundled(binary: str) -> bool:
    found = resolve(binary)
    return bool(found) and Path(found).parent == config.bundled_tools_dir()


class Run:
    def __init__(self, scan_id: str, plan: ScanPlan, is_demo: bool):
        self.scan_id = scan_id
        self.plan = plan
        self.is_demo = is_demo
        self.lines: list[str] = []        # everything, for display and evidence
        self.out_lines: list[str] = []    # the tool's stdout only, for the parsers
        self.subscribers: set[asyncio.Queue] = set()
        self.proc: asyncio.subprocess.Process | None = None
        self.status = "queued"
        self.task: asyncio.Task | None = None
        self.truncated = False

    def emit(self, event: dict) -> None:
        for q in list(self.subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    def add_line(self, text: str, stream: str = "stdout") -> None:
        if len(self.lines) >= MAX_LINES:
            if not self.truncated:
                self.truncated = True
                self.lines.append("[ReconScan] Output truncated - this run produced more "
                                  "than %d lines. The scan is still running." % MAX_LINES)
                self.emit({"type": "line", "stream": "meta", "text": self.lines[-1]})
            return
        self.lines.append(text)
        if stream == "stdout":
            # Parsers must never see ReconScan's own commentary, only the tool's.
            self.out_lines.append(text)
        self.emit({"type": "line", "stream": stream, "text": text})


class Manager:
    def __init__(self) -> None:
        self.runs: dict[str, Run] = {}

    # --- public API ---------------------------------------------------------
    def start(self, scan_id: str, plan: ScanPlan, is_demo: bool) -> Run:
        run = Run(scan_id, plan, is_demo)
        self.runs[scan_id] = run
        run.task = asyncio.create_task(self._execute(run))
        return run

    def get(self, scan_id: str) -> Run | None:
        return self.runs.get(scan_id)

    async def subscribe(self, scan_id: str) -> tuple[Run | None, asyncio.Queue]:
        q: asyncio.Queue = asyncio.Queue(maxsize=2000)
        run = self.runs.get(scan_id)
        if run:
            for line in run.lines:
                try:
                    q.put_nowait({"type": "line", "stream": "stdout", "text": line})
                except asyncio.QueueFull:
                    break
            run.subscribers.add(q)
            if run.status in ("done", "failed", "canceled"):
                q.put_nowait({"type": "finished", "status": run.status})
        return run, q

    def unsubscribe(self, scan_id: str, q: asyncio.Queue) -> None:
        run = self.runs.get(scan_id)
        if run:
            run.subscribers.discard(q)

    async def cancel(self, scan_id: str) -> bool:
        run = self.runs.get(scan_id)
        if not run or run.status not in ("running", "queued"):
            return False
        run.status = "canceling"
        if run.proc and run.proc.returncode is None:
            try:
                run.proc.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(run.proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                try:
                    run.proc.kill()
                except ProcessLookupError:
                    pass
        elif run.task:
            run.task.cancel()
        return True

    # --- internals ----------------------------------------------------------
    async def _execute(self, run: Run) -> None:
        run.status = "running"
        started = db.now()
        with db.connect() as conn:
            conn.execute("UPDATE scans SET status='running', started_at=? WHERE id=?",
                         (started, run.scan_id))
        run.emit({"type": "status", "status": "running"})

        exit_code = 0
        stderr_text = ""
        try:
            if run.is_demo:
                exit_code = await self._run_demo(run)
            else:
                exit_code, stderr_text = await self._run_real(run)
            status = "canceled" if run.status == "canceling" else (
                "done" if exit_code == 0 else "failed")
        except asyncio.CancelledError:
            status = "canceled"
            run.add_line("[ReconScan] Scan canceled by user.", "meta")
        except FileNotFoundError:
            status = "failed"
            exit_code = 127
            binary = run.plan.binary
            msg = (f"[ReconScan] '{binary}' is not installed on this machine, or is not on "
                   f"PATH. On Kali: sudo apt install {binary}. "
                   f"To try this scan anyway without touching the network, turn on Demo mode.")
            run.add_line(msg, "meta")
            stderr_text = msg
        except PermissionError as exc:
            status = "failed"
            exit_code = 126
            msg = (f"[ReconScan] Permission denied running {run.plan.binary}: {exc}. "
                   f"This scan needs root - start ReconScan with sudo, or pick an option "
                   f"that does not need raw packets (for example a TCP connect scan).")
            run.add_line(msg, "meta")
            stderr_text = msg
        except Exception as exc:  # noqa: BLE001 - surface anything to the user
            status = "failed"
            exit_code = 1
            msg = f"[ReconScan] Unexpected error while running the scan: {exc}"
            run.add_line(msg, "meta")
            stderr_text = msg

        await self._finish(run, status, exit_code, stderr_text)

    async def _run_demo(self, run: Run) -> int:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
        stdout, _stderr, code = fixtures.get(
            run.plan.tool_id, run.plan.goal_id, run.plan.target, {}, date)
        run.add_line("[DEMO MODE] Nothing is being sent to any network. "
                     "The output below is realistic saved output.", "meta")
        lines = stdout.splitlines()
        delay = min(0.08, 4.0 / max(1, len(lines)))
        for line in lines:
            if run.status == "canceling":
                raise asyncio.CancelledError
            run.add_line(line)
            await asyncio.sleep(delay)
        return code

    async def _run_real(self, run: Run) -> tuple[int, str]:
        argv = list(run.plan.argv)
        exe = resolve(argv[0])
        if exe is None:
            raise FileNotFoundError(argv[0])

        run.add_line(f"[ReconScan] Executing: {run.plan.preview}", "meta")
        # The preview shows the bare command, the way you would type it. When the
        # binary comes from a bundled folder rather than PATH we say so, so the
        # line above is never quietly running something other than it appears to.
        if Path(exe).parent == config.bundled_tools_dir():
            run.add_line(f"[ReconScan] '{argv[0]}' resolved to the copy bundled with "
                         f"ReconScan: {exe}", "meta")
        argv[0] = exe

        # Argument-array form: no shell, no string interpolation. See module docstring.
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        run.proc = proc
        errs: list[str] = []

        async def pump(stream, name: str) -> None:
            while True:
                raw = await stream.readline()
                if not raw:
                    break
                text = raw.decode("utf-8", "replace").rstrip("\r\n")
                if name == "stderr":
                    errs.append(text)
                run.add_line(text, name)

        await asyncio.gather(
            pump(proc.stdout, "stdout"),
            pump(proc.stderr, "stderr"),
        )
        code = await proc.wait()
        return code, "\n".join(errs)

    async def _finish(self, run: Run, status: str, exit_code: int, stderr_text: str) -> None:
        run.status = status

        # Translate a recognised tool failure before saving, so the explanation is
        # part of the stored evidence and not only a passing message in the UI.
        if status == "failed":
            hint = tools.hint_for(run.plan.tool_id,
                                  "\n".join(run.lines[-40:]) + "\n" + stderr_text)
            if hint:
                run.add_line(f"[ReconScan] {hint}", "meta")

        stdout_text = "\n".join(run.lines)[:MAX_OUTPUT_CHARS]        # evidence, kept whole
        parse_text = "\n".join(run.out_lines)[:MAX_OUTPUT_CHARS]     # tool output only

        parsed = tools.parse(run.plan.tool_id, run.plan.goal_id,
                             parse_text, stderr_text, run.plan.target)
        enriched = [interpret.interpret(f) for f in parsed]

        with db.connect() as conn:
            conn.execute(
                "UPDATE scans SET status=?, exit_code=?, stdout=?, stderr=?, finished_at=? "
                "WHERE id=?",
                (status, exit_code, stdout_text, stderr_text[:100000], db.now(), run.scan_id))
            conn.execute("DELETE FROM findings WHERE scan_id=?", (run.scan_id,))
            for f in enriched:
                conn.execute(
                    "INSERT INTO findings (id, scan_id, target, type, data, interpretation,"
                    " suggested_next_step) VALUES (?,?,?,?,?,?,?)",
                    (db.new_id(), run.scan_id, f["target"], f["type"],
                     json.dumps({**f["data"], "severity": f.get("severity"),
                                 "title": f.get("title")}),
                     f.get("interpretation"), f.get("suggested_next_step")))

        db.audit(f"scan_{status}", command=run.plan.preview)

        summary = interpret.summarise(enriched)
        run.emit({"type": "finished", "status": status, "exit_code": exit_code,
                  "findings": len(enriched), "summary": summary})
        if status == "failed" and exit_code not in (0, 127, 126):
            run.emit({"type": "line", "stream": "meta",
                      "text": f"[ReconScan] The tool exited with code {exit_code}. "
                              f"Any results it did produce before stopping are kept below "
                              f"and marked as partial."})


MANAGER = Manager()


def tool_availability() -> dict[str, bool]:
    """Which of the catalog's tools can actually be run here."""
    return {tid: resolve(tools.MODULES[tid].TOOL.binary) is not None
            for tid in tools.ORDER}


def tool_sources() -> dict[str, dict]:
    """Where each tool would come from - for the Learn screen and diagnostics."""
    out: dict[str, dict] = {}
    folder = config.bundled_tools_dir()
    for tid in tools.ORDER:
        binary = tools.MODULES[tid].TOOL.binary
        found = resolve(binary)
        out[tid] = {
            "found": found or "",
            "bundled": bool(found) and Path(found).parent == folder,
            "available": found is not None,
        }
    return out
