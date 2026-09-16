"""Scan comparison (Phase 2) - what changed between two runs.

Comparing two scans of the same target over time is how you notice that a new
service appeared, that a patch landed, or that someone opened a firewall port
they should not have. It is also the honest way to check whether something you
reported has actually been fixed.

Every finding gets an identity that survives between runs (a port is identified
by target/port/protocol, a vulnerability by its template or script name). Anything
whose identity appears in only one of the two scans is an appearance or a
disappearance; anything in both whose detail moved is a change.
"""
from __future__ import annotations

import json

from . import db, interpret

# Fields that count as a real change rather than noise, per finding type.
WATCHED = {
    "port": ("state", "service", "version"),
    "vuln": ("severity",),
    "script": (),
    "web": ("status", "severity"),
    "tech": ("value",),
    "os": ("guess",),
    "service": ("version",),
    "host": ("state",),
}


def identity(f: dict) -> tuple | None:
    """A stable key for a finding across runs, or None if it cannot be tracked."""
    d = f.get("data") or {}
    t = f.get("type")
    target = f.get("target")
    if t == "port":
        return (t, target, d.get("port"), d.get("proto"))
    if t == "service":
        return (t, target, d.get("port"))
    if t == "os":
        return (t, target)
    if t == "host":
        return (t, target)
    if t == "vuln":
        name = d.get("template") or d.get("script") or d.get("name")
        return (t, target, name, d.get("port"))
    if t == "script":
        return (t, target, d.get("script"), d.get("port"))
    if t == "tech":
        return (t, target, d.get("plugin"))
    if t == "web":
        return (t, target, d.get("kind"), d.get("path") or d.get("message", "")[:80])
    return None


def _load(scan_id: str) -> tuple[dict, list[dict]]:
    with db.connect() as conn:
        scan = db.row_to_dict(conn.execute(
            "SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())
        if not scan:
            raise KeyError(scan_id)
        rows = db.rows_to_list(conn.execute(
            "SELECT * FROM findings WHERE scan_id=?", (scan_id,)))
    out = []
    for r in rows:
        data = json.loads(r["data"]) if isinstance(r["data"], str) else r["data"]
        out.append({"target": r["target"], "type": r["type"], "data": data,
                    "severity": data.get("severity", "info"),
                    "title": data.get("title", ""),
                    "interpretation": r["interpretation"],
                    "suggested_next_step": r["suggested_next_step"]})
    return scan, out


def _label(f: dict) -> str:
    return f.get("title") or f"{f['type']} on {f['target']}"


# The general caveats ("a missing finding is not proof of a fix") belong on the
# group heading, which states them once. These per-item lines stay specific to
# the finding, so a list of twenty does not read as the same paragraph twenty times.
def _describe_appeared(f: dict) -> str:
    d = f.get("data") or {}
    t = f["type"]
    if t == "port":
        svc = d.get("service") or "an unidentified service"
        ver = f" running {d['version']}" if d.get("version") else ""
        return (f"{d.get('port')}/{d.get('proto')} now answers as {svc}{ver}. Something was "
                f"started here, or a firewall rule opened.")
    if t == "vuln":
        cves = d.get("cves") or []
        return ("New detection" + (f" for {', '.join(cves)}" if cves else "") +
                ". Either the software changed, or the scanner learned this check since the "
                "baseline - the second is common and does not mean the target got worse.")
    if t == "web":
        return (f"{d.get('path') or 'This item'} was not seen before. New content, or this run "
                f"simply reached further.")
    if t == "tech":
        val = d.get("value") or ""
        return (f"{d.get('plugin')} identified{f' as {val}' if val else ''}, which the baseline "
                f"did not report.")
    if t == "os":
        return f"An OS guess appeared: {d.get('guess', '')[:90]}."
    if t == "host":
        return f"{f['target']} responded in this run but not in the baseline."
    return "Present in the newer scan only."


def _describe_gone(f: dict) -> str:
    d = f.get("data") or {}
    t = f["type"]
    if t == "port":
        svc = d.get("service") or "a service"
        return (f"{d.get('port')}/{d.get('proto')} ({svc}) no longer answers - stopped, "
                f"firewalled, or simply missed this time.")
    if t == "vuln":
        cves = d.get("cves") or []
        return ("This detection did not repeat" + (f" ({', '.join(cves)})" if cves else "") +
                ". Check the service is still reachable before calling it patched.")
    if t == "web":
        return f"{d.get('path') or 'This item'} was not found this time."
    if t == "tech":
        return f"{d.get('plugin')} was not detected in the later run."
    return "Present in the earlier scan only."


def _describe_change(f_old: dict, f_new: dict, changes: list[dict]) -> str:
    t = f_new["type"]
    bits = ", ".join(f"{c['field']} went from '{c['before']}' to '{c['after']}'" for c in changes)
    if t == "port":
        extra = ""
        for c in changes:
            if c["field"] == "version":
                extra = (" A version change is the one to look at closely: it tells you the "
                         "software was updated or replaced, which changes which known "
                         "vulnerabilities apply.")
            elif c["field"] == "state":
                extra = (" A state change means the port's availability changed - check whether "
                         "that was deliberate.")
        return f"On port {f_new['data'].get('port')}: {bits}.{extra}"
    if t == "vuln":
        return (f"The severity of this finding changed: {bits}. Usually the template or script "
                f"was updated, not the target - check the matched output in both runs.")
    return f"{bits}."


def compare(old_id: str, new_id: str) -> dict:
    """Compare two scans. 'old' is the baseline, 'new' is the later run."""
    old_scan, old_f = _load(old_id)
    new_scan, new_f = _load(new_id)

    warnings: list[str] = []
    if old_scan["target"] != new_scan["target"]:
        warnings.append(
            f"These scans hit different targets ({old_scan['target']} vs {new_scan['target']}), "
            f"so most differences will just be the two machines being different machines. "
            f"Comparing runs is only meaningful against the same target.")
    if old_scan["tool"] != new_scan["tool"] or old_scan["goal"] != new_scan["goal"]:
        warnings.append(
            f"These scans used different settings ({old_scan['tool']}/{old_scan['goal']} vs "
            f"{new_scan['tool']}/{new_scan['goal']}). Different tools look for different things, "
            f"so an 'appeared' finding here often just means the second scan looked harder.")
    if old_scan["is_demo"] != new_scan["is_demo"]:
        warnings.append(
            "One of these runs was in Demo mode and the other was real. The comparison is "
            "meaningless - demo output is fixed sample data.")
    if old_scan["status"] != "done" or new_scan["status"] != "done":
        warnings.append(
            "At least one of these scans did not finish cleanly, so missing findings may simply "
            "be findings it never got to.")

    old_map = {}
    for f in old_f:
        k = identity(f)
        if k:
            old_map[k] = f
    new_map = {}
    for f in new_f:
        k = identity(f)
        if k:
            new_map[k] = f

    appeared, disappeared, changed, unchanged = [], [], [], 0

    for k, f in new_map.items():
        if k not in old_map:
            appeared.append({**f, "why": _describe_appeared(f)})
    for k, f in old_map.items():
        if k not in new_map:
            disappeared.append({**f, "why": _describe_gone(f)})
    for k, f_new in new_map.items():
        f_old = old_map.get(k)
        if not f_old:
            continue
        deltas = []
        for field in WATCHED.get(f_new["type"], ()):
            a = f_old["data"].get(field)
            bv = f_new["data"].get(field)
            if (a or "") != (bv or ""):
                deltas.append({"field": field, "before": a or "(none)", "after": bv or "(none)"})
        if deltas:
            changed.append({**f_new, "changes": deltas, "before": f_old["data"],
                            "why": _describe_change(f_old, f_new, deltas)})
        else:
            unchanged += 1

    order = lambda f: interpret.SEVERITY_ORDER.get(f.get("severity", "info"), 5)
    appeared.sort(key=order)
    disappeared.sort(key=order)
    changed.sort(key=order)

    return {
        "old": _scan_stub(old_scan, len(old_f)),
        "new": _scan_stub(new_scan, len(new_f)),
        "appeared": appeared,
        "disappeared": disappeared,
        "changed": changed,
        "unchanged": unchanged,
        "warnings": warnings,
        "summary": _summary(old_scan, new_scan, appeared, disappeared, changed, unchanged),
    }


def _scan_stub(s: dict, n: int) -> dict:
    return {"id": s["id"], "tool": s["tool"], "goal": s["goal"], "target": s["target"],
            "status": s["status"], "is_demo": s["is_demo"], "preview": s["preview"],
            "created_at": s["created_at"], "finished_at": s["finished_at"], "findings": n}


def _summary(old: dict, new: dict, appeared: list, disappeared: list,
             changed: list, unchanged: int) -> str:
    if not appeared and not disappeared and not changed:
        return ("Nothing changed. Every finding in the later scan matches the earlier one. For a "
                "system that is supposed to be stable, that is the result you want - and it is "
                "also evidence you can put in a report.")
    parts = []
    if appeared:
        ports = [f for f in appeared if f["type"] == "port"]
        vulns = [f for f in appeared if f["type"] == "vuln"]
        bit = f"{len(appeared)} finding(s) appeared"
        if ports:
            bit += f" including {len(ports)} newly open port(s)"
        if vulns:
            bit += f"{' and' if ports else ' including'} {len(vulns)} new potential vulnerability finding(s)"
        parts.append(bit)
    if disappeared:
        parts.append(f"{len(disappeared)} finding(s) are gone")
    if changed:
        parts.append(f"{len(changed)} changed detail(s)")
    text = "; ".join(parts) + f". {unchanged} finding(s) were identical."
    worst = ([f for f in appeared if f.get("severity") in ("critical", "high")]
             or [f for f in changed if f.get("severity") in ("critical", "high")])
    if worst:
        text += (f" The one to look at first is '{worst[0].get('title')}' "
                 f"({worst[0].get('severity')}).")
    text += (" Remember that scanning is not perfectly repeatable: dropped packets, rate limits "
             "and a busy host can all make a finding come and go without anything on the target "
             "actually changing. Treat a difference as a question, not a conclusion.")
    return text


def comparable(project_id: str) -> list[dict]:
    """Finished scans in a project, grouped by target so the UI can suggest pairs."""
    with db.connect() as conn:
        rows = db.rows_to_list(conn.execute(
            "SELECT id, tool, goal, target, status, is_demo, preview, created_at "
            "FROM scans WHERE project_id=? AND status IN ('done','canceled','failed') "
            "ORDER BY created_at DESC", (project_id,)))
    return rows
