"""Report export (PRD F11) - one canonical model, four renderings.

build_model() assembles everything once. Markdown, HTML, PDF and JSON are all
rendered from that same model, so the formats cannot disagree with each other.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from . import config, db, interpret
from .pdf import Writer

SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium",
             "low": "Low", "info": "Informational"}
SEV_COLOR = {"critical": "#8b1a1a", "high": "#b4341c", "medium": "#9a6407",
             "low": "#2c6b4f", "info": "#4a5568"}


def build_model(project_id: str, include_raw: bool = False) -> dict:
    with db.connect() as conn:
        project = db.row_to_dict(
            conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone())
        if not project:
            raise KeyError(project_id)
        targets = db.rows_to_list(conn.execute(
            "SELECT * FROM targets WHERE project_id=? ORDER BY created_at", (project_id,)))
        scans = db.rows_to_list(conn.execute(
            "SELECT * FROM scans WHERE project_id=? ORDER BY created_at", (project_id,)))
        audit = db.rows_to_list(conn.execute(
            "SELECT * FROM audit WHERE project_id=? ORDER BY timestamp", (project_id,)))
        findings_by_scan: dict[str, list[dict]] = {}
        for s in scans:
            rows = db.rows_to_list(conn.execute(
                "SELECT * FROM findings WHERE scan_id=?", (s["id"],)))
            for r in rows:
                r["data"] = json.loads(r["data"]) if isinstance(r["data"], str) else r["data"]
                r["severity"] = r["data"].get("severity", "info")
                r["title"] = r["data"].get("title", "")
            findings_by_scan[s["id"]] = rows

    all_findings = [f for rows in findings_by_scan.values() for f in rows]
    all_findings.sort(key=lambda f: interpret.SEVERITY_ORDER.get(f.get("severity", "info"), 5))

    # Per-host roll-up: the shape a reader actually wants.
    hosts: dict[str, dict] = {}
    for f in all_findings:
        h = hosts.setdefault(f["target"], {"target": f["target"], "ports": [], "os": [],
                                           "vulns": [], "web": [], "tech": []})
        if f["type"] == "port":
            h["ports"].append(f)
        elif f["type"] == "os":
            h["os"].append(f)
        elif f["type"] in ("vuln", "script"):
            h["vulns"].append(f)
        elif f["type"] == "web":
            h["web"].append(f)
        elif f["type"] == "tech":
            h["tech"].append(f)
    for h in hosts.values():
        h["ports"].sort(key=lambda f: f["data"].get("port") or 0)
        h["vulns"].sort(key=lambda f: interpret.SEVERITY_ORDER.get(f.get("severity", "info"), 5))

    counts = {k: 0 for k in SEV_LABEL}
    for f in all_findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1

    demo_scans = [s for s in scans if s["is_demo"]]
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "app": f"{config.APP_NAME} {config.APP_VERSION}",
        "project": project,
        "targets": targets,
        "scans": scans,
        "findings_by_scan": findings_by_scan,
        "findings": all_findings,
        "hosts": [hosts[k] for k in sorted(hosts)],
        "counts": counts,
        "include_raw": include_raw,
        "audit": audit,
        "demo_only": bool(scans) and len(demo_scans) == len(scans),
        "has_demo": bool(demo_scans),
        "summary": interpret.summarise([{**f, "data": f["data"]} for f in all_findings]),
    }


# --- Markdown ---------------------------------------------------------------
def to_markdown(m: dict) -> str:
    p = m["project"]
    L: list[str] = []
    a = L.append
    a(f"# Scanning report - {p['name']}")
    a("")
    a(f"*Generated {m['generated_at']} by {m['app']}*")
    a("")
    if m["has_demo"]:
        a("> **Note:** this project contains scans run in Demo mode. Demo scans send no "
          "packets; their output is realistic sample data and must not be presented as "
          "results from a real system.")
        a("")
    a("## 1. Authorization")
    a("")
    a(f"{p['authorization_note']}")
    a("")
    a("All scanning described here was carried out against the targets listed in section 2, "
      "which were declared in scope before any scan was run. ReconScan blocks scans of "
      "targets outside a project's declared scope.")
    a("")
    a("## 2. Scope")
    a("")
    a("| Target | Type | In scope |")
    a("| --- | --- | --- |")
    for t in m["targets"]:
        a(f"| `{t['value']}` | {t['type']} | {'yes' if t['in_scope'] else 'no'} |")
    a("")
    a("## 3. Summary")
    a("")
    a(m["summary"]["text"] or "No findings were recorded.")
    a("")
    c = m["counts"]
    a("| Severity | Count |")
    a("| --- | --- |")
    for k in ("critical", "high", "medium", "low", "info"):
        a(f"| {SEV_LABEL[k]} | {c.get(k,0)} |")
    a("")
    if m["summary"]["next_steps"]:
        a("**Suggested next steps**")
        a("")
        for s in m["summary"]["next_steps"]:
            a(f"- {s}")
        a("")
    a("## 4. Methodology")
    a("")
    a("Each scan below records the exact command that was executed. Commands are built as "
      "argument arrays and run without a shell.")
    a("")
    a("| # | Tool | Goal | Target | Mode | Status | Command |")
    a("| --- | --- | --- | --- | --- | --- | --- |")
    for i, s in enumerate(m["scans"], 1):
        a(f"| {i} | {s['tool']} | {s['goal']} | `{s['target']}` | "
          f"{'DEMO' if s['is_demo'] else 'real'} | {s['status']} | `{s['preview']}` |")
    a("")
    a("## 5. Findings by host")
    a("")
    if not m["hosts"]:
        a("_No parsed findings._")
        a("")
    for h in m["hosts"]:
        a(f"### {h['target']}")
        a("")
        if h["os"]:
            a(f"**Operating system guess:** {h['os'][0]['data'].get('guess','')}")
            a("")
        if h["ports"]:
            a("| Port | State | Service | Version | What it means |")
            a("| --- | --- | --- | --- | --- |")
            for f in h["ports"]:
                d = f["data"]
                a(f"| {d.get('port')}/{d.get('proto','tcp')} | {d.get('state','')} | "
                  f"{d.get('service','')} | {d.get('version','')} | "
                  f"{(f.get('interpretation') or '')[:220]} |")
            a("")
        if h["tech"]:
            a("**Technology identified:** "
              + ", ".join(f"{f['data'].get('plugin')}"
                          + (f" ({f['data'].get('value')})" if f['data'].get('value') else "")
                          for f in h["tech"][:20]))
            a("")
        for f in h["vulns"] + h["web"]:
            sev = f.get("severity", "info")
            a(f"#### [{SEV_LABEL.get(sev, sev)}] {f.get('title') or f['type']}")
            a("")
            if f.get("interpretation"):
                a(f["interpretation"])
                a("")
            if f.get("suggested_next_step"):
                a(f"*Next step:* {f['suggested_next_step']}")
                a("")
            out = (f["data"].get("output") or f["data"].get("raw") or "").strip()
            if out:
                a("```")
                a(out[:1500])
                a("```")
                a("")
    if m["include_raw"]:
        a("## 6. Raw evidence")
        a("")
        for i, s in enumerate(m["scans"], 1):
            a(f"### Scan {i}: `{s['preview']}`")
            a("")
            a("```")
            a((s.get("stdout") or "")[:20000])
            a("```")
            a("")
    a("---")
    a("")
    a("*Scanning was limited to discovery, service identification, limited enumeration and "
      "non-exploitative vulnerability checks. No exploitation, credential attacks or payload "
      "delivery was performed.*")
    return "\n".join(L)


# --- HTML -------------------------------------------------------------------
def to_html(m: dict) -> str:
    p = m["project"]
    e = html.escape
    rows = "".join(
        f"<tr><td><code>{e(t['value'])}</code></td><td>{e(t['type'])}</td>"
        f"<td>{'yes' if t['in_scope'] else 'no'}</td></tr>" for t in m["targets"])
    scan_rows = "".join(
        f"<tr><td>{i}</td><td>{e(s['tool'])}</td><td>{e(s['goal'])}</td>"
        f"<td><code>{e(s['target'])}</code></td>"
        f"<td>{'DEMO' if s['is_demo'] else 'real'}</td><td>{e(s['status'])}</td>"
        f"<td><code class='cmd'>{e(s['preview'])}</code></td></tr>"
        for i, s in enumerate(m["scans"], 1))

    sev_chips = "".join(
        f"<span class='chip' style='--c:{SEV_COLOR[k]}'>{SEV_LABEL[k]}: "
        f"{m['counts'].get(k,0)}</span>" for k in ("critical", "high", "medium", "low", "info"))

    host_html: list[str] = []
    for h in m["hosts"]:
        parts = [f"<h3>{e(h['target'])}</h3>"]
        if h["os"]:
            parts.append(f"<p><strong>OS guess:</strong> {e(h['os'][0]['data'].get('guess',''))}</p>")
        if h["ports"]:
            body = "".join(
                f"<tr><td>{f['data'].get('port')}/{e(f['data'].get('proto','tcp'))}</td>"
                f"<td>{e(f['data'].get('state',''))}</td><td>{e(f['data'].get('service',''))}</td>"
                f"<td>{e(f['data'].get('version',''))}</td>"
                f"<td class='interp'>{e((f.get('interpretation') or '')[:400])}</td></tr>"
                for f in h["ports"])
            parts.append("<table><thead><tr><th>Port</th><th>State</th><th>Service</th>"
                         f"<th>Version</th><th>What it means</th></tr></thead><tbody>{body}</tbody></table>")
        if h["tech"]:
            parts.append("<p><strong>Technology:</strong> " + e(", ".join(
                f"{f['data'].get('plugin')}"
                + (f" ({f['data'].get('value')})" if f['data'].get('value') else "")
                for f in h["tech"][:25])) + "</p>")
        for f in h["vulns"] + h["web"]:
            sev = f.get("severity", "info")
            out = (f["data"].get("output") or f["data"].get("raw") or "").strip()
            parts.append(
                f"<div class='finding'><div class='fhead'>"
                f"<span class='chip' style='--c:{SEV_COLOR.get(sev,'#4a5568')}'>{SEV_LABEL.get(sev,sev)}</span>"
                f"<strong>{e(f.get('title') or f['type'])}</strong></div>"
                f"<p>{e(f.get('interpretation') or '')}</p>"
                + (f"<p class='next'><em>Next step:</em> {e(f.get('suggested_next_step') or '')}</p>"
                   if f.get("suggested_next_step") else "")
                + (f"<pre>{e(out[:1500])}</pre>" if out else "")
                + "</div>")
        host_html.append("<section class='host'>" + "".join(parts) + "</section>")

    raw_html = ""
    if m["include_raw"]:
        raw_html = "<h2>6. Raw evidence</h2>" + "".join(
            f"<h3>Scan {i}: <code>{e(s['preview'])}</code></h3>"
            f"<pre>{e((s.get('stdout') or '')[:20000])}</pre>"
            for i, s in enumerate(m["scans"], 1))

    demo_banner = ("<div class='banner'>This project contains scans run in <strong>Demo "
                   "mode</strong>. Demo scans send no packets; their output is realistic "
                   "sample data and must not be presented as results from a real system.</div>"
                   ) if m["has_demo"] else ""

    steps = "".join(f"<li>{e(s)}</li>" for s in m["summary"]["next_steps"])

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scanning report - {e(p['name'])}</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font: 15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
         color:#1a202c; background:#fff; max-width:860px; margin:0 auto; padding:40px 24px; }}
  h1 {{ font-size:28px; margin:0 0 4px; }}
  h2 {{ font-size:19px; margin:34px 0 10px; padding-bottom:6px; border-bottom:1px solid #e2e8f0; }}
  h3 {{ font-size:15px; margin:22px 0 8px; }}
  .meta {{ color:#718096; font-size:13px; margin-bottom:24px; }}
  table {{ border-collapse:collapse; width:100%; margin:10px 0 18px; font-size:13px; }}
  th,td {{ text-align:left; padding:7px 9px; border-bottom:1px solid #edf2f7; vertical-align:top; }}
  th {{ background:#f7fafc; font-weight:600; }}
  code {{ background:#f7fafc; padding:1px 5px; border-radius:4px; font-size:12px;
          font-family:ui-monospace,Menlo,Consolas,monospace; }}
  code.cmd {{ white-space:nowrap; }}
  pre {{ background:#f7fafc; border:1px solid #e2e8f0; border-radius:6px; padding:12px;
         overflow-x:auto; font-size:12px; line-height:1.45; }}
  .chip {{ display:inline-block; background:var(--c); color:#fff; border-radius:999px;
           padding:2px 10px; font-size:11px; font-weight:600; margin-right:6px; }}
  .finding {{ border:1px solid #e2e8f0; border-radius:8px; padding:14px 16px; margin:12px 0; }}
  .fhead {{ display:flex; align-items:center; gap:8px; margin-bottom:6px; }}
  .next {{ color:#2c5282; font-size:13px; }}
  .interp {{ color:#4a5568; font-size:12px; }}
  .banner {{ background:#fffaf0; border:1px solid #f6e05e; border-radius:8px;
             padding:12px 14px; margin:16px 0; font-size:14px; }}
  .host {{ margin-bottom:26px; }}
  footer {{ margin-top:40px; padding-top:16px; border-top:1px solid #e2e8f0;
            color:#718096; font-size:13px; }}
  @media print {{ body {{ padding:0; max-width:none; }} }}
</style></head><body>
<h1>Scanning report - {e(p['name'])}</h1>
<div class="meta">Generated {e(m['generated_at'])} by {e(m['app'])}</div>
{demo_banner}
<h2>1. Authorization</h2>
<p>{e(p['authorization_note'])}</p>
<p>All scanning described here was carried out against the targets listed in section 2,
which were declared in scope before any scan was run. ReconScan blocks scans of targets
outside a project's declared scope.</p>
<h2>2. Scope</h2>
<table><thead><tr><th>Target</th><th>Type</th><th>In scope</th></tr></thead><tbody>{rows}</tbody></table>
<h2>3. Summary</h2>
<p>{e(m['summary']['text'] or 'No findings were recorded.')}</p>
<p>{sev_chips}</p>
{f'<p><strong>Suggested next steps</strong></p><ul>{steps}</ul>' if steps else ''}
<h2>4. Methodology</h2>
<p>Each scan below records the exact command that was executed. Commands are built as
argument arrays and run without a shell.</p>
<table><thead><tr><th>#</th><th>Tool</th><th>Goal</th><th>Target</th><th>Mode</th>
<th>Status</th><th>Command</th></tr></thead><tbody>{scan_rows}</tbody></table>
<h2>5. Findings by host</h2>
{''.join(host_html) or '<p><em>No parsed findings.</em></p>'}
{raw_html}
<footer>Scanning was limited to discovery, service identification, limited enumeration and
non-exploitative vulnerability checks. No exploitation, credential attacks or payload
delivery was performed.</footer>
</body></html>"""


# --- PDF --------------------------------------------------------------------
def to_pdf(m: dict) -> bytes:
    p = m["project"]
    w = Writer()
    w.h1(f"Scanning report - {p['name']}")
    w.p(f"Generated {m['generated_at']} by {m['app']}")
    w.rule()
    if m["has_demo"]:
        w.p("NOTE: this project contains scans run in Demo mode. Demo scans send no packets; "
            "their output is realistic sample data and must not be presented as results from "
            "a real system.")
    w.h2("1. Authorization")
    w.p(p["authorization_note"])
    w.p("All scanning described here was carried out against the targets listed in section 2, "
        "which were declared in scope before any scan was run. ReconScan blocks scans of "
        "targets outside a project's declared scope.")
    w.h2("2. Scope")
    for t in m["targets"]:
        w.bullet(f"{t['value']}  ({t['type']}, {'in scope' if t['in_scope'] else 'OUT of scope'})")
    w.h2("3. Summary")
    w.p(m["summary"]["text"] or "No findings were recorded.")
    c = m["counts"]
    w.p("Findings by severity - " + ", ".join(
        f"{SEV_LABEL[k]}: {c.get(k, 0)}" for k in ("critical", "high", "medium", "low", "info")))
    if m["summary"]["next_steps"]:
        w.h3("Suggested next steps")
        for s in m["summary"]["next_steps"]:
            w.bullet(s)
    w.h2("4. Methodology")
    w.p("Each scan below records the exact command that was executed. Commands are built as "
        "argument arrays and run without a shell.")
    for i, s in enumerate(m["scans"], 1):
        w.h3(f"Scan {i}: {s['tool']} - {s['goal']} - {s['target']}"
             + ("  [DEMO]" if s["is_demo"] else ""))
        w.kv("Status", f"{s['status']} (exit code {s.get('exit_code')})")
        w.mono(s["preview"])
    w.h2("5. Findings by host")
    if not m["hosts"]:
        w.p("No parsed findings.")
    for h in m["hosts"]:
        w.h3(h["target"])
        if h["os"]:
            w.kv("OS guess", h["os"][0]["data"].get("guess", ""))
        for f in h["ports"]:
            d = f["data"]
            w.kv(f"{d.get('port')}/{d.get('proto','tcp')} {d.get('state','')}",
                 f"{d.get('service','')} {d.get('version','')}".strip())
            if f.get("interpretation"):
                w.p(f["interpretation"])
        if h["tech"]:
            w.kv("Technology", ", ".join(
                f"{f['data'].get('plugin')}"
                + (f" ({f['data'].get('value')})" if f["data"].get("value") else "")
                for f in h["tech"][:20]))
        for f in h["vulns"] + h["web"]:
            sev = SEV_LABEL.get(f.get("severity", "info"), "Info")
            w.h3(f"[{sev}] {f.get('title') or f['type']}")
            if f.get("interpretation"):
                w.p(f["interpretation"])
            if f.get("suggested_next_step"):
                w.p(f"Next step: {f['suggested_next_step']}")
            out = (f["data"].get("output") or f["data"].get("raw") or "").strip()
            if out:
                w.mono(out[:900])
    if m["include_raw"]:
        w.h2("6. Raw evidence")
        for i, s in enumerate(m["scans"], 1):
            w.h3(f"Scan {i}: {s['preview']}")
            w.mono((s.get("stdout") or "")[:6000])
    w.rule()
    w.p("Scanning was limited to discovery, service identification, limited enumeration and "
        "non-exploitative vulnerability checks. No exploitation, credential attacks or "
        "payload delivery was performed.")
    return w.render(f"Scanning report - {p['name']}")


def to_json(m: dict) -> str:
    return json.dumps(m, indent=2, default=str)


RENDERERS = {
    "md": ("text/markdown; charset=utf-8", "md", lambda m: to_markdown(m).encode()),
    "html": ("text/html; charset=utf-8", "html", lambda m: to_html(m).encode()),
    "pdf": ("application/pdf", "pdf", to_pdf),
    "json": ("application/json", "json", lambda m: to_json(m).encode()),
}
