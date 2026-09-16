/* ReconScan UI - zero build step, plain ES modules-free JS.
   Design rule enforced throughout: nothing is clickable without an explanation
   available at that spot, and the exact command is always visible before a run. */

const S = {
  meta: null,
  projects: [],
  project: null,
  tools: null,
  guided: [],
  glossary: [],
  view: 'dashboard',
  scanId: null,
  builder: null,
  ws: null,
};

/* ---------------- helpers ---------------- */
const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: opts.body instanceof FormData ? {} : { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (res.status === 401) {
    const j = await res.json().catch(() => ({}));
    S.meta = await (await fetch('/api/meta')).json();
    render();
    throw new Error(j.message || 'Sign in required.');
  }
  if (!res.ok) {
    const j = await res.json().catch(() => ({}));
    throw new Error(j.detail || j.message || `Request failed (${res.status}).`);
  }
  return res.status === 204 ? null : res.json();
}
const post = (p, body) => api(p, { method: 'POST', body: JSON.stringify(body) });
const del = (p) => api(p, { method: 'DELETE' });

function toast(msg, kind = '') {
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), kind === 'bad' ? 7000 : 3800);
}

function ago(iso) {
  if (!iso) return '';
  const d = new Date(iso), s = (Date.now() - d.getTime()) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return d.toLocaleDateString();
}
const dur = (n) => n < 60 ? `${n} sec` : n < 3600 ? `${Math.round(n / 60)} min` : `${(n / 3600).toFixed(1)} h`;

/* ---------------- drawer (the universal "?" explanation) ---------------- */
function drawer(title, html) {
  $('#drawerTitle').textContent = title;
  $('#drawerBody').innerHTML = html;
  $('#drawer').classList.add('open');
  $('#drawer').setAttribute('aria-hidden', 'false');
}
function closeDrawer() {
  $('#drawer').classList.remove('open');
  $('#drawer').setAttribute('aria-hidden', 'true');
}

/** A "?" button that opens an explanation. */
function q(title, body) {
  return `<button class="q" data-explain="${esc(title)}" data-body="${esc(body)}"
    title="What is this?" aria-label="Explain: ${esc(title)}">?</button>`;
}
/** An inline glossary link. */
function G(term, label) {
  return `<span class="gloss" data-term="${esc(term)}">${esc(label || term)}</span>`;
}

function showGlossary(term) {
  const t = S.glossary.find((x) => x.term.toLowerCase() === String(term).toLowerCase())
    || S.glossary.find((x) => x.term.toLowerCase().includes(String(term).toLowerCase()));
  if (!t) { drawer(term, `<p class="muted">No glossary entry for that yet.</p>`); return; }
  drawer(t.term, `<p><strong>${esc(t.short)}</strong></p><p>${esc(t.long)}</p>
    <p class="small muted">Tagged: ${t.tags.map(esc).join(', ')}</p>`);
}

document.addEventListener('click', (e) => {
  const ex = e.target.closest('[data-explain]');
  if (ex) { drawer(ex.dataset.explain, `<p>${esc(ex.dataset.body)}</p>`); return; }
  const gl = e.target.closest('[data-term]');
  if (gl) { showGlossary(gl.dataset.term); return; }
});

/* ---------------- boot ---------------- */
async function boot() {
  $('#drawerClose').onclick = closeDrawer;
  $('#ethicsLink').onclick = (e) => { e.preventDefault(); ethicsDrawer(); };
  try {
    S.meta = await (await fetch('/api/meta')).json();
  } catch {
    document.body.innerHTML = '<p style="padding:40px">Cannot reach the ReconScan server.</p>';
    return;
  }
  if (S.meta.authenticated) {
    const t = await api('/api/tools');
    S.tools = t.tools; S.guided = t.guided; S.installed = t.installed;
    S.sources = t.sources || {}; S.bundledDir = t.bundled_dir; S.platform = t.platform;
    S.glossary = await api('/api/glossary');
    S.projects = await api('/api/projects');
    S.templates = await api('/api/templates');
    const last = localStorage.getItem('reconscan.project');
    if (last && S.projects.some((p) => p.id === last)) await selectProject(last);
  }
  render();
}

async function selectProject(id) {
  S.project = await api(`/api/projects/${id}`);
  localStorage.setItem('reconscan.project', id);
}

function ethicsDrawer() {
  drawer('Authorized use only', `
    <p><strong>Scanning a computer you do not have permission to test is a crime in most
    countries</strong> - including the UK (Computer Misuse Act), the US (Computer Fraud and
    Abuse Act) and across the EU. It does not matter that you meant no harm, caused no damage,
    or only "looked".</p>
    <p>Permission means <strong>written</strong> permission, from someone entitled to give it,
    naming the systems and the dates. For your class, that is your instructor's lab brief.</p>
    <dt>Places you may legally practise</dt>
    <dd>Virtual machines on your own computer. Your class lab range. Deliberately vulnerable
    images such as Metasploitable or the OWASP Juice Shop, run locally. And
    <code class="inline">scanme.nmap.org</code>, which the nmap project publishes permission for -
    a few light scans a day, nothing heavy.</dd>
    <dt>What ReconScan does about it</dt>
    <dd>Every project records what authorizes it. Every target must be declared in scope before
    it can be scanned. Every command that runs is written to an audit log you can export with
    your report. None of this makes an unauthorized scan legal - it just makes it harder to do
    by accident.</dd>
    <dt>Where this tool stops</dt>
    <dd>ReconScan covers discovery, service identification, light enumeration and
    non-exploitative vulnerability checks. It will not exploit anything, guess passwords or
    deliver a payload. That boundary is the difference between an assessment and an intrusion.</dd>`);
}

/* ---------------- chrome ---------------- */
const NAV = [
  { sep: 'Engagement' },
  { id: 'dashboard', label: 'Dashboard', ic: '▦' },
  { id: 'targets', label: 'Targets & scope', ic: '◎' },
  { sep: 'Scanning' },
  { id: 'newscan', label: 'New scan', ic: '▶' },
  { id: 'results', label: 'Results', ic: '≡' },
  { id: 'compare', label: 'Compare scans', ic: '⇄' },
  { id: 'schedules', label: 'Schedules', ic: '◴' },
  { sep: 'Output' },
  { id: 'reports', label: 'Reports', ic: '⤓' },
  { sep: 'Learning' },
  { id: 'learn', label: 'Learn & glossary', ic: '⚑' },
  { id: 'quiz', label: 'Quiz yourself', ic: '◈' },
];

function renderNav() {
  $('#nav').innerHTML = NAV.map((n) => n.sep
    ? `<div class="sep">${esc(n.sep)}</div>`
    : `<button data-nav="${n.id}" class="${S.view === n.id || (n.id === 'results' && S.view === 'scan') ? 'active' : ''}">
         <span class="ic">${n.ic}</span>${esc(n.label)}</button>`).join('');
  $('#nav').querySelectorAll('[data-nav]').forEach((b) => {
    b.onclick = () => go(b.dataset.nav);
  });
}

function renderTopbar() {
  const m = S.meta;
  const proj = S.projects.length
    ? `<select id="projSel" style="width:auto;min-width:210px" title="Switch project">
        ${S.project ? '' : '<option value="">Choose a project…</option>'}
        ${S.projects.map((p) => `<option value="${p.id}" ${S.project && p.id === S.project.id ? 'selected' : ''}>${esc(p.name)}</option>`).join('')}
       </select>`
    : `<span class="muted small">No projects yet</span>`;
  const demo = `<label class="switch" title="Demo mode runs the whole app on realistic saved output and sends no packets.">
      <input type="checkbox" id="demoToggle" ${demoOn() ? 'checked' : ''}>
      <span class="track"></span>
      <span>${demoOn() ? '<span class="badge demo">DEMO MODE</span>' : '<span class="badge real">REAL SCANS</span>'}</span>
    </label>${q('Demo mode', 'When Demo mode is on, ReconScan never runs a real tool and never sends a packet. Every screen, parser and report works exactly as it does for real, but the output comes from realistic saved samples. Turn it off to run the actual tools against your in-scope targets.')}`;
  $('#topbar').innerHTML = `${proj}<div class="spacer"></div>${demo}
    ${m.lan_mode ? `<span class="badge lan">LAN - ${esc(m.username || '')}</span>
      <button class="btn ghost sm" id="logoutBtn">Sign out</button>` : `<span class="badge info">localhost</span>`}`;
  const sel = $('#projSel');
  if (sel) sel.onchange = async () => {
    if (!sel.value) return;
    await selectProject(sel.value);
    render();
  };
  const dt = $('#demoToggle');
  if (dt) dt.onchange = () => { localStorage.setItem('reconscan.demo', dt.checked ? '1' : '0'); render(); };
  const lo = $('#logoutBtn');
  if (lo) lo.onclick = async () => { await post('/api/logout', {}); location.reload(); };
}

function demoOn() {
  const v = localStorage.getItem('reconscan.demo');
  if (v === null) return !!(S.meta && S.meta.demo_default);
  return v === '1';
}

function go(view, arg) {
  // "New scan" means a new scan, including when you are already on that screen -
  // otherwise saving a template from the preflight and clicking New scan to use
  // it appears to do nothing. Internal step navigation goes through
  // renderBuilder(), not go(), so nothing here loses a part-built scan by accident.
  if (view === 'newscan') S.builder = null;
  S.view = view;
  if (view === 'scan') S.scanId = arg;
  closeDrawer();
  render();
  window.scrollTo(0, 0);
}

/* ---------------- render ---------------- */
function render() {
  const m = S.meta;
  if (!m) return;
  if (m.setup_required) return renderSetup();
  if (!m.authenticated) return renderLogin();

  document.querySelector('nav.sidebar').style.display = '';
  document.querySelector('.legalbar').style.display = '';
  renderNav();
  renderTopbar();

  const v = $('#view');
  v.className = 'view' + (S.view === 'scan' || S.view === 'results' ? ' wide' : '');
  const need = ['targets', 'newscan', 'results', 'reports', 'compare', 'schedules'];
  if (need.includes(S.view) && !S.project) return viewNoProject(v);

  ({
    dashboard: viewDashboard, targets: viewTargets, newscan: viewNewScan,
    results: viewResults, scan: viewScan, reports: viewReports, learn: viewLearn,
    compare: viewCompare, schedules: viewSchedules, quiz: viewQuiz,
  }[S.view] || viewDashboard)(v);
}

/* ---------------- gates ---------------- */
function gateShell(inner) {
  document.querySelector('nav.sidebar').style.display = 'none';
  document.querySelector('.legalbar').style.display = 'none';
  $('#topbar').innerHTML = `<h1 style="font-size:16px;margin:0"><span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--accent);margin-right:8px"></span>ReconScan</h1>`;
  $('#view').className = 'view';
  $('#view').innerHTML = `<div class="gate">${inner}</div>`;
}

function renderSetup() {
  gateShell(`
    <div class="card">
      <h2 class="page">Create your account</h2>
      <p class="lede">ReconScan is about to accept connections from other devices on your
      network, so it needs a login. This is the only account it will ever have.</p>
      <div class="notice caution"><strong>Why this matters</strong>
        This server can run network scanners, often as root. Anyone who reaches it can point
        those tools at anything your machine can see. Treat this password like a root password.</div>
      <label class="field"><span class="lbl">Username</span>
        <input type="text" id="su" autocomplete="username" value="admin"></label>
      <label class="field"><span class="lbl">Password
        ${q('Choosing a password', `At least ${S.meta.min_password_len} characters. Three or four unrelated words makes a password that is both stronger and easier to remember than a short one full of symbols. It is stored only as a salted hash - ReconScan never keeps the password itself.`)}</span>
        <input type="password" id="sp" autocomplete="new-password">
        <span class="help">Minimum ${S.meta.min_password_len} characters. Stored as a salted hash, never in plain text.</span></label>
      <label class="field"><span class="lbl">Confirm password</span>
        <input type="password" id="sp2" autocomplete="new-password"></label>
      <button class="btn primary" id="suBtn">Create account and sign in</button>
    </div>`);
  $('#suBtn').onclick = async () => {
    if ($('#sp').value !== $('#sp2').value) return toast('The two passwords do not match.', 'bad');
    try {
      await post('/api/setup', { username: $('#su').value, password: $('#sp').value });
      location.reload();
    } catch (e) { toast(e.message, 'bad'); }
  };
}

function renderLogin() {
  gateShell(`
    <div class="card">
      <h2 class="page">Sign in</h2>
      <p class="lede">ReconScan is reachable from your network, so it requires a login.</p>
      <label class="field"><span class="lbl">Username</span>
        <input type="text" id="lu" autocomplete="username"></label>
      <label class="field"><span class="lbl">Password</span>
        <input type="password" id="lp" autocomplete="current-password"></label>
      <button class="btn primary" id="loginBtn">Sign in</button>
      <p class="help" style="margin-top:14px">Connections are encrypted with a self-signed
      certificate, which is why your browser warned you. ${S.meta.cert_fingerprint
        ? `You can check it matches this fingerprint:<br><code class="inline">${esc(S.meta.cert_fingerprint.slice(0, 47))}...</code>` : ''}</p>
    </div>`);
  const submit = async () => {
    try {
      await post('/api/login', { username: $('#lu').value, password: $('#lp').value });
      location.reload();
    } catch (e) { toast(e.message, 'bad'); }
  };
  $('#loginBtn').onclick = submit;
  $('#lp').onkeydown = (e) => { if (e.key === 'Enter') submit(); };
}

function viewNoProject(v) {
  v.innerHTML = `<h2 class="page">Pick a project first</h2>
    <p class="lede">Everything in ReconScan happens inside a project: it holds the scope you
    are authorized to test, the scans you ran, and the report you will hand in.</p>
    <button class="btn primary" id="mk">Create a project</button>`;
  $('#mk').onclick = () => go('dashboard');
}

/* ---------------- dashboard ---------------- */
function viewDashboard(v) {
  const p = S.project;
  v.innerHTML = `
    <h2 class="page">Dashboard</h2>
    <p class="lede">ReconScan covers the <strong>scanning</strong> phase of a penetration test:
    active discovery, port and service identification, light ${G('Enumeration', 'enumeration')} and
    non-exploitative vulnerability checks. Recon is already done; ${G('Exploitation', 'exploitation')}
    comes later and is deliberately out of scope here.</p>

    ${demoOn() ? `<div class="notice demo"><strong>Demo mode is on</strong>
      Nothing you do right now sends a single packet anywhere. Scans return realistic saved
      output so you can learn the whole workflow risk-free. Flip the switch in the header when
      you are ready to scan for real.</div>` : ''}

    ${p ? dashProject(p) : ''}

    <h3 class="sec">Projects</h3>
    <div class="grid three">
      ${S.projects.map((pr) => `
        <div class="card">
          <h4>${esc(pr.name)}</h4>
          <p class="small muted" style="margin:4px 0 10px">${pr.target_count} target(s) &middot; ${pr.scan_count} scan(s) &middot; created ${ago(pr.created_at)}</p>
          <div class="btnrow">
            <button class="btn sm" data-open="${pr.id}">Open</button>
            <button class="btn sm ghost danger" data-delp="${pr.id}">Delete</button>
          </div>
        </div>`).join('')}
      <div class="card" style="border-style:dashed;box-shadow:none">
        <h4>New project</h4>
        <p class="small muted" style="margin:4px 0 10px">One project per engagement or assignment.</p>
        <button class="btn primary sm" id="newProj">Create project</button>
      </div>
    </div>`;

  v.querySelectorAll('[data-open]').forEach((b) => {
    b.onclick = async () => { await selectProject(b.dataset.open); go('targets'); };
  });
  v.querySelectorAll('[data-delp]').forEach((b) => {
    b.onclick = async () => {
      if (!confirm('Delete this project, and every target, scan and result in it? This cannot be undone.')) return;
      await del(`/api/projects/${b.dataset.delp}`);
      if (S.project && S.project.id === b.dataset.delp) { S.project = null; localStorage.removeItem('reconscan.project'); }
      S.projects = await api('/api/projects');
      render();
    };
  });
  $('#newProj').onclick = newProjectDialog;
}

function dashProject(p) {
  const done = p.scans.filter((s) => s.status === 'done').length;
  const inScope = p.targets.filter((t) => t.in_scope).length;
  return `
    <div class="grid three" style="margin-bottom:20px">
      <div class="stat"><div class="n">${inScope}</div><div class="l">targets in scope</div></div>
      <div class="stat"><div class="n">${p.scans.length}</div><div class="l">scans run (${done} completed)</div></div>
      <div class="stat"><div class="n">${p.scans.filter((s) => s.is_demo).length}</div><div class="l">of those were demo runs</div></div>
    </div>
    <div class="card">
      <h4>${esc(p.name)}</h4>
      <p class="small" style="color:var(--ink-2);margin:6px 0 12px"><strong>Authorized by:</strong> ${esc(p.authorization_note)}</p>
      <div class="btnrow">
        <button class="btn primary sm" onclick="RS.go('newscan')">Start a scan</button>
        <button class="btn sm" onclick="RS.go('targets')">Manage scope</button>
        <button class="btn sm" onclick="RS.go('reports')">Build the report</button>
      </div>
    </div>`;
}

function newProjectDialog() {
  drawer('New project', `
    <p>A project records <em>what you are allowed to test and why</em>. That note goes into
    your report, and it is the line between a penetration test and a computer crime.</p>
    <label class="field"><span class="lbl">Project name</span>
      <input type="text" id="np_name" placeholder="CS-410 Lab 3 - internal range"></label>
    <label class="field"><span class="lbl">What authorizes this testing?
      ${q('Authorization note', 'Write down who gave permission, for which systems, and when. Examples: "CS-410 Lab 3 brief from Prof. Adeyemi, instructor-provided VMs at 10.10.10.0/24, week of 14 Sep 2026." Or "My own Metasploitable VM running in VirtualBox on my laptop." Or "scanme.nmap.org, which the nmap project publishes permission to scan."')}</span>
      <textarea id="np_auth" rows="4" placeholder="CS-410 Lab 3 brief, instructor-provided VMs at 10.10.10.0/24, week of 14 Sep 2026"></textarea>
      <span class="help">At least a full sentence. This appears in section 1 of your exported report.</span></label>
    <label class="check"><input type="checkbox" id="np_ack">
      <span>I confirm I have permission from the owner of these systems to scan them, and I
      understand that scanning systems without permission is illegal.</span></label>
    <button class="btn primary" id="np_go">Create project</button>`);
  $('#np_go').onclick = async () => {
    try {
      const p = await post('/api/projects', {
        name: $('#np_name').value, authorization_note: $('#np_auth').value,
        acknowledged: $('#np_ack').checked,
      });
      S.projects = await api('/api/projects');
      await selectProject(p.id);
      closeDrawer(); toast('Project created. Now add the targets you are allowed to scan.', 'good');
      go('targets');
    } catch (e) { toast(e.message, 'bad'); }
  };
}

/* ---------------- targets ---------------- */
function viewTargets(v) {
  const p = S.project;
  v.innerHTML = `
    <h2 class="page">Targets &amp; scope</h2>
    <p class="lede">Scope is the list of systems you are authorized to test. ReconScan will
    refuse to scan anything that is not on it - that guardrail is there for your protection.
    ${q('Why scope is enforced', 'A typo in an IP address is the classic way a student ends up scanning a stranger. By requiring every target to be declared first, a mistyped address during scan setup becomes a refusal rather than an incident.')}</p>

    <div class="grid two">
      <div class="card">
        <h4>Add targets</h4>
        <p class="small muted" style="margin:4px 0 10px">One per line. Paste your recon output
        straight in - comments (<code class="inline">#</code>) and extra columns are ignored.</p>
        <textarea id="tg_text" rows="7" placeholder="10.10.10.42
192.168.56.0/24
192.168.1.10-40
scanme.nmap.org
http://10.10.10.42:8080"></textarea>
        <div class="help" style="margin-bottom:10px">Accepted: ${G('IP address', 'single IP')},
        ${G('CIDR', 'CIDR range')}, address range, hostname, or URL.</div>
        <div class="btnrow">
          <button class="btn primary sm" id="tg_add">Add to scope</button>
          <label class="btn sm" style="cursor:pointer">Import a file
            <input type="file" id="tg_file" hidden accept=".txt,.csv,.list,.log,.json"></label>
        </div>
      </div>
      <div class="card">
        <h4>Safe places to practise</h4>
        <p class="small" style="color:var(--ink-2)">If you are not in a lab right now, these are
        legal to scan:</p>
        <ul class="small" style="color:var(--ink-2);padding-left:18px;line-height:1.85">
          <li><code class="inline">scanme.nmap.org</code> - the nmap project publishes permission.
            Keep it to a few light scans a day.</li>
          <li><code class="inline">127.0.0.1</code> - your own machine.</li>
          <li>A vulnerable VM you run yourself (Metasploitable, Juice Shop) on its local IP.</li>
        </ul>
        <button class="btn sm" id="tg_quick">Add scanme.nmap.org</button>
      </div>
    </div>

    <h3 class="sec">Declared scope (${p.targets.length})
      ${q('In scope vs excluded', 'An excluded entry always wins over an in-scope one. So you can declare 10.10.10.0/24 in scope and then exclude 10.10.10.1 - the range stays scannable, that one machine does not. That is how you carve out the box you must not touch: the domain controller, or the production server someone left on the lab network.')}</h3>
    ${p.targets.some((t) => !t.in_scope) ? `<div class="notice caution" style="margin-bottom:12px">
      <strong>${p.targets.filter((t) => !t.in_scope).length} target(s) are excluded</strong>
      An exclusion beats any in-scope range that would otherwise cover it, so these will be
      refused even if they sit inside a range you declared.</div>` : ''}
    ${p.targets.length ? `
      <table class="data"><thead><tr>
        <th>Target</th><th>Type</th><th>Expands to</th><th>In scope</th><th></th>
      </tr></thead><tbody>
      ${p.targets.map((t) => `<tr>
        <td><code class="inline">${esc(t.value)}</code></td>
        <td>${esc(t.type)}</td>
        <td class="muted">${t.type === 'cidr' || t.type === 'range' ? 'multiple addresses' : '1 address'}</td>
        <td>${t.in_scope ? '<span class="badge low">in scope</span>' : '<span class="badge high">excluded</span>'}</td>
        <td style="text-align:right;white-space:nowrap">
          <button class="btn ghost sm" data-toggle="${t.id}" data-val="${t.in_scope ? '0' : '1'}">${t.in_scope ? 'Exclude' : 'Include'}</button>
          <button class="btn ghost sm danger" data-delt="${t.id}">Remove</button></td>
      </tr>`).join('')}
      </tbody></table>` : `<div class="empty"><div class="big">◎</div>
        No targets yet. Add the systems from your lab brief above.</div>`}`;

  $('#tg_add').onclick = async () => {
    const text = $('#tg_text').value;
    if (!text.trim()) return toast('Nothing to add.', 'bad');
    const r = await post(`/api/projects/${p.id}/targets`, { text, in_scope: true });
    afterImport(r);
  };
  $('#tg_quick').onclick = async () => {
    const r = await post(`/api/projects/${p.id}/targets`, { text: 'scanme.nmap.org', in_scope: true });
    afterImport(r);
  };
  $('#tg_file').onchange = async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    const fd = new FormData();
    fd.append('file', f); fd.append('in_scope', 'true');
    const r = await api(`/api/projects/${p.id}/targets/upload`, { method: 'POST', body: fd });
    afterImport(r);
  };
  v.querySelectorAll('[data-toggle]').forEach((b) => {
    b.onclick = async () => {
      await api(`/api/targets/${b.dataset.toggle}`, {
        method: 'PATCH', body: JSON.stringify({ in_scope: b.dataset.val === '1' }),
      });
      await selectProject(p.id); render();
    };
  });
  v.querySelectorAll('[data-delt]').forEach((b) => {
    b.onclick = async () => { await del(`/api/targets/${b.dataset.delt}`); await selectProject(p.id); render(); };
  });
}

async function afterImport(r) {
  await selectProject(S.project.id);
  render();
  if (r.added.length) toast(`Added ${r.added.length} target(s).`, 'good');
  if (r.skipped.length) toast(`${r.skipped.length} were already in scope.`);
  if (r.errors.length) {
    drawer('Some lines could not be added', `<p>${r.added.length} target(s) were added.
      These lines were not understood:</p>` +
      r.errors.map((e) => `<dt><code class="inline">${esc(e.line)}</code></dt>
        <dd>${esc(e.error)}</dd>`).join(''));
  }
}

/* ---------------- new scan ---------------- */
function viewNewScan(v) {
  const p = S.project;
  const inScope = p.targets.filter((t) => t.in_scope);
  if (!inScope.length) {
    v.innerHTML = `<h2 class="page">New scan</h2>
      <div class="notice caution"><strong>No targets in scope yet</strong>
      ReconScan will not scan anything you have not declared. Add the systems from your lab
      brief on the Targets screen first.</div>
      <button class="btn primary" onclick="RS.go('targets')">Go to Targets</button>`;
    return;
  }
  if (!S.builder) S.builder = { step: 1, goal: null, target: inScope[0].value, opts: {}, advanced: false, plan: null };
  const b = S.builder;

  v.innerHTML = `
    <h2 class="page">New scan</h2>
    <p class="lede">Pick what you want to find out. ReconScan chooses the tool and the flags,
    shows you the exact command, and explains every part of it before anything runs.</p>
    ${stepsBar(b.step)}
    <div id="builder"></div>`;
  renderBuilder();
}

function stepsBar(step) {
  const labels = ['Choose a goal', 'Pick the target', 'Tune the options', 'Review and run'];
  return `<div class="steps">${labels.map((l, i) => {
    const n = i + 1;
    const done = step > n;
    return `<div class="st ${step === n ? 'on' : ''} ${done ? 'done' : ''}"
        ${done ? `data-step="${n}" role="button" tabindex="0" title="Go back to this step"` : ''}>
      <span class="num">${done ? '✓' : n}</span>${esc(l)}</div>
      ${n < 4 ? '<span class="arrow">›</span>' : ''}`;
  }).join('')}</div>`;
}

/** Steps you have already completed are clickable, so you can jump back. */
function wireSteps() {
  document.querySelectorAll('.steps [data-step]').forEach((el) => {
    el.onclick = () => { S.builder.step = Number(el.dataset.step); renderBuilder(); };
  });
}

function renderBuilder() {
  const b = S.builder, host = $('#builder');
  if (!host) return;
  const bar = $('#view').querySelector('.steps');
  if (bar) { bar.outerHTML = stepsBar(b.step); wireSteps(); }

  if (b.step === 1) return builderGoals(host);
  if (b.step === 2) return builderTarget(host);
  if (b.step === 3) return builderOptions(host);
  return builderPreflight(host);
}

function builderGoals(host) {
  const tpl = S.templates || [];
  host.innerHTML = `
    ${tpl.length ? `
      <h3 class="sec" style="margin-top:0">Your saved setups
        ${q('Saved templates', 'A template remembers a tool, a goal and every option you tuned, so a scan you worked out once can be re-run against anything in scope with one click. The target is not part of the template - you pick that each time.')}</h3>
      <div class="goals" style="margin-bottom:6px">
        ${tpl.map((t) => `<button class="goal" data-tpl="${t.id}">
          <span class="g-step">Saved · used ${t.use_count} time(s)</span>
          <span class="g-label">${esc(t.name)}</span>
          <span class="g-tool">${esc(t.tool)} · ${esc(t.goal)}</span>
          ${t.note ? `<span class="help" style="margin:4px 0 0">${esc(t.note)}</span>` : ''}
        </button>`).join('')}
      </div>
      <div class="btnrow" style="margin-bottom:22px">
        <button class="btn ghost sm" id="mgTpl">Manage saved setups</button>
      </div>` : ''}

    <h3 class="sec" style="${tpl.length ? '' : 'margin-top:0'}">What do you want to find out?</h3>
    <div class="goals">
      ${S.guided.map((g) => {
        const installed = S.installed[g.tool];
        return `<button class="goal ${S.builder.goal === g.id ? 'sel' : ''}" data-goal="${g.id}">
          <span class="g-step">${esc(g.step)}</span>
          <span class="g-label">${esc(g.label)}</span>
          <span class="g-tool">${esc(g.tool)}</span>
          ${!installed && !demoOn() ? '<span class="g-missing">not installed</span>' : ''}
        </button>`;
      }).join('')}
    </div>
    <p class="help" style="margin-top:14px">Every goal maps to a real tool and real flags -
    nothing here is a toy. You will see the command before it runs, and the Advanced panel on
    the next screen exposes the raw flags once you want them.</p>`;

  host.querySelectorAll('[data-goal]').forEach((btn) => {
    btn.onclick = () => {
      const g = S.guided.find((x) => x.id === btn.dataset.goal);
      S.builder.goal = g.id; S.builder.tool = g.tool; S.builder.goalId = g.goal;
      S.builder.opts = {}; S.builder.fromTemplate = null; S.builder.step = 2;
      renderBuilder();
    };
  });
  host.querySelectorAll('[data-tpl]').forEach((btn) => {
    btn.onclick = () => {
      const t = tpl.find((x) => x.id === btn.dataset.tpl);
      const g = S.guided.find((x) => x.tool === t.tool && x.goal === t.goal);
      S.builder.goal = g ? g.id : null;
      S.builder.tool = t.tool; S.builder.goalId = t.goal;
      S.builder.opts = { ...(t.options || {}) };
      S.builder.fromTemplate = t.id;
      S.builder.step = 2;
      renderBuilder();
    };
  });
  const mg = $('#mgTpl');
  if (mg) mg.onclick = manageTemplates;
}

function manageTemplates() {
  drawer('Saved setups', `
    <p>Each of these remembers a tool, a goal and the options you chose. Deleting one does not
    affect any scan you already ran with it.</p>
    ${(S.templates || []).map((t) => `
      <dt>${esc(t.name)}</dt>
      <dd><code class="inline">${esc(t.tool)} · ${esc(t.goal)}</code> · used ${t.use_count} time(s)
        ${t.note ? `<br>${esc(t.note)}` : ''}
        <br><button class="btn ghost sm danger" data-deltpl="${t.id}" style="margin-top:6px">Delete</button></dd>`).join('')
      || '<p class="muted">Nothing saved yet.</p>'}`);
  $('#drawerBody').querySelectorAll('[data-deltpl]').forEach((b) => {
    b.onclick = async () => {
      await del(`/api/templates/${b.dataset.deltpl}`);
      S.templates = await api('/api/templates');
      closeDrawer(); renderBuilder();
    };
  });
}

function goalDef() {
  const b = S.builder;
  const tool = S.tools.find((t) => t.id === b.tool);
  return { tool, goal: tool.goals.find((g) => g.id === b.goalId) };
}

function builderTarget(host) {
  const b = S.builder;
  const { tool, goal } = goalDef();
  const inScope = S.project.targets.filter((t) => t.in_scope);
  const usable = inScope.filter((t) => goal.target_types.includes(t.type));
  host.innerHTML = `
    <div class="card">
      <h4>${esc(goal.label)}</h4>
      <p class="small" style="color:var(--ink-2);margin:6px 0 0">${esc(goal.detail)}</p>
      <p class="small muted" style="margin:8px 0 0">Tool: <code class="inline">${esc(tool.name)}</code>
      &middot; typically ${esc(goal.typical_duration)}
      ${q(tool.name, `${tool.card.what}\n\nWhy: ${tool.card.why}\n\nWhen: ${tool.card.when}\n\nHow noisy: ${tool.card.noise}`)}</p>
    </div>
    <div class="card">
      <h4>Which target?</h4>
      ${usable.length ? `
        <p class="small muted" style="margin:4px 0 10px">Only targets you declared in scope appear here.</p>
        ${usable.map((t) => `<label class="check">
          <input type="radio" name="tg" value="${esc(t.value)}" ${b.target === t.value ? 'checked' : ''}>
          <span><code class="inline">${esc(t.value)}</code> <span class="muted small">(${esc(t.type)})</span></span>
        </label>`).join('')}`
      : `<div class="notice caution"><strong>None of your in-scope targets suit this goal</strong>
          '${esc(goal.label)}' accepts ${goal.target_types.join(', ')}. Add a suitable target on the
          Targets screen.</div>`}
      ${inScope.length > usable.length ? `<p class="help">${inScope.length - usable.length} in-scope
        target(s) hidden because this goal cannot use that kind of target.</p>` : ''}
    </div>
    <div class="btnrow">
      <button class="btn" data-back>‹ Back</button>
      <button class="btn primary" data-next ${usable.length ? '' : 'disabled'}>Continue</button>
    </div>`;
  host.querySelectorAll('input[name=tg]').forEach((r) => {
    r.onchange = () => { S.builder.target = r.value; };
  });
  if (usable.length && !usable.some((t) => t.value === b.target)) b.target = usable[0].value;
  host.querySelector('[data-back]').onclick = () => { b.step = 1; renderBuilder(); };
  const nx = host.querySelector('[data-next]');
  if (nx) nx.onclick = () => { b.step = 3; renderBuilder(); };
}

function optionField(o, val) {
  const id = `opt_${o.id}`;
  const lbl = `<span class="lbl">${esc(o.label)} ${q(o.label, o.help)}</span>`;
  if (o.type === 'bool') {
    return `<label class="check"><input type="checkbox" id="${id}" data-opt="${o.id}" ${val ? 'checked' : ''}>
      <span><strong>${esc(o.label)}</strong> ${q(o.label, o.help)}<br>
      <span class="help" style="margin:0">${esc(o.help.slice(0, 150))}${o.help.length > 150 ? '…' : ''}</span></span></label>`;
  }
  if (o.type === 'select') {
    const cur = val == null ? o.default : val;
    const choice = o.choices.find((c) => String(c.value) === String(cur));
    return `<label class="field">${lbl}
      <select id="${id}" data-opt="${o.id}">
        ${o.choices.map((c) => `<option value="${esc(c.value)}" ${String(c.value) === String(cur) ? 'selected' : ''}>${esc(c.label)}</option>`).join('')}
      </select>
      <span class="help">${esc(choice ? choice.help : o.help)}</span></label>`;
  }
  if (o.type === 'number') {
    return `<label class="field">${lbl}
      <input type="number" id="${id}" data-opt="${o.id}" value="${esc(val == null ? o.default : val)}"
        ${o.min != null ? `min="${o.min}"` : ''} ${o.max != null ? `max="${o.max}"` : ''}>
      <span class="help">${esc(o.help)}</span></label>`;
  }
  return `<label class="field">${lbl}
    <input type="text" id="${id}" data-opt="${o.id}" value="${esc(val == null ? o.default : val)}"
      placeholder="${esc(o.placeholder || '')}">
    <span class="help">${esc(o.help)}</span></label>`;
}

function builderOptions(host) {
  const b = S.builder;
  const { tool, goal } = goalDef();
  const basic = goal.options.filter((o) => !o.advanced);
  const adv = goal.options.filter((o) => o.advanced);
  host.innerHTML = `
    <div class="card">
      <h4>${esc(goal.label)} <span class="muted small" style="font-weight:400">on <code class="inline">${esc(b.target)}</code></span></h4>
      <p class="small" style="color:var(--ink-2);margin:6px 0 16px">${esc(goal.blurb)}</p>
      ${basic.map((o) => optionField(o, b.opts[o.id])).join('')}
      ${adv.length ? `
        <div style="border-top:1px solid var(--line);margin-top:6px;padding-top:14px">
          <label class="check" style="margin-bottom:${b.advanced ? '14px' : '0'}">
            <input type="checkbox" id="advToggle" ${b.advanced ? 'checked' : ''}>
            <span><strong>Advanced</strong> ${q('Advanced options', 'These are the expert controls: raw flags, scan techniques, probe intensity. They are hidden by default so the guided path stays clean, not because you should not use them. Once you know the CLI, this is where you stop being limited by this interface.')}<br>
            <span class="help" style="margin:0">Raw flags and expert controls. Nothing here is hidden from you - just tucked away.</span></span>
          </label>
          <div id="advPanel" ${b.advanced ? '' : 'hidden'}>${adv.map((o) => optionField(o, b.opts[o.id])).join('')}</div>
        </div>` : ''}
    </div>
    <div class="btnrow">
      <button class="btn" data-back>‹ Back</button>
      <button class="btn primary" data-next>Review the command ›</button>
    </div>`;

  const collect = () => {
    host.querySelectorAll('[data-opt]').forEach((el) => {
      b.opts[el.dataset.opt] = el.type === 'checkbox' ? el.checked
        : el.type === 'number' ? Number(el.value) : el.value;
    });
  };
  // Only selects and checkboxes re-render, because their choice changes the help
  // text or reveals the Advanced panel. Text and number fields just record their
  // value: re-rendering on their blur would replace the button you were about to
  // click, and the click would land on nothing.
  host.querySelectorAll('[data-opt]').forEach((el) => {
    if (el.tagName === 'SELECT' || el.type === 'checkbox') {
      el.onchange = () => { collect(); renderBuilder(); };
    } else {
      el.oninput = collect;
    }
  });
  const at = $('#advToggle');
  if (at) at.onchange = () => { collect(); b.advanced = at.checked; renderBuilder(); };
  host.querySelector('[data-back]').onclick = () => { collect(); b.step = 2; renderBuilder(); };
  host.querySelector('[data-next]').onclick = async () => {
    collect();
    try {
      b.plan = await post('/api/plan', {
        project_id: S.project.id, tool: b.tool, goal: b.goalId,
        target: b.target, options: b.opts,
      });
      b.step = 4; renderBuilder();
    } catch (e) { toast(e.message, 'bad'); }
  };
}

function commandBox(plan) {
  const toks = plan.explained.map((t, i) => {
    const cls = i === 0 ? 'bin' : t.token.startsWith('-') ? 'flag'
      : i === plan.explained.length - 1 ? 'target' : '';
    const ex = t.help ? 'explained' : '';
    return `<span class="tok ${cls} ${ex}" ${t.help ? `data-explain="${esc(t.token)}" data-body="${esc(t.help)}" title="${esc(t.help)}"` : ''}>${esc(t.token)}</span>`;
  }).join(' ');
  return `<div class="cmdhead">
      <h4>The exact command that will run</h4>
      ${q('Why show the command?', 'This is the single most useful thing on the screen. It is exactly what a professional would type into a terminal, and it is exactly what ReconScan is about to execute - not a simplified version of it. Click any underlined part to find out what it does. Once these stop surprising you, you no longer need the training wheels.')}
      <div style="flex:1"></div>
      <button class="btn ghost sm" id="copyCmd">Copy</button>
    </div>
    <div class="cmdbox">${toks}</div>
    <p class="help">Underlined parts are explained - hover, or click for the full note.
    ReconScan builds this as a list of separate arguments and runs it without a shell, which is
    why ${G('Command injection', 'command injection')} is not possible here.</p>`;
}

function builderPreflight(host) {
  const b = S.builder, plan = b.plan;
  const demo = demoOn();
  host.innerHTML = `
    <div class="card">
      ${commandBox(plan)}
    </div>

    <div class="grid three" style="margin:14px 0">
      <div class="stat"><div class="n">${plan.host_count.toLocaleString()}</div>
        <div class="l">address${plan.host_count === 1 ? '' : 'es'} will be scanned</div></div>
      <div class="stat"><div class="n">~${dur(plan.est_seconds)}</div>
        <div class="l">rough estimate, not a promise</div></div>
      <div class="stat"><div class="n">${plan.needs_root ? 'root' : 'normal'}</div>
        <div class="l">privileges this scan wants</div></div>
    </div>

    ${demo ? `<div class="notice demo"><strong>This will run in Demo mode</strong>
      No packets will be sent. You will get realistic saved output so you can see exactly what
      this scan produces and how it is interpreted. Turn Demo off in the header to run it for real.</div>`
    : `<div class="notice ok"><strong>This is a real scan</strong>
      ${esc(plan.tool_name)} will genuinely contact <code>${esc(plan.target)}</code>.
      Confirm this target is inside the scope you are authorized to test.</div>`}

    ${plan.warnings.map((w) => `<div class="notice ${w.level === 'danger' ? 'danger' : w.level === 'caution' ? 'caution' : 'info'}">
      <strong>${esc(w.title)}</strong>${esc(w.body)}</div>`).join('')}

    ${plan.notes.length ? `<div class="card"><h4>Worth knowing</h4>
      <ul class="small" style="color:var(--ink-2);padding-left:18px;line-height:1.8;margin:6px 0 0">
      ${plan.notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul></div>` : ''}

    ${!plan.tool_installed && !demo ? `<div class="notice danger"><strong>${esc(plan.tool_name)} is not installed here</strong>
      This scan cannot run for real on this machine. Install it on the Kali host, or switch on
      Demo mode to see how it works.</div>` : ''}

    <div class="btnrow" style="margin-top:16px">
      <button class="btn" data-back>‹ Change options</button>
      <button class="btn primary" data-run ${(!plan.tool_installed && !demo) ? 'disabled' : ''}>
        ${demo ? 'Run in Demo mode' : 'Run this scan'}</button>
      <button class="btn ghost" data-savetpl>Save these settings</button>
      ${q('Save these settings', 'Stores this tool, goal and every option you tuned as a reusable setup, so you can run the same scan again without rebuilding it. The target is not saved - you pick that each time, and it is still checked against your scope.')}
    </div>`;

  $('#copyCmd').onclick = () => {
    navigator.clipboard.writeText(plan.preview).then(() => toast('Command copied.', 'good'));
  };
  host.querySelector('[data-back]').onclick = () => { b.step = 3; renderBuilder(); };
  host.querySelector('[data-run]').onclick = async () => {
    try {
      const r = await post('/api/scans', {
        project_id: S.project.id, tool: b.tool, goal: b.goalId,
        target: b.target, options: b.opts, demo,
      });
      if (b.fromTemplate) post(`/api/templates/${b.fromTemplate}/used`, {}).catch(() => {});
      S.builder = null;
      await selectProject(S.project.id);
      go('scan', r.id);
    } catch (e) { toast(e.message, 'bad'); }
  };
  host.querySelector('[data-savetpl]').onclick = () => saveTemplateDialog(b, plan);
}

function saveTemplateDialog(b, plan) {
  drawer('Save these settings', `
    <p>This stores the tool, the goal and every option you tuned, so you can run the same scan
    again in one click. The target is <strong>not</strong> saved - you pick that each time, and
    it is still checked against your project's scope.</p>
    <label class="field"><span class="lbl">Name</span>
      <input type="text" id="tp_name" value="${esc(plan.goal_label)}"></label>
    <label class="field"><span class="lbl">Note to yourself (optional)</span>
      <input type="text" id="tp_note" placeholder="Quiet version for the fragile lab box"></label>
    <div class="cmdhead"><h4>Settings being saved</h4></div>
    <div class="cmdbox" style="font-size:12px">${esc(plan.preview)}</div>
    <button class="btn primary" id="tp_go" style="margin-top:14px">Save</button>`);
  $('#tp_go').onclick = async () => {
    try {
      await post('/api/templates', {
        name: $('#tp_name').value, tool: b.tool, goal: b.goalId,
        options: b.opts, note: $('#tp_note').value,
      });
      S.templates = await api('/api/templates');
      closeDrawer();
      toast('Saved. It will appear at the top of the New scan screen.', 'good');
    } catch (e) { toast(e.message, 'bad'); }
  };
}

/* ---------------- results list ---------------- */
function viewResults(v) {
  const p = S.project;
  v.innerHTML = `
    <h2 class="page">Results</h2>
    <p class="lede">Every scan this project has run, newest first. Each one keeps its exact
    command, its raw output and its parsed findings.</p>
    ${p.scans.length ? `
      <table class="data"><thead><tr>
        <th>When</th><th>Goal</th><th>Target</th><th>Command</th><th>Mode</th><th>Status</th><th></th>
      </tr></thead><tbody>
      ${p.scans.map((s) => `<tr class="clickable" data-scan="${s.id}">
        <td class="muted" style="white-space:nowrap">${ago(s.created_at)}</td>
        <td>${esc(s.goal)}</td>
        <td><code class="inline">${esc(s.target)}</code></td>
        <td class="muted small" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(s.preview)}</td>
        <td>${s.is_demo ? '<span class="badge demo">DEMO</span>' : '<span class="badge real">real</span>'}</td>
        <td><span class="badge ${esc(s.status)}">${esc(s.status)}</span></td>
        <td style="text-align:right"><button class="btn ghost sm danger" data-dels="${s.id}">Delete</button></td>
      </tr>`).join('')}
      </tbody></table>`
    : `<div class="empty"><div class="big">≡</div>No scans yet.
        <div style="margin-top:12px"><button class="btn primary" onclick="RS.go('newscan')">Start your first scan</button></div></div>`}`;

  v.querySelectorAll('[data-scan]').forEach((tr) => {
    tr.onclick = (e) => { if (!e.target.closest('[data-dels]')) go('scan', tr.dataset.scan); };
  });
  v.querySelectorAll('[data-dels]').forEach((b) => {
    b.onclick = async (e) => {
      e.stopPropagation();
      if (!confirm('Delete this scan and its results?')) return;
      await del(`/api/scans/${b.dataset.dels}`);
      await selectProject(p.id); render();
    };
  });
}

/* ---------------- scan detail ---------------- */
async function viewScan(v) {
  v.innerHTML = `<p class="muted">Loading scan…</p>`;
  let scan;
  try { scan = await api(`/api/scans/${S.scanId}`); }
  catch (e) { v.innerHTML = `<div class="notice danger">${esc(e.message)}</div>`; return; }
  S.scan = scan;
  paintScan(v, scan);
  if (scan.status === 'running' || scan.status === 'queued') openSocket(scan.id);
  else if (scan.stdout) fillConsole(scan.stdout.split('\n'));
}

function paintScan(v, scan) {
  const running = scan.status === 'running' || scan.status === 'queued';
  v.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px">
      <h2 class="page" style="margin:0">${esc(scan.goal)} on ${esc(scan.target)}</h2>
      <span class="badge ${esc(scan.status)}" id="scanStatus">${esc(scan.status)}</span>
      ${scan.is_demo ? '<span class="badge demo">DEMO - no packets sent</span>' : '<span class="badge real">real scan</span>'}
      <div style="flex:1"></div>
      ${running ? '<button class="btn danger sm" id="cancelBtn">Stop this scan</button>' : ''}
      <button class="btn sm" id="rerunBtn">Run again</button>
    </div>
    <p class="lede small" id="narration">${running
      ? `${esc(scan.tool)} is running. Output appears below as it arrives.`
      : `Finished ${ago(scan.finished_at || scan.created_at)} with exit code ${scan.exit_code}.`}</p>

    <div class="card" style="margin-bottom:14px">${commandBoxFromScan(scan)}</div>
    ${running ? '<div class="progress indet"><div></div></div>' : ''}

    <div class="tabs" id="scanTabs">
      <button data-tab="findings" class="active">Findings <span class="muted">(${scan.findings.length})</span></button>
      <button data-tab="output">Live output</button>
      <button data-tab="next">What to do next</button>
    </div>
    <div id="tab_findings">${renderFindings(scan)}</div>
    <div id="tab_output" hidden>
      <div class="console" id="console"></div>
      <p class="help">This is the tool's raw output, exactly as it was printed - the evidence
      behind every finding above. Keep it; a report that shows its evidence is worth more than
      one that only shows conclusions.</p>
    </div>
    <div id="tab_next" hidden>${renderNext(scan)}</div>`;

  $('#scanTabs').querySelectorAll('[data-tab]').forEach((b) => {
    b.onclick = () => {
      $('#scanTabs').querySelectorAll('button').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      ['findings', 'output', 'next'].forEach((t) => { $(`#tab_${t}`).hidden = t !== b.dataset.tab; });
    };
  });
  const cb = $('#cancelBtn');
  if (cb) cb.onclick = async () => {
    try { await post(`/api/scans/${scan.id}/cancel`, {}); toast('Stopping the scan…'); }
    catch (e) { toast(e.message, 'bad'); }
  };
  $('#rerunBtn').onclick = async () => {
    try {
      const r = await post('/api/scans', {
        project_id: scan.project_id, tool: scan.tool, goal: scan.goal,
        target: scan.target, options: {}, demo: demoOn(),
      });
      await selectProject(scan.project_id);
      go('scan', r.id);
    } catch (e) { toast(e.message, 'bad'); }
  };
  v.querySelectorAll('.cmdbox .tok.explained').forEach(() => {});
}

function commandBoxFromScan(scan) {
  const argv = scan.command_args || [];
  const tool = S.tools.find((t) => t.id === scan.tool);
  const help = tool ? tool.flag_help : {};
  const plan = {
    preview: scan.preview,
    explained: argv.map((tok, i) => ({
      token: tok,
      help: help[tok] || (i === argv.length - 1 ? 'The target you are scanning.' : ''),
    })),
  };
  const html = commandBox(plan);
  setTimeout(() => {
    const c = $('#copyCmd');
    if (c) c.onclick = () => navigator.clipboard.writeText(scan.preview).then(() => toast('Command copied.', 'good'));
  }, 0);
  return html;
}

function renderFindings(scan) {
  if (!scan.findings.length) {
    return `<div class="empty"><div class="big">○</div>
      ${scan.status === 'running' ? 'Findings appear here as the scan progresses.'
        : 'Nothing was parsed from this run. Check the raw output tab - the scan may have been blocked, found nothing, or ended early.'}</div>`;
  }
  const sum = scan.summary;
  return `
    <div class="card" style="margin-bottom:14px">
      <h4>In plain English ${q('How to read this', 'This paragraph is assembled from the parsed findings below. It is a summary, not a substitute - always look at the findings and the raw output before you write anything into a report.')}</h4>
      <p style="color:var(--ink-2);margin:8px 0 0">${esc(sum.text)}</p>
    </div>
    ${scan.findings.map(findingCard).join('')}`;
}

function findingCard(f) {
  const d = f.data || {};
  const out = (d.output || d.raw || '').trim();
  return `<div class="finding">
    <div class="fhead">
      <span class="badge ${esc(f.severity)}">${esc(f.severity)}</span>
      <span class="ftitle">${esc(f.title || f.type)}</span>
      <span class="muted small">${esc(f.target)}</span>
      ${d.cves && d.cves.length ? `<span class="muted small">${d.cves.map(esc).join(', ')}</span>` : ''}
    </div>
    ${f.interpretation ? `<div class="fbody">${esc(f.interpretation)}</div>` : ''}
    ${f.suggested_next_step ? `<div class="fnext"><b>Next step:</b> ${esc(f.suggested_next_step)}</div>` : ''}
    ${out ? `<pre>${esc(out)}</pre>` : ''}
  </div>`;
}

function renderNext(scan) {
  const steps = (scan.summary && scan.summary.next_steps) || [];
  return `<div class="card">
    <h4>Where this leaves you</h4>
    <p class="small" style="color:var(--ink-2)">Scanning is one phase of a larger method:
    recon → <strong>scanning</strong> → ${G('Enumeration', 'enumeration')} →
    ${G('Exploitation', 'exploitation')} → post-exploitation → reporting. These
    suggestions all stay inside what ReconScan does; anything that would cross into exploitation
    is named as such and left to you and your instructor.</p>
    ${steps.length ? `<ol style="color:var(--ink-2);font-size:14px;line-height:1.9;padding-left:20px">
      ${steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>`
      : '<p class="muted small">No specific suggestions from this run.</p>'}
    <div class="btnrow" style="margin-top:12px">
      <button class="btn primary sm" onclick="RS.go('newscan')">Set up the next scan</button>
      <button class="btn sm" onclick="RS.go('reports')">Add this to the report</button>
    </div>
  </div>`;
}

function fillConsole(lines) {
  const c = $('#console');
  if (!c) return;
  c.innerHTML = lines.map(consoleLine).join('');
  c.scrollTop = c.scrollHeight;
}
function consoleLine(text, stream) {
  const cls = stream === 'stderr' ? 'err' : (stream === 'meta' || /^\[(ReconScan|DEMO)/.test(text)) ? 'meta' : '';
  return `<div class="${cls}">${esc(text)}</div>`;
}

function openSocket(id) {
  if (S.ws) { try { S.ws.close(); } catch {} }
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/scans/${id}`);
  S.ws = ws;
  const c = () => $('#console');
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.type === 'line') {
      const el = c();
      if (el) {
        const near = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
        el.insertAdjacentHTML('beforeend', consoleLine(m.text, m.stream));
        if (near) el.scrollTop = el.scrollHeight;
      }
      const n = $('#narration');
      if (n && m.text && !m.text.startsWith('[')) n.textContent = m.text.slice(0, 160);
    } else if (m.type === 'finished') {
      const b = $('#scanStatus');
      if (b) { b.className = `badge ${m.status}`; b.textContent = m.status; }
      const pr = document.querySelector('.progress');
      if (pr) pr.remove();
      toast(m.status === 'done'
        ? `Scan finished - ${m.findings || 0} finding(s).`
        : `Scan ${m.status}.`, m.status === 'done' ? 'good' : 'bad');
      setTimeout(async () => {
        await selectProject(S.project.id);
        if (S.view === 'scan') render();
      }, 400);
    }
  };
  ws.onerror = () => {};
}

/* ---------------- compare two scans ---------------- */
async function viewCompare(v) {
  const p = S.project;
  v.innerHTML = `<h2 class="page">Compare scans</h2>
    <p class="lede">Run the same scan twice and see what moved. This is how you notice a new
    service appearing, and the honest way to check whether something you reported was actually
    fixed. ${q('Why compare runs?', 'A single scan is a snapshot. Two scans of the same target, taken apart in time, tell you about change - which is usually what a client or an instructor actually wants to know. It is also how you catch yourself: if a finding vanishes, the interesting question is whether it was fixed or whether the scan just had a worse day.')}</p>
    <p class="muted">Loading scans…</p>`;

  const scans = await api(`/api/projects/${p.id}/comparable`);
  if (scans.length < 2) {
    v.innerHTML = `<h2 class="page">Compare scans</h2>
      <div class="notice info"><strong>You need at least two finished scans</strong>
      Run the same scan twice - ideally against the same target with the same settings - and
      then come back here to see what changed between them.</div>
      <button class="btn primary" onclick="RS.go('newscan')">Run a scan</button>`;
    return;
  }

  // Default to the two most recent runs that share a target, if such a pair exists.
  let defOld = scans[1].id, defNew = scans[0].id;
  for (let i = 0; i < scans.length; i++) {
    const match = scans.slice(i + 1).find((s) => s.target === scans[i].target
      && s.tool === scans[i].tool && s.goal === scans[i].goal);
    if (match) { defNew = scans[i].id; defOld = match.id; break; }
  }

  const opt = (s, sel) => `<option value="${s.id}" ${s.id === sel ? 'selected' : ''}>
    ${esc(s.goal)} · ${esc(s.target)} · ${ago(s.created_at)}${s.is_demo ? ' (demo)' : ''}</option>`;

  v.innerHTML = `<h2 class="page">Compare scans</h2>
    <p class="lede">Run the same scan twice and see what moved. This is how you notice a new
    service appearing, and the honest way to check whether something you reported was actually
    fixed. ${q('Why compare runs?', 'A single scan is a snapshot. Two scans of the same target, taken apart in time, tell you about change - which is usually what a client or an instructor actually wants to know. It is also how you catch yourself: if a finding vanishes, the interesting question is whether it was fixed or whether the scan just had a worse day.')}</p>
    <div class="card">
      <div class="grid two">
        <label class="field"><span class="lbl">Baseline (the earlier run)</span>
          <select id="cmpOld">${scans.map((s) => opt(s, defOld)).join('')}</select></label>
        <label class="field"><span class="lbl">Compared against (the later run)</span>
          <select id="cmpNew">${scans.map((s) => opt(s, defNew)).join('')}</select></label>
      </div>
      <button class="btn primary" id="cmpGo">Compare</button>
    </div>
    <div id="cmpOut"></div>`;
  $('#cmpGo').onclick = runCompare;
  runCompare();
}

async function runCompare() {
  const out = $('#cmpOut');
  out.innerHTML = '<p class="muted">Comparing…</p>';
  let d;
  try {
    d = await api(`/api/diff?old=${encodeURIComponent($('#cmpOld').value)}&new=${encodeURIComponent($('#cmpNew').value)}`);
  } catch (e) { out.innerHTML = `<div class="notice danger">${esc(e.message)}</div>`; return; }

  const group = (title, items, kind, blurb) => !items.length ? '' : `
    <h3 class="sec">${esc(title)} (${items.length})</h3>
    <p class="help" style="margin:-6px 0 12px">${esc(blurb)}</p>
    ${items.map((f) => `<div class="finding">
      <div class="fhead">
        <span class="badge ${esc(kind)}">${kind === 'high' ? '+ appeared' : kind === 'low' ? '− gone' : '~ changed'}</span>
        <span class="badge ${esc(f.severity)}">${esc(f.severity)}</span>
        <span class="ftitle">${esc(f.title || f.type)}</span>
        <span class="muted small">${esc(f.target)}</span>
      </div>
      ${f.changes ? `<div class="fbody">${f.changes.map((c) => `<code class="inline">${esc(c.field)}</code>: ${esc(c.before)} → <strong>${esc(c.after)}</strong>`).join('<br>')}</div>` : ''}
      <div class="fnext"><b>What this means:</b> ${esc(f.why)}</div>
    </div>`).join('')}`;

  out.innerHTML = `
    ${d.warnings.map((w) => `<div class="notice caution"><strong>Read this before you trust the comparison</strong>${esc(w)}</div>`).join('')}
    <div class="card" style="margin-top:14px">
      <h4>What changed</h4>
      <p style="color:var(--ink-2);margin:8px 0 0">${esc(d.summary)}</p>
      <p class="small muted" style="margin:10px 0 0">
        Baseline: <code class="inline">${esc(d.old.preview)}</code> (${ago(d.old.created_at)}, ${d.old.findings} findings)<br>
        Later: <code class="inline">${esc(d.new.preview)}</code> (${ago(d.new.created_at)}, ${d.new.findings} findings)</p>
    </div>
    <div class="grid three" style="margin:14px 0">
      <div class="stat"><div class="n">${d.appeared.length}</div><div class="l">appeared</div></div>
      <div class="stat"><div class="n">${d.disappeared.length}</div><div class="l">disappeared</div></div>
      <div class="stat"><div class="n">${d.changed.length}</div><div class="l">changed detail</div></div>
    </div>
    ${group('Appeared in the later scan', d.appeared, 'high',
      'Not present in the baseline. Before concluding something changed on the target, remember the earlier scan may simply have missed it - a filtered port and a closed one look identical from outside.')}
    ${group('Gone in the later scan', d.disappeared, 'low',
      'Present in the baseline and not in the later run. This is NOT proof of a fix: a dropped packet, a rate limiter or a busy host produces exactly the same result. Re-scan before you record anything here as resolved.')}
    ${group('Changed detail', d.changed, 'medium',
      'Same finding, different detail. Version changes are the ones worth reading closely - they change which known vulnerabilities apply.')}
    ${!d.appeared.length && !d.disappeared.length && !d.changed.length
      ? `<div class="notice ok"><strong>Identical</strong>Every tracked finding matched. ${d.unchanged} finding(s) were the same in both runs.</div>` : ''}`;
}

/* ---------------- schedules ---------------- */
async function viewSchedules(v) {
  const p = S.project;
  v.innerHTML = `<h2 class="page">Schedules</h2><p class="muted">Loading…</p>`;
  const list = await api(`/api/projects/${p.id}/schedules`);
  const inScope = p.targets.filter((t) => t.in_scope);

  v.innerHTML = `
    <h2 class="page">Schedules</h2>
    <p class="lede">Re-run a scan automatically on an interval, then use Compare to see what
    changed between runs. ${q('When is this useful?', 'Two common uses. First, monitoring: scan the lab every hour and diff the results, so you notice the moment a new service appears. Second, patience: some scans are slow, and a schedule means you are not sitting there starting them by hand.')}</p>

    <div class="notice caution"><strong>A schedule runs while nobody is watching</strong>
      That is the point, and it is also the risk - this is the only part of ReconScan that can
      put packets on a network when you are not at the keyboard. Scope is re-checked every time
      one fires, and a schedule whose target leaves scope disables itself rather than running.
      New schedules default to Demo mode; switch that off deliberately.</div>

    <h3 class="sec">Active schedules (${list.length})</h3>
    ${list.length ? list.map((s) => `
      <div class="card">
        <div style="display:flex;align-items:center;gap:9px;flex-wrap:wrap">
          <strong>${esc(s.name)}</strong>
          <span class="badge ${s.enabled ? 'running' : 'queued'}">${s.enabled ? 'active' : 'paused'}</span>
          ${s.is_demo ? '<span class="badge demo">DEMO</span>' : '<span class="badge real">real scans</span>'}
          <div style="flex:1"></div>
          <button class="btn sm" data-runnow="${s.id}">Run now</button>
          <button class="btn sm" data-toggle-s="${s.id}" data-val="${s.enabled ? '0' : '1'}">${s.enabled ? 'Pause' : 'Resume'}</button>
          <button class="btn sm ghost danger" data-del-s="${s.id}">Delete</button>
        </div>
        <p class="small muted" style="margin:8px 0 0">
          <code class="inline">${esc(s.tool)} · ${esc(s.goal)}</code> against
          <code class="inline">${esc(s.target)}</code> every ${everyLabel(s.every_minutes)}
          ${s.max_runs ? `· ${s.run_count}/${s.max_runs} runs` : `· ${s.run_count} run(s) so far`}
          ${s.enabled ? `· next in ${dur(s.due_in_seconds)}` : ''}
        </p>
        ${s.last_scan_id ? `<p class="small" style="margin:6px 0 0">Last run ${ago(s.last_run_at)} —
          <a href="#" data-openscan="${s.last_scan_id}">open the result</a></p>` : ''}
        ${s.last_error ? `<div class="notice caution" style="margin:10px 0 0"><strong>This schedule stopped itself</strong>${esc(s.last_error)}</div>` : ''}
      </div>`).join('')
    : `<div class="empty"><div class="big">◴</div>No schedules yet.</div>`}

    <h3 class="sec">New schedule</h3>
    <div class="card">
      ${inScope.length ? `
      <div class="grid two">
        <label class="field"><span class="lbl">What to run</span>
          <select id="sc_goal">${S.guided.map((g) => `<option value="${g.id}">${esc(g.label)} (${esc(g.tool)})</option>`).join('')}</select>
          <span class="help">The same goals as the scan builder. Options use each goal's safe defaults.</span></label>
        <label class="field"><span class="lbl">Target</span>
          <select id="sc_target">${inScope.map((t) => `<option value="${esc(t.value)}">${esc(t.value)}</option>`).join('')}</select>
          <span class="help">Only in-scope targets. Scope is checked again every time the schedule fires.</span></label>
      </div>
      <div class="grid three">
        <label class="field"><span class="lbl">How often
          ${q('Choosing an interval', 'Match it to how fast the thing you are watching actually changes. A lab that gets rebuilt daily does not need an hourly scan, and re-scanning faster than the scan takes to finish just queues work up. The minimum here is 5 minutes.')}</span>
          <select id="sc_every">
            <option value="5">Every 5 minutes</option>
            <option value="15">Every 15 minutes</option>
            <option value="60" selected>Every hour</option>
            <option value="360">Every 6 hours</option>
            <option value="1440">Every day</option>
          </select></label>
        <label class="field"><span class="lbl">Stop after</span>
          <select id="sc_max">
            <option value="">Keep going until I stop it</option>
            <option value="2">2 runs</option>
            <option value="5" selected>5 runs</option>
            <option value="24">24 runs</option>
          </select>
          <span class="help">A cap is a good habit - it means a forgotten schedule cannot run forever.</span></label>
        <label class="field"><span class="lbl">Name (optional)</span>
          <input type="text" id="sc_name" placeholder="Hourly check of the web box"></label>
      </div>
      <label class="check"><input type="checkbox" id="sc_demo" checked>
        <span><strong>Run in Demo mode</strong> ${q('Demo schedules', 'A demo schedule sends no packets - it replays sample output on the interval you set. It is the safe way to see how scheduling behaves before you let it touch a real network.')}<br>
        <span class="help" style="margin:0">Leave this on unless you specifically want real scans running unattended.</span></span></label>
      <label class="check"><input type="checkbox" id="sc_now">
        <span>Run the first one immediately<br>
        <span class="help" style="margin:0">Otherwise the first run happens one interval from now.</span></span></label>
      <button class="btn primary" id="sc_add">Create schedule</button>`
      : `<div class="notice caution"><strong>No in-scope targets</strong>Add targets before scheduling anything.</div>`}
    </div>`;

  v.querySelectorAll('[data-toggle-s]').forEach((b) => {
    b.onclick = async () => {
      await api(`/api/schedules/${b.dataset.toggleS}`, {
        method: 'PATCH', body: JSON.stringify({ enabled: b.dataset.val === '1' }) });
      render();
    };
  });
  v.querySelectorAll('[data-del-s]').forEach((b) => {
    b.onclick = async () => {
      if (!confirm('Delete this schedule? Scans it already produced are kept.')) return;
      await del(`/api/schedules/${b.dataset.delS}`); render();
    };
  });
  v.querySelectorAll('[data-runnow]').forEach((b) => {
    b.onclick = async () => {
      try {
        const r = await post(`/api/schedules/${b.dataset.runnow}/run`, {});
        await selectProject(p.id);
        go('scan', r.scan_id);
      } catch (e) { toast(e.message, 'bad'); }
    };
  });
  v.querySelectorAll('[data-openscan]').forEach((a) => {
    a.onclick = (e) => { e.preventDefault(); go('scan', a.dataset.openscan); };
  });
  const add = $('#sc_add');
  if (add) add.onclick = async () => {
    const g = S.guided.find((x) => x.id === $('#sc_goal').value);
    try {
      await post(`/api/projects/${p.id}/schedules`, {
        name: $('#sc_name').value, tool: g.tool, goal: g.goal,
        target: $('#sc_target').value, options: {},
        every_minutes: Number($('#sc_every').value),
        is_demo: $('#sc_demo').checked,
        max_runs: $('#sc_max').value ? Number($('#sc_max').value) : null,
        start_now: $('#sc_now').checked,
      });
      toast('Schedule created.', 'good');
      render();
    } catch (e) { toast(e.message, 'bad'); }
  };
}

function everyLabel(m) {
  if (m < 60) return `${m} min`;
  if (m < 1440) return m === 60 ? 'hour' : `${m / 60} hours`;
  return m === 1440 ? 'day' : `${m / 1440} days`;
}

/* ---------------- quiz ---------------- */
async function viewQuiz(v) {
  v.innerHTML = `<h2 class="page">Quiz yourself</h2><p class="muted">Loading…</p>`;
  const topic = S.quizTopic || '';
  const data = await api(`/api/quiz?project_id=${S.project ? S.project.id : ''}&topic=${encodeURIComponent(topic)}&count=8`);
  S.quiz = { questions: data.questions, i: 0, answered: null };
  const pr = data.progress;

  v.innerHTML = `
    <h2 class="page">Quiz yourself</h2>
    <p class="lede">Questions on methodology, tool choice, reading results, and the rules -
    plus questions built from your own scans. Every answer is explained, including why the
    tempting wrong ones are wrong.</p>

    <div class="card" style="margin-bottom:14px">
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <div id="qzScore"><strong>${pr.correct}/${pr.answered}</strong> <span class="muted small">answered correctly${pr.answered ? ` (${pr.percent}%)` : ''}</span></div>
        <div style="flex:1;min-width:140px">
          <div class="progress"><div id="qzBar" style="width:${pr.answered ? pr.percent : 0}%"></div></div>
        </div>
        <select id="qzTopic" style="width:auto">
          <option value="">All topics</option>
          ${pr.topics.map((t) => `<option value="${esc(t)}" ${t === topic ? 'selected' : ''}>${esc(t)}</option>`).join('')}
        </select>
        <button class="btn ghost sm" id="qzReset">Reset score</button>
      </div>
      ${Object.keys(pr.by_topic).length ? `<p class="small muted" style="margin:10px 0 0">
        ${Object.entries(pr.by_topic).map(([t, s]) => `${esc(t)}: ${s.right}/${s.asked}`).join(' · ')}</p>` : ''}
    </div>

    <div id="qzCard"></div>`;

  $('#qzTopic').onchange = (e) => { S.quizTopic = e.target.value; render(); };
  $('#qzReset').onclick = async () => { await post('/api/quiz/reset', {}); render(); };
  paintQuestion();
}

/** Refresh the running score in place, so it reflects the answer you just gave. */
async function updateScore() {
  try {
    const pr = (await api('/api/quiz?count=1')).progress;
    const el = $('#qzScore'), bar = $('#qzBar');
    if (el) el.innerHTML = `<strong>${pr.correct}/${pr.answered}</strong>
      <span class="muted small">answered correctly${pr.answered ? ` (${pr.percent}%)` : ''}</span>`;
    if (bar) bar.style.width = `${pr.answered ? pr.percent : 0}%`;
  } catch { /* the score is decoration; never break the quiz over it */ }
}

function paintQuestion() {
  const box = $('#qzCard');
  const st = S.quiz;
  if (!box) return;
  if (!st.questions.length) {
    box.innerHTML = `<div class="empty"><div class="big">◈</div>
      No questions for that topic yet. Questions under "Your scans" appear once you have run
      scans that found something.</div>`;
    return;
  }
  if (st.i >= st.questions.length) {
    box.innerHTML = `<div class="card"><h4>Round complete</h4>
      <p class="small" style="color:var(--ink-2)">That is all ${st.questions.length} questions in
      this round. Your running score is at the top of the page.</p>
      <button class="btn primary" id="qzAgain">Another round</button></div>`;
    $('#qzAgain').onclick = () => render();
    return;
  }

  const q2 = st.questions[st.i];
  const a = st.answered;
  box.innerHTML = `
    <div class="card">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
        <span class="badge info">${esc(q2.topic)}</span>
        ${q2.generated ? '<span class="badge low">from your scans</span>' : ''}
        <div style="flex:1"></div>
        <span class="muted small">Question ${st.i + 1} of ${st.questions.length}</span>
      </div>
      <p style="font-size:16px;font-weight:600;margin:0 0 14px">${esc(q2.q)}</p>
      ${q2.options.map((o, i) => {
        let cls = '', mark = '';
        if (a) {
          if (i === a.answer) { cls = 'ok'; mark = '✓ '; }
          else if (i === a.chosen) { cls = 'danger'; mark = '✗ '; }
        }
        return `<div class="notice ${cls || 'info'}" style="cursor:${a ? 'default' : 'pointer'};
            ${a ? '' : 'background:var(--surface-2);border-color:var(--line);color:var(--ink)'}"
            data-choice="${i}">
          <strong style="display:inline">${mark}${esc(o)}</strong>
          ${a ? `<div style="margin-top:6px;font-weight:400">${esc(a.why[i])}</div>` : ''}
        </div>`;
      }).join('')}
      ${a ? `<div class="btnrow" style="margin-top:12px">
        <button class="btn primary" id="qzNext">${st.i + 1 < st.questions.length ? 'Next question ›' : 'Finish'}</button>
        <span class="small ${a.correct ? '' : 'muted'}" style="color:${a.correct ? 'var(--ok)' : 'var(--danger)'}">
          ${a.correct ? 'Correct.' : 'Not quite - the explanation above is the part worth reading.'}</span>
      </div>` : '<p class="help">Pick the answer you think is right.</p>'}
    </div>`;

  if (!a) {
    box.querySelectorAll('[data-choice]').forEach((el) => {
      el.onclick = async () => {
        try {
          S.quiz.answered = await post('/api/quiz/answer', {
            question_id: q2.id, choice: Number(el.dataset.choice),
            project_id: S.project ? S.project.id : '',
          });
          paintQuestion();
          updateScore();
        } catch (e) { toast(e.message, 'bad'); }
      };
    });
  } else {
    $('#qzNext').onclick = () => { S.quiz.i++; S.quiz.answered = null; paintQuestion(); };
  }
}

/* ---------------- reports ---------------- */
function viewReports(v) {
  const p = S.project;
  const demoScans = p.scans.filter((s) => s.is_demo).length;
  v.innerHTML = `
    <h2 class="page">Reports</h2>
    <p class="lede">Turn this project into something you can hand in. One report model is
    rendered to every format, so they always agree with each other.</p>

    ${demoScans ? `<div class="notice demo"><strong>${demoScans} of this project's
      ${p.scans.length} scans ran in Demo mode</strong>
      The report will say so, in every format. Demo output is realistic sample data - presenting
      it as results from a real system would be fabricating evidence, so ReconScan labels it
      for you.</div>` : ''}

    <div class="card">
      <h4>What goes in</h4>
      <ol class="small" style="color:var(--ink-2);line-height:1.9;padding-left:20px;margin:8px 0 0">
        <li><strong>Authorization</strong> - the note you wrote when creating the project.</li>
        <li><strong>Scope</strong> - every declared target and whether it was in scope.</li>
        <li><strong>Summary</strong> - findings by severity, in plain English, with next steps.</li>
        <li><strong>Methodology</strong> - the exact command behind every scan.</li>
        <li><strong>Findings by host</strong> - ports, services, technology and issues, each
          with what it means and what to do about it.</li>
        <li><strong>Raw evidence</strong> - optional, the unedited tool output.</li>
      </ol>
    </div>

    <div class="card">
      <h4>Options</h4>
      <label class="check"><input type="checkbox" id="rawInc">
        <span><strong>Include raw tool output</strong> ${q('Raw evidence', 'Appends the unedited output of every scan. Markers examining your work can see exactly what the tool said, which makes your conclusions checkable. It also makes the document much longer - check your rubric.')}<br>
        <span class="help" style="margin:0">Longer, but your conclusions become checkable. Many rubrics ask for it.</span></span></label>
      <div class="btnrow" style="margin-top:12px">
        <button class="btn primary" data-fmt="pdf">Download PDF</button>
        <button class="btn" data-fmt="md">Markdown</button>
        <button class="btn" data-fmt="html">HTML</button>
        <button class="btn" data-fmt="json">JSON (raw data)</button>
        <button class="btn ghost" id="previewBtn">Preview in a new tab</button>
      </div>
      <p class="help">JSON is the full data model - useful if you want to chart something or
      pull it into another tool.</p>
    </div>

    <div class="card">
      <h4>Audit log ${q('Audit log', 'Every project action and every command ReconScan ran, with a timestamp. Good professional practice - if anyone ever asks what you did and when, this is the answer - and useful evidence for a methodology section.')}</h4>
      <p class="small muted" style="margin:4px 0 10px">Every action taken in this project.</p>
      <div id="auditBox" class="small muted">Loading…</div>
    </div>`;

  v.querySelectorAll('[data-fmt]').forEach((b) => {
    b.onclick = () => {
      const raw = $('#rawInc').checked ? '&raw=true' : '';
      window.location = `/api/projects/${p.id}/report?format=${b.dataset.fmt}${raw}`;
    };
  });
  $('#previewBtn').onclick = () => {
    const raw = $('#rawInc').checked ? '?raw=true' : '';
    window.open(`/api/projects/${p.id}/report/preview${raw}`, '_blank');
  };
  api(`/api/projects/${p.id}/audit`).then((rows) => {
    const box = $('#auditBox');
    if (!box) return;
    box.innerHTML = rows.length ? `<table class="data"><thead><tr><th>When</th><th>Action</th><th>Detail</th></tr></thead><tbody>
      ${rows.slice(0, 60).map((r) => `<tr><td style="white-space:nowrap">${esc(new Date(r.timestamp).toLocaleString())}</td>
        <td>${esc(r.action)}</td><td><code class="inline">${esc((r.command || '').slice(0, 90))}</code></td></tr>`).join('')}
      </tbody></table>` : 'Nothing logged yet.';
  });
}

/* Where a tool comes from: carried with the app, on the host, or absent. */
function toolBadge(id) {
  const src = (S.sources || {})[id] || {};
  if (src.bundled) return `<span class="badge low" title="${esc(src.found)}">bundled with ReconScan</span>`;
  if (src.available) return `<span class="badge low" title="${esc(src.found)}">installed on this machine</span>`;
  return '<span class="badge medium">not available here</span>';
}

/* ---------------- learn ---------------- */
function viewLearn(v) {
  v.innerHTML = `
    <h2 class="page">Learn &amp; glossary</h2>
    <p class="lede">Every tool ReconScan can run, and plain-English definitions for the jargon.</p>

    <h3 class="sec">Tool catalog
      ${q('Where these come from', 'ReconScan looks for each tool in its own bundled folder first, then on the host PATH. Bundled copies travel with the app - useful on a USB stick - but only tools that are a single self-contained binary can be carried that way. nmap and masscan need a packet-capture driver, and nikto and whatweb need Perl and Ruby, so those must be installed on the machine doing the scanning.')}</h3>
    ${S.sources ? `<p class="help" style="margin:-6px 0 12px">Bundled folder for this machine
      (<code class="inline">${esc(S.platform || '')}</code>):
      <code class="inline">${esc(S.bundledDir || '')}</code>
      &mdash; run <code class="inline">python fetch_tools.py</code> to fill it.</p>` : ''}
    <div class="grid two">
      ${S.tools.map((t) => `<div class="card">
        <div style="display:flex;align-items:center;gap:8px">
          <h4 style="margin:0;font-family:var(--mono)">${esc(t.name)}</h4>
          ${toolBadge(t.id)}
        </div>
        <p class="small muted" style="margin:4px 0 10px">${esc(t.category)}</p>
        <p class="small" style="color:var(--ink-2)">${esc(t.card.what)}</p>
        <dl class="small" style="color:var(--ink-2);margin:10px 0 0">
          <dt style="font-weight:600">Why you would use it</dt><dd style="margin:2px 0 8px">${esc(t.card.why)}</dd>
          <dt style="font-weight:600">When</dt><dd style="margin:2px 0 8px">${esc(t.card.when)}</dd>
          <dt style="font-weight:600">How noisy</dt><dd style="margin:2px 0 8px">${esc(t.card.noise)}</dd>
          <dt style="font-weight:600">Safe default</dt><dd style="margin:2px 0 0">${esc(t.card.safe_default)}</dd>
        </dl>
        <div class="btnrow" style="margin-top:12px">
          <button class="btn sm" data-goals="${t.id}">What it can answer (${t.goals.length})</button>
          ${t.card.docs ? `<a class="btn sm ghost" href="${esc(t.card.docs)}" target="_blank" rel="noopener">Official docs</a>` : ''}
        </div>
      </div>`).join('')}
    </div>

    <h3 class="sec">Glossary</h3>
    <input type="text" id="gsearch" placeholder="Search: port, CIDR, SYN scan, CVE, scope…" style="max-width:420px;margin-bottom:14px">
    <div id="glist"></div>`;

  v.querySelectorAll('[data-goals]').forEach((b) => {
    b.onclick = () => {
      const t = S.tools.find((x) => x.id === b.dataset.goals);
      drawer(`${t.name} - what it can answer`, t.goals.map((g) => `
        <dt>${esc(g.label)}</dt>
        <dd>${esc(g.detail)}<br><span class="muted">Typically ${esc(g.typical_duration)}${g.root_recommended ? ' - wants root' : ''}.</span></dd>`).join('')
        + `<p style="margin-top:16px"><strong>Flags this tool uses</strong></p>`
        + Object.entries(t.flag_help).map(([k, vv]) =>
          `<dt><code class="inline">${esc(k)}</code></dt><dd>${esc(vv)}</dd>`).join(''));
    };
  });

  const paint = (q2) => {
    const list = S.glossary.filter((t) => !q2
      || (t.term + t.short + t.long + t.tags.join(' ')).toLowerCase().includes(q2.toLowerCase()));
    $('#glist').innerHTML = list.length ? list.map((t) => `<div class="card" style="margin-bottom:9px">
        <h4>${esc(t.term)}</h4>
        <p class="small" style="margin:4px 0 6px;color:var(--ink)"><strong>${esc(t.short)}</strong></p>
        <p class="small" style="margin:0;color:var(--ink-2)">${esc(t.long)}</p>
      </div>`).join('') : '<p class="muted">No matches.</p>';
  };
  paint('');
  $('#gsearch').oninput = (e) => paint(e.target.value);
}

/* ---------------- go ---------------- */
window.RS = { go, drawer, showGlossary };
boot();
