// Orchestrator ticket helper: whole-file rewrite of ticket frontmatter.
// Tickets live in tasks/<status>/TASK-*.md (board convention); scanned recursively.
// usage: node .orchestrate/tk.js list | ready <ID|all> | set <ID> key=value ... [--activity '<json>']
const fs = require('fs'), path = require('path');
const dir = path.join(__dirname, '..', 'tasks');
const now = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z');

function files() {
  const out = [];
  const walk = d => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (/^TASK-.*\.md$/.test(e.name)) out.push(p);
    }
  };
  walk(dir);
  return out;
}

function parse(p) {
  const t = fs.readFileSync(p, 'utf8').replace(/\r\n/g, '\n');
  const m = t.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (!m) throw new Error('parse ' + p);
  const fm = [];
  m[1].split('\n').forEach(l => {
    const i = l.indexOf(':');
    if (i > 0) fm.push([l.slice(0, i).trim(), l.slice(i + 1).trim()]);
  });
  return { p, fm, body: m[2] };
}
const get = (t, k) => { const e = t.fm.find(x => x[0] === k); return e ? e[1] : undefined; };
const setk = (t, k, v) => {
  if (v === '' || v === null) { t.fm = t.fm.filter(x => x[0] !== k); return; }
  const e = t.fm.find(x => x[0] === k);
  if (e) e[1] = v; else t.fm.push([k, v]);
};

function write(t) {
  const s = '---\n' + t.fm.map(([k, v]) => `${k}: ${v}`).join('\n') + '\n---\n' + t.body;
  const dd = path.join(dir, get(t, 'status'));
  fs.mkdirSync(dd, { recursive: true });
  const np = path.join(dd, path.basename(t.p));
  const tmp = np + '.tmp';
  fs.writeFileSync(tmp, s);
  fs.renameSync(tmp, np);
  if (path.resolve(np) !== path.resolve(t.p) && fs.existsSync(t.p)) fs.unlinkSync(t.p);
  t.p = np;
}

function byId(id) {
  for (const p of files()) { const t = parse(p); if (get(t, 'id') === id) return t; }
  throw new Error('no ' + id);
}

function ready(body) {
  const gaps = [];
  const L = body.split('\n');
  const sec = n => {
    const a = L.findIndex(l => l.trim() === '## ' + n);
    if (a < 0) return '';
    let b = a + 1;
    while (b < L.length && !L[b].startsWith('## ')) b++;
    return L.slice(a + 1, b).join('\n');
  };
  const ac = sec('Acceptance Criteria').split('\n').filter(l => /^\s*- \[[ x]\]/.test(l));
  if (!ac.length) gaps.push('no real acceptance criterion');
  const vague = /\b(gracefully|properly|appropriately|correctly|robust|as needed|user-friendly|intuitive|reasonable|adequate)\b/i;
  ac.forEach(l => { if (vague.test(l)) gaps.push('vague criterion: ' + l.trim().slice(0, 100)); });
  const g = sec('Cucumber Tests');
  const sc = (g.match(/^\s*Scenario( Outline)?:/gm) || []).length;
  if (sc < ac.length) gaps.push(`fewer scenarios (${sc}) than criteria (${ac.length})`);
  if (!/Scenario[^\n]*(fail|reject|invalid|error|missing|denied|unauthori|expired|wrong|bad|edge|empty|not |no |timeout|offline|replay|tamper|unknown|exceed|refus|without|unmatched|non-|duplicate|nothing|escape|stale|corrupt|conflict)/i.test(g))
    gaps.push('no failure/edge scenario');
  if (!sec('Relevant Files').trim()) gaps.push('missing/empty Relevant Files');
  return { ready: !gaps.length, gaps };
}

const [cmd, ...a] = process.argv.slice(2);
if (cmd === 'list') {
  for (const p of files()) {
    const t = parse(p);
    console.log([get(t, 'id'), get(t, 'status'), get(t, 'agent') || '-', 'deps:' + (get(t, 'depends-on') || ''), get(t, 'title')].join(' | '));
  }
} else if (cmd === 'ready') {
  for (const p of files()) {
    const t = parse(p);
    if (a[0] !== 'all' && get(t, 'id') !== a[0]) continue;
    const r = ready(t.body);
    console.log(get(t, 'id'), r.ready ? 'READY' : 'NOT READY', r.gaps.join('; '));
  }
} else if (cmd === 'body') {
  // body <ID> <file> [key=value ...]: replace body up to "## Additional Context" (preserved verbatim)
  const t = byId(a[0]);
  let nb = fs.readFileSync(a[1], 'utf8').replace(/\r\n/g, '\n').trim();
  const dm = nb.match(/^depends-on:\s*(.+)\n/);
  if (dm) { setk(t, 'depends-on', dm[1].trim()); nb = nb.slice(dm[0].length).trim(); }
  const idx = t.body.indexOf('## Additional Context');
  const ac = idx >= 0 ? t.body.slice(idx) : '## Additional Context\n\n';
  t.body = '\n' + nb + '\n\n' + ac;
  for (let i = 2; i < a.length; i++) {
    if (a[i] === '--activity') {
      const cur = get(t, 'activities'); const arr = cur ? JSON.parse(cur) : [];
      arr.push(JSON.parse(a[++i])); setk(t, 'activities', JSON.stringify(arr)); continue;
    }
    const j = a[i].indexOf('='); if (j < 1) throw new Error('bad arg ' + a[i]);
    setk(t, a[i].slice(0, j), a[i].slice(j + 1));
  }
  setk(t, 'updated', now());
  write(t);
  console.log(a[0], 'body replaced ->', get(t, 'status'));
} else if (cmd === 'set') {
  const t = byId(a[0]);
  let act = null;
  for (let i = 1; i < a.length; i++) {
    if (a[i] === '--activity') { act = JSON.parse(a[++i]); continue; }
    const j = a[i].indexOf('=');
    setk(t, a[i].slice(0, j), a[i].slice(j + 1));
  }
  if (act) {
    const cur = get(t, 'activities');
    const arr = cur ? JSON.parse(cur) : [];
    arr.push(act);
    setk(t, 'activities', JSON.stringify(arr));
  }
  setk(t, 'updated', now());
  write(t);
  console.log(a[0], '->', get(t, 'status'));
}
