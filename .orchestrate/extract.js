// Extract "===== TASK-xxx" ticket bodies from a subagent JSONL transcript.
// usage: node .orchestrate/extract.js <transcript.jsonl> <outDir>
// Writes <outDir>/TASK-xxx.md for the LAST occurrence of each ticket body.
const fs = require('fs'), path = require('path');
const [src, outDir] = process.argv.slice(2);
fs.mkdirSync(outDir, { recursive: true });
const texts = [];
for (const line of fs.readFileSync(src, 'utf8').split('\n')) {
  if (!line.trim()) continue;
  let o; try { o = JSON.parse(line); } catch { continue; }
  const msg = o.message || o;
  if (msg.role !== 'assistant') continue;
  const c = msg.content;
  if (typeof c === 'string') texts.push(c);
  else if (Array.isArray(c)) for (const b of c) if (b.type === 'text') texts.push(b.text);
  // SubagentHandback tool input may hold the final report
  if (Array.isArray(c)) for (const b of c) if (b.type === 'tool_use' && b.input) {
    for (const v of Object.values(b.input)) if (typeof v === 'string' && v.includes('===== TASK-')) texts.push(v);
  }
}
const found = {};
for (const t of texts) {
  const parts = t.split(/^===== (TASK-\d{3})\s*$/m);
  for (let i = 1; i < parts.length; i += 2) {
    let body = parts[i + 1];
    // stop at a trailing summary section that isn't part of the ticket
    body = body.split(/\n(?:Summary of decisions|Clarifying question|Tickets revised|Notes on the|Earlier deliveries|## Summary|## Tickets revised|## How each)/)[0];
    found[parts[i]] = body.trim() + '\n';
  }
}
for (const [id, body] of Object.entries(found)) {
  fs.writeFileSync(path.join(outDir, id + '.md'), body);
  console.log(id, body.length, 'chars');
}
