/** prism_source_snapshot.mjs — 源码快照与漂移核对。改动前 run 一次，改动后 --diff 对该清单比出实际变了哪些文件。 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const root = process.cwd();
const SNAP_DIR = ".superpowers/sdd/2026-10-09-preview-quality-modification-plan/snapshots";
const rel = (p) => path.relative(root, p).split(path.sep).join("/");

const SCOPES = [
  ["Include/Prism", /\.(hpp|h|cpp|cxx|cc)$/i],
  ["Src/Prism", /\.(hpp|h|cpp|cxx|cc)$/i],
  ["Test/Prism", /\.(hpp|cpp)$/i],
  ["scripts", /^check_prism_.*\.(mjs|ps1)$|^prism_source_snapshot\.mjs$/i],
];
const EXTRA = ["Src/Prism/CMakeLists.txt", "Src/Prism/CMake/PrismBoundary.cmake",
  "Src/Prism/CMake/PrismTargets.cmake", "Src/Prism/CMake/PrismLinks.cmake", "CMakeLists.txt",
  "Test/CMakeLists.txt", "Test/Prism/CMakeLists.txt",
  "Include/Prism/Application/Configuration/PrismConfiguration.json"];

function walk(dir, re, acc) {
  if (!fs.existsSync(dir)) return acc;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, re, acc);
    else if (re.test(e.name)) acc.push(p);
  }
  return acc;
}

function collect() {
  const files = new Set();
  for (const [scope, re] of SCOPES) for (const f of walk(path.join(root, scope), re, [])) files.add(f);
  for (const e of EXTRA) { const p = path.join(root, e); if (fs.existsSync(p)) files.add(p); }
  return [...files].sort((a, b) => rel(a).localeCompare(rel(b)));
}

const manifest = () => {
  const entries = {};
  for (const f of collect()) {
    const buf = fs.readFileSync(f);
    entries[rel(f)] = { sha256: crypto.createHash("sha256").update(buf).digest("hex"), bytes: buf.length, lines: buf.toString("utf8").split("\n").length };
  }
  const aggregate = crypto.createHash("sha256").update(Object.entries(entries).map(([k, v]) => k + "=" + v.sha256).sort().join("\n")).digest("hex");
  return { capturedAt: new Date().toISOString(), root, aggregate, fileCount: Object.keys(entries).length, entries };
};

const args = process.argv.slice(2);
const diffIdx = args.indexOf("--diff");

if (diffIdx === -1) {
  const m = manifest();
  fs.mkdirSync(path.join(root, SNAP_DIR), { recursive: true });
  const stamp = m.capturedAt.replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  const out = path.join(root, SNAP_DIR, `snapshot-${stamp}.json`);
  fs.writeFileSync(out, JSON.stringify(m, null, 2));
  console.log(JSON.stringify({ capturedAt: m.capturedAt, fileCount: m.fileCount, aggregate: m.aggregate, written: rel(out) }, null, 1));
  process.exit(0);
}

const prevPath = args[diffIdx + 1];
const prev = JSON.parse(fs.readFileSync(path.isAbsolute(prevPath) ? prevPath : path.join(root, prevPath), "utf8"));
const cur = manifest();
const added = [], removed = [], changed = [];
for (const [p, v] of Object.entries(cur.entries)) {
  const o = prev.entries[p];
  if (!o) added.push(p);
  else if (o.sha256 !== v.sha256) changed.push(`${p}  ${o.sha256.slice(0, 12)} → ${v.sha256.slice(0, 12)}`);
}
for (const p of Object.keys(prev.entries)) if (!cur.entries[p]) removed.push(p);
console.log(JSON.stringify({
  baselineCapturedAt: prev.capturedAt, currentCapturedAt: cur.capturedAt,
  baselineAggregate: prev.aggregate, currentAggregate: cur.aggregate,
  counts: { changed: changed.length, added: added.length, removed: removed.length, files: cur.fileCount },
  changed, added, removed,
}, null, 1));
process.exit(changed.length + added.length + removed.length === 0 ? 0 : 1);
