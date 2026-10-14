/** check_preview_boundary_edges.mjs — 用 CMake 的真实策略逐条校验生产依赖边，包含绕过 LinkPreviewTargets 的裸 target_link_libraries。 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

const root = process.cwd();
const BOUNDARY = path.join(root, "Preview", "CMake", "PreviewBoundary.cmake");
const PROBE = path.join(root, "scripts", "CMake", "AssertPreviewEdge.cmake");
const GRAPH_PROBE = path.join(root, "scripts", "CMake", "AssertPreviewGraphEdge.cmake");
const CM = ["Preview/CMakeLists.txt", "Preview/Application/CMakeLists.txt"].map((p) => path.join(root, p));
const KEYWORDS = /^(PUBLIC|PRIVATE|INTERFACE|SYSTEM)$/;

/** 找出 PRISM_PREVIEW_BOUNDARY_FAULT 注入块的行区间；块内的负向边按设计必须失败。 */
function faultRanges(text) {
  const lines = text.split("\n");
  const ranges = [];
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].includes("PRISM_PREVIEW_BOUNDARY_FAULT")) continue;
    let depth = 0, j = i;
    for (; j < lines.length; j++) {
      const l = lines[j].trim();
      if (/^(if|foreach)\s*\(/.test(l)) depth++;
      if (/^endif\s*\(/.test(l) || /^endforeach\s*\(/.test(l)) depth--;
      if (depth <= 0 && j > i) break;
    }
    ranges.push([i + 1, j + 1]);
    i = j;
  }
  return ranges;
}

function edgesOf(file) {
  const raw = fs.readFileSync(file, "utf8");
  const text = raw.replace(/#[^\n]*/g, "");
  const ranges = faultRanges(raw);
  const out = [];
  const re = /(LinkPreviewTargets|target_link_libraries)\s*\(([^)]*)\)/g;
  let m;
  while ((m = re.exec(text))) {
    const line = text.slice(0, m.index).split("\n").length;
    const toks = m[2].split(/[\s;]+/).filter(Boolean).map((s) => s.replace(/"/g, "")).filter((s) => !KEYWORDS.test(s));
    const consumer = toks[0];
    const deps = toks.slice(1).filter((d) => /^Preview[A-Za-z0-9]*$/.test(d));
    if (!consumer || !deps.length || /^\$\{/.test(consumer)) continue;
    out.push({
      consumer,
      deps,
      command: m[1],
      site: `${path.relative(root, file).split(path.sep).join("/")}:${line}`,
      faultInjection: ranges.some(([a, b]) => line >= a && line <= b),
    });
  }
  return out;
}

function runProbe(probe, consumer, dep) {
  try {
    execFileSync("cmake", ["-DBOUNDARY=" + BOUNDARY, "-DC=" + consumer, "-DD=" + dep, "-P", probe], { stdio: "pipe" });
    return null;
  } catch (e) {
    const msg = (e.stdout?.toString() || "") + (e.stderr?.toString() || "");
    return msg.split(/\r?\n/).find((l) => l.includes("outside") || l.includes("Forbidden") || l.includes("FATAL") || l.includes("must not")) || "policy FATAL";
  }
}

const all = CM.flatMap(edgesOf);
const results = {
  viaLinkPreviewTargets: 0,
  viaRawTargetLinkLibraries: 0,
  bothAllow: 0,
  table1RejectsTable2Allows: [],
  table2RejectsTable1Allows: [],
  bothReject: [],
  unexpectedViolations: [],
  expectedFaultInjectionRejections: [],
};
const seen = new Set();
for (const e of all) {
  for (const dep of e.deps) {
    const k = `${e.consumer}->${dep}`;
    if (seen.has(k)) continue;
    seen.add(k);
    e.command === "LinkPreviewTargets" ? results.viaLinkPreviewTargets++ : results.viaRawTargetLinkLibraries++;
    const t1 = runProbe(PROBE, e.consumer, dep);
    const t2 = runProbe(GRAPH_PROBE, e.consumer, dep);
    const row = `${k} @ ${e.site} [${e.command}]` + (t1 || t2 ? ` — ${t1 ? "表1拒绝" : ""}${t1 && t2 ? " / " : ""}${t2 ? "表2拒绝" : ""}` : "");
    if (!t1 && !t2) { results.bothAllow++; continue; }
    if (e.faultInjection) { results.expectedFaultInjectionRejections.push(row); continue; }
    if (t1 && t2) { results.bothReject.push(row); results.unexpectedViolations.push(row); }
    else if (t1) results.table1RejectsTable2Allows.push(row);
    else results.table2RejectsTable1Allows.push(row);
  }
}

const hash = (p) => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const summary = {
  capturedAt: new Date().toISOString(),
  edgesChecked: seen.size,
  sourceManifestSha256: crypto.createHash("sha256").update([BOUNDARY, ...CM].map((p) => rel(p) + "=" + hash(p)).join("\n")).digest("hex"),
  enforcementCoverage: { viaLinkPreviewTargets: results.viaLinkPreviewTargets, viaRawTargetLinkLibraries: results.viaRawTargetLinkLibraries },
  unexpectedViolations: results.unexpectedViolations.length,
  expectedFaultInjectionRejections: results.expectedFaultInjectionRejections.length,
  policyDifferential: {
    bothAllow: results.bothAllow,
    bothReject: results.bothReject.length,
    table1RejectsTable2Allows: results.table1RejectsTable2Allows.length,
    table2RejectsTable1Allows: results.table2RejectsTable1Allows.length,
  },
};
function rel(p) { return path.relative(root, p).split(path.sep).join("/"); }
console.log(JSON.stringify({ summary, ...results }, null, 2));
process.exit(summary.unexpectedViolations === 0 ? 0 : 1);
