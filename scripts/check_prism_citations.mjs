/** check_prism_citations.mjs — 只读门禁：校验文档里的 `文件:行号` / `文件:行-行` 引用，被引文件必须存在且真的有那一行。
 *  动机：本会话两份补丁设计（E-27 §1.1、E-10 §3）都因为「引用了当态源码里不成立的形状」而作废；
 *  路径存在性由 check_prism_doc_paths.mjs 管，但 **行号** 从来没人核。注释类改动会让行号整体漂移。
 *  用法：node scripts/check_prism_citations.mjs [--include-docs] [--full]
 *  豁免：与 docpaths 同语义 —— 行内 `<!-- pathcheck:ignore=理由 -->`，文件级 `<!-- pathcheck:historical=理由 -->`（前 20 行内）。
 */
import fs from "node:fs";
import path from "node:path";

const dirs = [
  ".superpowers/sdd/2026-10-09-preview-quality-modification-plan",
  "logs",
  "Include/Prism",
  "Src/Prism",
];
if (process.argv.includes("--include-docs")) dirs.push("docs");
const full = process.argv.includes("--full");

// 存在性必须逐段大小写精确：Windows 的 existsSync 不敏感，Linux/git 敏感（与 docpaths 同一判据）。
function existsExact(rel) {
  const segs = rel.split("/");
  let cur = ".";
  for (const s of segs) {
    let entries = null;
    try { entries = fs.readdirSync(cur); } catch { return false; }
    if (!entries.includes(s)) return false;
    cur = path.join(cur, s);
  }
  try { return fs.statSync(cur).isFile(); } catch { return false; }
}
const lineCountCache = new Map();
function lineCount(rel) {
  if (lineCountCache.has(rel)) return lineCountCache.get(rel);
  const text = fs.readFileSync(rel, "utf8");
  const parts = text.split("\n");
  if (parts.length > 0 && parts[parts.length - 1] === "") parts.pop(); // 「不超过 N 行」按内容行数算
  lineCountCache.set(rel, parts.length);
  return parts.length;
}

// 只认带扩展名的仓库相对路径后紧跟 :数字；前面必须是路径边界（避免 URL、`a/b:12` 之类）。
const citeRe = /(?:Prism|tests|scripts|docs|src|include)\/[A-Za-z0-9_./-]*\.(?:hpp|cpp|h|md|txt|cmake|ps1|sh|mjs|json|go):[0-9]+(?:-[0-9]+)?/g;
const buckets = { ok: 0, fileMissing: [], lineBeyond: [], rangeBeyond: [], reversedRange: [], retired: [], crossTree: [], crossTreeLines: [], historical: [] };

// 与 docpaths 同一套退役/跨树判定：tracked 但在磁盘上已删 = 有意退役；主树有 = 合法的跨树陈述。
import { execFileSync } from "node:child_process";
let deletedSet = new Set();
try {
  deletedSet = new Set(execFileSync("git", ["ls-files", "--deleted"], { encoding: "utf8" }).split("\n").map((s) => s.trim().split(path.sep).join("/")).filter(Boolean));
} catch { /* 非 git 环境下退役分类退化，不影响行号判定 */ }
const isRetired = (p) => deletedSet.has(p);
const MAIN_ROOT = process.env.PRISM_MAIN_TREE || "I:/code/Prism";
// 主树侧同样必须逐段大小写校核：`fs.existsSync` 在 Windows 上大小写不敏感，会把
// 「主树只有 Protocols/」与「只有 protocols/」判成同一件事，从而把真实的错拼豁免成跨树陈述。
// 本仓库正处于双树对账期（E-39/E-44），这个豁免若不准就直接吞掉缺陷。
const resolveMainExact = (rel) => {
  let cur = MAIN_ROOT;
  for (const seg of rel.split("/")) {
    let entries = [];
    try { entries = fs.readdirSync(cur); } catch { return null; }
    const hit = entries.find((e) => e === seg);
    if (!hit) return null;
    cur = path.join(cur, hit);
  }
  try { return fs.statSync(cur).isFile() ? cur : null; } catch { return null; }
};
const inMainTree = (p) => resolveMainExact(p) !== null;
// 同一相对路径在主树可能有**不同版本**（双树分歧）。执行树里越界的行号，若主树该文件真有这一行，
// 那就是合法的「跨树行号陈述」（本项目大量结论是「主树有 X 行、隔离树只有 Y 行」这种比较），不能当笔误。
function mainTreeLineCount(rel) {
  const abs = resolveMainExact(rel);
  if (!abs) return -1;
  const parts = fs.readFileSync(abs, "utf8").split("\n");
  if (parts.length > 0 && parts[parts.length - 1] === "") parts.pop();
  return parts.length;
}


let citations = 0, docs = 0;

for (const dir of dirs) {
  if (!fs.existsSync(dir)) continue;
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    for (const e of fs.readdirSync(cur, { withFileTypes: true })) {
      const norm = path.join(cur, e.name).split(path.sep).join("/");
      if (e.isDirectory()) {
        if (!/(^|\/)(snapshots|Baseline)(\/|$)/.test(norm)) stack.push(path.join(cur, e.name));
        continue;
      }
      if (!/\.md$/.test(e.name)) continue;
      docs++;
      const lines = fs.readFileSync(norm, "utf8").split("\n");
      const head20 = lines.slice(0, 20).join("\n");
      const histMark = /pathcheck:historical/.test(head20);
      if (histMark && !/pathcheck:historical\s*=\s*[^\s>]/.test(head20)) console.log(`  ! ${norm} 有 pathcheck:historical 标记但缺理由`);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/pathcheck:ignore(?!\s*=\s*\S)/.test(line)) console.log(`  ! ${norm}:${i + 1} 有豁免标记但缺理由`);
        if (/pathcheck:ignore/.test(line)) continue;
        for (const raw of line.match(citeRe) || []) {
          const at = line.indexOf(raw);
          if (at > 0 && /[\w./-]/.test(line[at - 1])) continue;
          const sep = raw.lastIndexOf(":");
          const file = raw.slice(0, sep);
          const span = raw.slice(sep + 1);
          citations++;
          const where = `${norm}:${i + 1}`;
          if (!existsExact(file)) {
            if (histMark) buckets.historical.push(`${where} 引用 ${raw} —— 历史文档内的失效坐标`);
            else if (isRetired(file)) buckets.retired.push(file);
            else if (inMainTree(file)) buckets.crossTree.push(file);
            else buckets.fileMissing.push(`${where} 引用 ${raw} —— 文件不存在或大小写不符`);
            continue;
          }
          const total = lineCount(file);
          const dash = span.indexOf("-");
          const a = dash < 0 ? Number(span) : Number(span.slice(0, dash));
          const b = dash < 0 ? a : Number(span.slice(dash + 1));
          if (!(a >= 1 && a <= total)) {
            const mt = mainTreeLineCount(file);
            if (!histMark && mt >= a) buckets.crossTreeLines.push(`${where} 引用 ${raw} —— 执行树 ${total} 行，主树 ${mt} 行`);
            else (histMark ? buckets.historical : buckets.lineBeyond).push(`${where} 引用 ${raw} —— 目标文件只有 ${total} 行`);
          } else if (b < a) {
            buckets.reversedRange.push(`${where} 引用 ${raw} —— 区间反向（起 ${a} > 止 ${b}），目标共 ${total} 行`);
          } else if (b > total) {
            const mt = mainTreeLineCount(file);
            if (!histMark && mt >= b) buckets.crossTreeLines.push(`${where} 引用 ${raw} —— 执行树 ${total} 行，主树 ${mt} 行`);
            else (histMark ? buckets.historical : buckets.rangeBeyond).push(`${where} 引用 ${raw} —— 区间末行超界，目标共 ${total} 行`);
          } else buckets.ok++;


        }
      }
    }
  }
}

const summary = {
  docsScanned: docs,
  citationsChecked: citations,
  lineCitationsVerified: buckets.ok,
  fileMissingOrWrongCase: buckets.fileMissing.length,
  lineBeyondEnd: buckets.lineBeyond.length,
  rangeEndBeyondFile: buckets.rangeBeyond.length,
  reversedRange: buckets.reversedRange.length,
  retiredFileCitations: new Set(buckets.retired).size,
  crossTreeFileCitations: new Set(buckets.crossTree).size,
  crossTreeLineCitations: buckets.crossTreeLines.length,
  historicalDocCitations: buckets.historical.length,
};
console.log(JSON.stringify(summary, null, 2));
const all = [...buckets.fileMissing, ...buckets.lineBeyond, ...buckets.rangeBeyond, ...buckets.reversedRange];
for (const b of (full ? all : all.slice(0, 40))) console.log("  " + b);
if (!full && all.length > 40) console.log(`  （还有 ${all.length - 40} 条，用 --full 展开）`);
// 退出码只看「文件定位不到 + 行号越界/反向」；退役与跨树引用是合法陈述，历史文档已带理由标记。
process.exit(all.length === 0 ? 0 : 1);
