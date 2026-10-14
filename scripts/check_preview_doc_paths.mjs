import fs from "node:fs";
import path from "node:path";

// 校验 SDD 台账与 logs/issues.md 中引用的**仓库内文件路径**是否真实存在。
// 动机：本会话三次因"按引用文本拼路径"产出错误坐标（少 Detail/、把 Http3 根目录文件写成 Qpack/ 子目录等）。
// 用法：node scripts/check_preview_doc_paths.mjs [--full]
// 门禁默认只扫「本计划工作区 + 问题账 + Preview 自带的 README」；repo 文档整体陈旧度用 --include-docs 单独量（属 M36 台账更新待办，不混入门禁退出码）。
// Preview/ 必须进默认面：docs/ 的多份文档把 `Preview/README.md` 指为**当前**入口，而它此前不在任何坐标校验范围内。
const dirs = [".superpowers/sdd/2026-10-09-preview-quality-modification-plan", "logs", "Preview"];
if (process.argv.includes("--include-docs")) dirs.push("docs");
const full = process.argv.includes("--full");
const existsCache = new Map();

function exists(rel) {
  if (existsCache.has(rel)) return existsCache.get(rel);
  const ok = fs.existsSync(rel);
  existsCache.set(rel, ok);
  return ok;
}

// 存在性必须**精确到大小写**：本仓库在 Windows（core.ignorecase=true）上开发，
// fs.existsSync 对 `tests/preview/` 这种只错大小写的写法同样返回 true，
// 而 Linux CI 与 MinGW 之外的编译器会直接找不到文件。
const exactCache = new Map();
function existsExact(rel) {
  if (exactCache.has(rel)) return exactCache.get(rel);
  const segs = rel.split("/");
  let cur = ".";
  let ok = true;
  for (const s of segs) {
    let entries = null;
    try { entries = fs.readdirSync(cur); } catch { ok = false; break; }
    if (!entries.includes(s)) { ok = false; break; }
    cur = path.join(cur, s);
  }
  if (ok) { try { ok = fs.statSync(cur).isFile(); } catch { ok = false; } }
  exactCache.set(rel, ok);
  return ok;
}

// 只认带扩展名的仓库相对路径；反引号/空格/中文顿号作为边界
const refRe = /(?:Preview|tests|scripts|docs|src|include)\/[A-Za-z0-9_.\/-]*\.(?:hpp|cpp|json|md|txt|cmake|ps1|sh|mjs)/g;

const bad = [];
let checked = 0;
let docs = 0;

// 分类依据：git 里 tracked-已删除（`D`）的路径属于**有意退役**，其引用是历史记录而非笔误。
import { execFileSync } from "node:child_process";
let deletedSet = new Set();
try {
  deletedSet = new Set(execFileSync("git", ["ls-files", "--deleted"], { encoding: "utf8" }).split("\n").map((s) => s.trim().split(path.sep).join("/")).filter(Boolean));
} catch { /* 非 git 环境下退役分类退化为 unknown，不影响存在性判定 */ }
const retiredDirs = new Set([...deletedSet].map((p) => p.split("/").slice(0, -1).join("/")));
const isRetired = (p) => deletedSet.has(p) || [...retiredDirs].some((d) => d && (p === d || p.startsWith(d + "/")));

const buckets = { retired: [], mainOnly: [], wrongPath: [], unknown: [], caseMismatch: [], historical: [] };
// 双树引用是合法写法（例如「主树仍在 Protocols/Http1/，执行树已移到 Foundation/Utility/Http/」）。
// 因此执行树里不存在、主树里存在的路径单独归一类，不算笔误。
const MAIN_ROOT = process.env.PRISM_MAIN_TREE || "I:/code/Prism";
// 主树存在性也必须**逐段大小写校核**：`fs.existsSync` 在 Windows 上大小写不敏感，
// 会把「主树只有 Protocols/」与「主树只有 protocols/」两种事实判成一样，从而把真实错拼
// 豁免成「跨树引用」。本仓库正在做双树对账（E-39/E-44），这个豁免若不准就会直接吞掉缺陷。
const existsExactIn = (root, rel) => {
  let cur = root;
  for (const seg of rel.split("/")) {
    let entries = [];
    try { entries = fs.readdirSync(cur); } catch { return false; }
    const hit = entries.find((e) => e === seg);
    if (!hit) return false;
    cur = path.join(cur, hit);
  }
  try { return fs.statSync(cur).isFile(); } catch { return false; }
};
const inMainTree = (p) => existsExactIn(MAIN_ROOT, p);

// 只错大小写时给出磁盘上的真实写法，便于直接订正。
function resolveCase(rel) {
  const segs = rel.split("/");
  let cur = ".";
  const out = [];
  for (const s of segs) {
    let entries = [];
    try { entries = fs.readdirSync(cur); } catch { return []; }
    const hit = entries.find((e) => e.toLowerCase() === s.toLowerCase());
    if (!hit) return [];
    out.push(hit);
    cur = path.join(cur, hit);
  }
  return [out.join("/")];
}

for (const dir of dirs) {
  if (!fs.existsSync(dir)) continue;
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    for (const e of fs.readdirSync(cur, { withFileTypes: true })) {
      const full_ = path.join(cur, e.name);
      const norm_ = full_.split(path.sep).join("/");
      // 两类目录必须跳过，否则门禁会去抱怨自己写出的文件与冻结快照：
      //   snapshots/ = 本门禁自身的输出；Baseline/ = 阶段 0 冻结的仓库文档副本（按定义不可编辑）。
      if (/(^|\/)(snapshots|Baseline)(\/|$)/.test(norm_)) continue;
      if (e.isDirectory()) { stack.push(full_); continue; }
      if (!/\.md$/.test(e.name)) continue; // 不扫 .txt：门禁输出会污染统计
      docs++;
      const text = fs.readFileSync(full_, "utf8");
      const lines = text.split("\n");
      // 文件级历史标记：整篇是历史规划/快照文档时，逐行加豁免会把文档改写成它当时并不存在的样子。
      // 只认前 20 行内的 `<!-- pathcheck:historical=理由 -->`，缺理由则告警。
      const head20 = lines.slice(0, 20).join("\n");
      const histMark = /pathcheck:historical/.test(head20);
      const histReason = /pathcheck:historical\s*=\s*[^\s>]/.test(head20);
      if (histMark && !histReason) console.log(`  ! ${norm_} 有 pathcheck:historical 标记但缺理由`);
      const local = new Map();
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // 允许显式豁免：某条引用「按设计就是不存在的」（占位符、构建后才存在的路径、
        // 或结论本身就是「该文件/类型缺失」）。豁免必须就地标注理由，否则等于关掉检查。
        if (/pathcheck:ignore(?!\s*=\s*(?:reason|理由))/.test(line) && !/pathcheck:ignore\s*=\s*\S/.test(line)) {
          console.log(`  ! ${full_}:${i + 1} 有豁免标记但缺理由（写法应为 pathcheck:ignore=理由…）`);
        }
        if (/pathcheck:ignore/.test(line)) continue;
        const seg = line.match(refRe);
        if (!seg) continue;
        for (const raw of seg) {
          // 必须出现在路径边界上：`<Experiments/Preview/Authentication.hpp>` 属实验树 include，
          // 不能被当成本仓库根下的 `Preview/Authentication.hpp`（首版正是这样产生假阳性）。
          const at = line.indexOf(raw);
          const prev = at > 0 ? line[at - 1] : "";
          if (at > 0 && /[\w./-]/.test(prev)) continue;
          const p = raw.replace(/[.,;:]+$/, "");
          checked++;
          if (existsExact(p)) continue;
          // "case" = 只错大小写（Windows 看得见、Linux 与 git 看不见），其它缺失按 null 走原分类。
          if (!local.has(p)) local.set(p, exists(p) ? "case" : null);
        }
      }
      for (const [p, kind] of local.entries()) {
        if (histMark) {
          buckets.historical.push({ cited: p, from: norm_, actual: kind === "case" ? resolveCase(p) : [], kind: "historical" });
          continue;
        }
        // 判定顺序即严格性来源：先认「主树精确存在」（合法的双树陈述），再判「本树只错大小写」（缺陷）。
        // 反过来会把主树 Protocols/ 的合法引用误判成隔离树拼写错误，或把拼写错误豁免成跨树引用。
        if (inMainTree(p)) { buckets.mainOnly.push({ cited: p, from: norm_, actual: [], kind: "mainOnly" }); continue; }
        if (kind === "case") {
          const c = { cited: p, from: norm_, actual: resolveCase(p), kind: "caseMismatch" };
          buckets.caseMismatch.push(c);
          bad.push(c);
          continue;
        }
        if (isRetired(p)) { buckets.retired.push({ cited: p, from: norm_, actual: [], kind: "retired" }); continue; }
        const base = path.basename(p);
        const hits = [];
        (function scan(d, depth) {
          if (depth > 6 || hits.length > 3) return;
          if (!fs.existsSync(d)) return;
          for (const e of fs.readdirSync(d, { withFileTypes: true })) {
            if (e.isDirectory()) { if (!/node_modules|\.git|build|_deps/.test(e.name)) scan(path.join(d, e.name), depth + 1); }
            else if (e.name === base) hits.push(path.join(d, e.name).split(path.sep).join("/"));
          }
        })(p.split("/")[0], 0);
        const rec = { cited: p, from: norm_, actual: hits.slice(0, 3), kind: hits.length ? "wrongPath" : "unknown" };
        (hits.length ? buckets.wrongPath : buckets.unknown).push(rec);
        bad.push(rec);
      }
    }
  }
}

const summary = {
  docsScanned: docs,
  citationsChecked: checked,
  retiredCitations: buckets.retired.length,
  crossTreeCitations: buckets.mainOnly.length,
  historicalDocCitations: buckets.historical.length,
  caseMismatchCitations: buckets.caseMismatch.length,
  wrongPathCitations: buckets.wrongPath.length,
  unknownMissing: buckets.unknown.length,
};
console.log(JSON.stringify(summary, null, 2));
const all = [...buckets.caseMismatch, ...buckets.wrongPath, ...buckets.unknown];
const show = full ? all : all.slice(0, 30);
for (const b of show) {
  console.log(`  [${b.kind}] ${b.from}\n      引用 ${b.cited}${b.actual.length ? `；磁盘同名：${b.actual.slice(0, 2).join(", ")}` : "；磁盘无同名文件"}`);
}
if (!full && all.length > 30) console.log(`  （还有 ${all.length - 30} 条，用 --full 展开）`);
// 退出码看「大小写陷阱 + 疑似笔误 + 完全未知」；退役引用是历史记录，历史文档已带理由标记，均不算失败。
process.exit(all.length === 0 ? 0 : 1);
