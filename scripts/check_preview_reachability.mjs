/** check_preview_reachability.mjs — 只读可达性门禁：CMake↔磁盘双向、链接可达闭包、悬空 include、尺寸与大小写陷阱，输出带源码哈希。 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const root = process.cwd();
const PROD_CMAKE = path.join(root, "Preview", "CMakeLists.txt");
const TEST_CMAKE = path.join(root, "tests", "Preview", "CMakeLists.txt");
const FINAL_TARGETS = ["PrismPreview"];
const LIMITS = { productionHeaderLines: 600, testCppLines: 800 };

// 行数必须按「内容行」算：`split("\n").length` 对以换行结尾的文件多算一行，于是正好 800 行的测试
// 被报成 801、被判超限。AGENTS.md 的判据是「不超过 800 行」，off-by-one 会制造无意义的拆文件动作。
function countLines(text) {
  const parts = text.split("\n");
  if (parts.length > 0 && parts[parts.length - 1] === "") parts.pop();
  return parts.length;
}

const readIf = (p) => { try { return fs.readFileSync(p, "utf8"); } catch { return null; } };
const stripComments = (s) => s.replace(/#[^\n]*/g, "");
const rel = (p) => path.relative(root, p).split(path.sep).join("/");

function listCmds(text) {
  const out = [];
  const re = /(add_library|add_executable|target_sources|target_link_libraries|LinkPreviewTargets|add_subdirectory|AddPreviewTest|AddContractTest|AddProductionTest|set_source_files_properties)\s*\(/g;
  let m;
  while ((m = re.exec(text))) {
    let depth = 1, i = m.index + m[0].length;
    while (i < text.length && depth > 0) {
      if (text[i] === "(") depth++;
      else if (text[i] === ")") depth--;
      i++;
    }
    out.push({ cmd: m[1], body: text.slice(m.index + m[0].length, i - 1) });
  }
  return out;
}

function collectCMake(entry, baseDir, acc) {
  const text = readIf(entry);
  if (text === null) { acc.missingCMake.push(path.relative(root, entry)); return acc; }
  acc.cmakeFiles.add(entry);
  const norm = (t) => {
    const expanded = t.replace(/^\$\{CMAKE_SOURCE_DIR\}/, root.replace(/\\/g, "/"));
    if (/^\$\{/.test(expanded) || /^[-a-zA-Z0-9_]+:/.test(expanded)) return null;
    return rel(path.resolve(expanded.startsWith(root.replace(/[\\]/g, "/")) || /^[A-Za-z]:/.test(expanded) ? expanded : path.join(baseDir, expanded)));
  };
  const dir = path.dirname(entry);
  for (const { cmd, body } of listCmds(stripComments(text))) {
    const toks = body.split(/[\s;]+/).filter(Boolean);
    const name = toks[0];
    if (cmd === "set_source_files_properties") {
      const properties = toks.indexOf("PROPERTIES");
      const language = toks.indexOf("LANGUAGE", properties + 1);
      if (properties !== -1 && language !== -1 && toks[language + 1] === "CXX") {
        for (const src of toks.slice(0, properties)) {
          const p = norm(src.replace(/"/g, ""));
          if (p) acc.tuRoots.add(p);
        }
      }
      continue;
    }
    if (/^Add(?:Preview|Contract|Production)Test$/.test(cmd)) {
      const src = name?.replace(/"/g, "");
      if (src && /\.cpp$/i.test(src)) {
        const tname = path.basename(src).replace(/\.cpp$/i, "");
        acc.targets.add(tname);
        const p = norm(src);
        if (p) acc.sources.set(p, tname);
      }
      continue;
    }
    if (cmd === "add_subdirectory") {
      const sub = toks[0]?.replace(/"/g, "");
      if (sub && !/^\$\{/.test(sub)) {
        acc.declared.push(rel(path.resolve(dir, sub)));
        collectCMake(path.join(dir, sub, "CMakeLists.txt"), path.join(dir, sub), acc);
      }
      continue;
    }
    if (cmd === "add_library" || cmd === "add_executable") {
      acc.targets.add(name);
      const rest = toks.slice(1).filter((t) => /\.(hpp|cpp|h|cxx|cc)$/i.test(t));
      for (const r of rest) { const p = norm(r); if (p) acc.sources.set(p, name); }
      continue;
    }
    if (cmd === "target_sources") {
      const rest = toks.slice(1).filter((t) => !/^(INTERFACE|PUBLIC|PRIVATE|FILE_SET|EXCLUDE_FROM_ALL|BASE_DIRS)$/.test(t));
      for (const r of rest) {
        if (!/\.(hpp|cpp|h|cxx|cc)$/i.test(r)) continue;
        const p = norm(r);
        if (p) acc.sources.set(p, name);
      }
      continue;
    }
    if (cmd === "target_link_libraries" || cmd === "LinkPreviewTargets") {
      const clean = toks.map((t) => t.replace(/"/g, "")).filter((t) => !/^(INTERFACE|PUBLIC|PRIVATE)$/.test(t));
      const consumer = clean[0];
      for (const dep of clean.slice(1)) (acc.edges.get(consumer) ?? acc.edges.set(consumer, new Set()).get(consumer)).add(dep);
    }
  }
  return acc;
}

const newAcc = () => ({ targets: new Set(), sources: new Map(), edges: new Map(), tuRoots: new Set(), cmakeFiles: new Set(), declared: [], missingCMake: [] });
const prod = collectCMake(PROD_CMAKE, path.join(root, "Preview"), newAcc());
const test = collectCMake(TEST_CMAKE, path.join(root, "tests", "Preview"), newAcc());

function walk(dir, filter, acc = []) {
  if (!fs.existsSync(dir)) return acc;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, filter, acc);
    else if (filter(e.name)) acc.push(full);
  }
  return acc;
}

const prodHeaders = walk(path.join(root, "Preview"), (n) => /\.(hpp|h|cpp|cxx|cc)$/i.test(n));
const testFiles = walk(path.join(root, "tests", "Preview"), (n) => /\.(hpp|cpp)$/i.test(n));

// 链接闭包：INTERFACE 库沿边传播。
function closure(seeds, edges) {
  const seen = new Set();
  const queue = [...seeds];
  while (queue.length) {
    const t = queue.pop();
    if (seen.has(t)) continue;
    seen.add(t);
    for (const dep of edges.get(t) ?? []) queue.push(dep);
  }
  return seen;
}
const reachableTargets = closure(FINAL_TARGETS, prod.edges);
// target_sources 记录到的是文件所属 target；文件可达 = 其 target 在闭包内。
const registered = new Map(prod.sources);

const problems = { registeredMissing: [], caseMismatch: [], diskUnregistered: [], unreachableRegistered: [], danglingIncludes: { production: [], registeredTest: [], unregisteredTest: [] }, tuRootIncluders: [], productionCpp: [], oversize: { production: [], test: [] }, caseCollisions: [] };

const diskIndex = new Map();
for (const p of prodHeaders) diskIndex.set(rel(p), p);

for (const [relPath, target] of registered) {
  if (!fs.existsSync(path.join(root, relPath))) { problems.registeredMissing.push(`${relPath} (target ${target})`); continue; }
  const exact = exactCasePath(relPath);
  if (!exact) problems.caseMismatch.push(relPath);
  if (!reachableTargets.has(target)) problems.unreachableRegistered.push(`${relPath} (target ${target})`);
}
for (const p of prodHeaders) {
  const r = rel(p);
  if (!registered.has(r)) problems.diskUnregistered.push(r);
  if (r.endsWith(".cpp") || r.endsWith(".cxx") || r.endsWith(".cc")) problems.productionCpp.push(r);
  const lines = countLines(fs.readFileSync(p, "utf8"));
  if (lines > LIMITS.productionHeaderLines) problems.oversize.production.push(`${r}: ${lines}`);
}

// 注册判定必须大小写折叠：磁盘目录名与 CMake 声明不一致时（见 caseMismatch），
// 精确匹配会把已登记测试误分成“未登记”，从而掩盖真实的编译阻塞。
const registeredTests = new Map();
for (const relPath of test.sources.keys()) registeredTests.set(relPath.toLowerCase(), relPath);
for (const [relPath, target] of test.sources) {
  if (!fs.existsSync(path.join(root, relPath))) problems.registeredMissing.push(`${relPath} (test target ${target})`);
}
for (const p of testFiles) {
  const r = rel(p);
  if (!/\.(cpp)$/i.test(r)) continue;
  const lines = countLines(fs.readFileSync(p, "utf8"));
  if (lines > LIMITS.testCppLines) problems.oversize.test.push(`${r}: ${lines}`);
}

// 悬空 include：解析 <Preview/...> 与 "Preview/..."（根 = CMAKE_SOURCE_DIR，见 ConfigurePreviewTarget）。
const includeRe = /#\s*include\s*[<"]([^">]+)[>"]/g;
// LANGUAGE CXX 头文件承载唯一翻译单元，生产头和测试不得再 include 它。
// 同时解析根路径和相对路径，避免只检查 Preview/... 而漏掉局部 include。
const tuRootsByPath = new Map([...prod.tuRoots].map((p) => [path.resolve(root, p).toLowerCase(), p]));
function danglingOf(fileText, filePath) {
  const out = [];
  if (fileText === null) return out;
  const dir = path.dirname(filePath);
  // 去掉块注释与行注释，避免注释里的示例被当成真实 include。
  const code = fileText.replace(/\/\*[\s\S]*?\*\//g, (comment) => comment.replace(/[^\n]/g, " "))
    .replace(/^[ \t]*\/\/[^\n]*/gm, "");
  let m;
  includeRe.lastIndex = 0;
  while ((m = includeRe.exec(code))) {
    const spec = m[1];
    const includedRoot = [path.resolve(root, spec), path.resolve(dir, spec)]
      .map((p) => tuRootsByPath.get(p.toLowerCase())).find((p) => p !== undefined);
    if (includedRoot !== undefined) {
      const line = code.slice(0, m.index).split("\n").length;
      problems.tuRootIncluders.push(`${rel(filePath)}:${line} -> ${includedRoot}`);
    }
    if (!spec.startsWith("Preview/") && !spec.startsWith("tests/")) continue;
    const fromRoot = path.join(root, spec);
    const fromDir = path.resolve(dir, spec);
    // AddPreviewTest 在 tests/CMakeLists.txt 明确 BEFORE 加入 tests/ 和 Preview/；生产头不使用这些测试搜索域。
    const previewTest = rel(filePath).startsWith("tests/Preview/");
    const fromTestIncludes = previewTest && [path.join(root, "tests", spec), path.join(root, "Preview", spec)]
      .some(candidate => fs.existsSync(candidate));
    if (!fs.existsSync(fromRoot) && !fs.existsSync(fromDir) && !fromTestIncludes) out.push(spec);
  }
  return out;
}
for (const p of prodHeaders) {
  const d = danglingOf(readIf(p), p);
  for (const spec of d) problems.danglingIncludes.production.push(`${rel(p)} -> ${spec}`);
}
for (const p of testFiles) {
  const d = danglingOf(readIf(p), p);
  const r = rel(p);
  for (const spec of d) {
    const declared = registeredTests.get(r.toLowerCase());
    if (declared !== undefined) {
      const note = declared === r ? "" : ` (CMake 声明为 ${declared})`;
      problems.danglingIncludes.registeredTest.push(`${r} -> ${spec}${note}`);
    } else problems.danglingIncludes.unregisteredTest.push(`${r} -> ${spec}`);
  }
}

// Windows 大小写陷阱：同一目录下仅大小写不同的名字。
for (const dir of new Set([...prodHeaders, ...testFiles].map((p) => path.dirname(p)))) {
  const seen = new Map();
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const key = e.name.toLowerCase();
    if (seen.has(key) && seen.get(key) !== e.name) problems.caseCollisions.push(`${rel(path.join(dir, e.name))} vs ${rel(path.join(dir, seen.get(key)))}`);
    seen.set(key, e.name);
  }
}

function exactCasePath(relPath) {
  let cur = root;
  for (const part of relPath.split("/")) {
    if (!fs.existsSync(cur)) return false;
    const hit = fs.readdirSync(cur).find((n) => n === part);
    if (!hit) return false;
    cur = path.join(cur, hit);
  }
  return true;
}

// CMake 声明的路径必须与磁盘大小写逐字一致：Windows 不敏感会掩盖，Linux configure 直接失败。
// 计数按"第一个不一致的目录成分"去重，避免 Integration 与其子路径被重复统计。
const caseSeen = new Set();
function checkCase(p, kind) {
  if (!fs.existsSync(path.join(root, p))) {
    const key = `absent:${p}`;
    if (!caseSeen.has(key)) { caseSeen.add(key); problems.caseMismatch.push(`${kind} absent from disk: ${p}`); }
    return;
  }
  let cur = root;
  const walked = [];
  for (const part of p.split("/")) {
    walked.push(part);
    const names = fs.readdirSync(cur);
    if (!names.includes(part)) {
      const ci = names.find((n) => n.toLowerCase() === part.toLowerCase());
      const key = `${cur}/${ci ?? part}`;
      if (!caseSeen.has(key)) {
        caseSeen.add(key);
        problems.caseMismatch.push(`${kind} case mismatch at ${walked.join("/")}: ${p} (磁盘为 ${ci ?? part})`);
      }
      return;
    }
    cur = path.join(cur, part);
  }
}
for (const acc of [prod, test]) {
  for (const d of acc.declared) checkCase(d, "add_subdirectory");
  for (const s of acc.sources.keys()) checkCase(s, "registered source");
}

// 二阶分歧：checkCase 按「第一个不一致成分」去重，所以父目录一旦不符，其下所有子目录的分歧都会被掩盖。
// 改名父目录后这些会立刻变成新的 configure 失败，因此单独逐段展开列出（不在第一个分歧处停）。
const secondOrder = new Map();
const visitedDir = new Set();
function walkDeclared(dir) {
  const key = dir.replace(/\\/g, "/");
  if (visitedDir.has(key)) return;
  visitedDir.add(key);
  const text = readIf(path.join(root, key, "CMakeLists.txt"));
  if (text === null) return;
  for (const { cmd, body } of listCmds(stripComments(text))) {
    if (cmd !== "add_subdirectory") continue;
    const sub = body.split(/[\s;]+/).filter(Boolean)[0]?.replace(/"/g, "");
    if (!sub || /^\$\{/.test(sub)) continue;
    let cur = key;
    let dead = false;
    for (const s of sub.split("/")) {
      let names = [];
      try { names = fs.readdirSync(path.join(root, cur)); } catch { dead = true; break; }
      if (names.includes(s)) { cur = `${cur}/${s}`; continue; }
      const hit = names.find((n) => n.toLowerCase() === s.toLowerCase());
      if (!hit) { dead = true; break; }
      secondOrder.set(`${cur} :: ${s} -> ${hit}`, (secondOrder.get(`${cur} :: ${s} -> ${hit}`) || 0) + 1);
      cur = `${cur}/${hit}`;
    }
    if (!dead) walkDeclared(cur);
  }
}
walkDeclared("tests/Preview");
walkDeclared("Preview");
problems.secondOrderCaseDivergence = [...secondOrder.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, n]) => `refs=${n}  ${k}`);

const scanned = [...new Set([...prodHeaders, ...testFiles, ...prod.cmakeFiles, ...test.cmakeFiles,
  path.join(root, "scripts", "check_preview_reachability.mjs")])];
const digest = crypto.createHash("sha256").update(scanned.sort().map((p) => `${rel(p)}=${crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex")}`).join("\n")).digest("hex");

const summary = {
  capturedAt: new Date().toISOString(),
  sourceManifestSha256: digest,
  translationUnitRoots: [...prod.tuRoots].sort(),
  counts: Object.fromEntries(Object.entries(problems).map(([k, v]) => [k, Array.isArray(v) ? v.length : Object.keys(v).reduce((n, kk) => n + v[kk].length, 0)])),
  reachableTargets: [...reachableTargets].sort(),
  unreachableTargetList: [...prod.targets].filter((t) => !reachableTargets.has(t)).sort(),
  missingCMake: prod.missingCMake.concat(test.missingCMake),
};
console.log(JSON.stringify({ summary, problems }, null, 2));
const total = Object.values(summary.counts).reduce((a, b) => a + b, 0);
process.exit(total === 0 ? 0 : 1);
