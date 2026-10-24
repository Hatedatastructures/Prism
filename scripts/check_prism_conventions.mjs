import { GetPrismAbiContract } from './PrismAbiContracts.mjs';
/** check_prism_conventions.mjs — 只读约定门禁：源码 include 方向、兼容层与重复错误形状、PascalCase、中文 Doxygen、三目计数；输出带源码清单哈希。 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const root = process.cwd();
const PROD = [path.join(root, "Include", "Prism"), path.join(root, "Src", "Prism")];
const missingRoots = PROD.filter((directory) =>
  !fs.existsSync(directory) || !fs.statSync(directory).isDirectory());
if (missingRoots.length > 0) {
  console.error(`Required production source roots are missing: ${missingRoots.join(", ")}`);
  process.exit(1);
}

const walk = (d, acc = []) => {
  if (!fs.existsSync(d)) return acc;
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (/\.(?:hpp|cpp)$/i.test(e.name)) acc.push(p);
  }
  return acc;
};
const rel = (p) => path.relative(root, p).split(path.sep).join("/").replace(/^(?:Include|Src)\//, "");

// 去注释与字符串，避免把示例、日志文本和 wire 字段当成代码事实。
function strip(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^[ \t]*\/\/[^\n]*/gm, "")
    .replace(/\\?[^\S\n]?"(?:[^"\\\n]|\\.)*"/g, ' ""')
    .replace(/\\?[^\S\n]?'(?:[^'\\\n]|\\.)*'/g, " ''");
}

// 与 Src/Prism/CMake/PrismBoundary.cmake 的模块所有权表对应的源码侧规则。
const RULES = [
  { owner: "^Prism/Foundation/", forbidden: /^Prism\/(?!Foundation\/)/, why: "Foundation 必须处于最底层" },
  { owner: "^Prism/Lifecycle/", forbidden: /^Prism\/(?!Foundation\/|Lifecycle\/)/, why: "Lifecycle 只依赖 Foundation" },
  { owner: "^Prism/Transport/", forbidden: /^Prism\/(?!Foundation\/|Lifecycle\/|Contract\/Io\/|Transport\/)/, why: "Transport 只允许 Foundation/Lifecycle/Io 契约" },
  { owner: "^Prism/Protocols/", forbidden: /^Prism\/(Composition|Application|Runtime|Boundary)\//, why: "协议不得反向依赖装配/应用/调度/入口" },
  { owner: "^Prism/Boundary/", forbidden: /^Prism\/(Composition|Application)\//, why: "Boundary 不得消费装配与应用" },
  { owner: "^Prism/Boundary/", forbidden: /^Prism\/Protocols\/(?!Common\/)/, why: "Boundary 不得引用具体协议实现（Common 除外）" },
  { owner: "^Prism/Runtime/", forbidden: /^Prism\/(Composition|Application)\//, why: "Runtime 不得消费装配与应用" },
  { owner: "^Prism/Runtime/", forbidden: /^Prism\/Protocols\/(?!Common\/)/, why: "Runtime 不得引用具体协议实现（Common 除外）" },
  { owner: "^Prism/Net/", forbidden: /^Prism\/(Composition|Application|Protocols)\//, why: "Net 不得消费装配/应用/协议" },
  // 中立契约不得泄漏具体协议类型或反向消费装配层；此前缺规则，属门禁覆盖盲点。
  { owner: "^Prism/Contract/", forbidden: /^Prism\/(Protocols|Composition|Application|Runtime)\//, why: "Contract 是中立契约，不得引用具体协议/装配/应用/调度" },
];

const files = PROD.flatMap((directory) => walk(directory));
const findings = { includeDirection: [], forwardDeclCoupling: [], compatLayer: [], duplicateErrorShapes: [], nonPascalIdentifiers: [], missingChineseDoxygen: [], ternaryFiles: 0, ternaryCount: 0 };
const includeRe = /#\s*include\s*[<"]([^">]+)[>"]/g;
// 第三方/标准库规定的回调 ABI 名，必须保留小写；每一项都是显式例外，不是启发式放过。
const ABI_HOOKS = new Set(["shutdown", "close", "send", "receive", "assign", "cancel", "wait",
  "read_some", "write_some", "connect", "accept", "resolve", "set_option", "io_control", "release"]);
const NS_ALIASES = new Set(["std", "glz", "net", "asio", "posix", "nghttp3", "ngtcp2", "ssl", "bio", "evp", "json", "asio_ssl"]);
// 标准库/第三方 C ABI 强制名称：小写是规定，不是违规。每一项都是显式例外。
const STD_ABI_NAMES = /^(?:is_error_code_enum|is_error_condition_enum|is_system_error|hash|equal_to|less|value_type|variant_size|variant_alternative|tuple_size|error_code|error_condition|.*_st|.*_type|difference_type|iterator_category|iterator_concept|reference|pointer|const_iterator|iterator|begin|end|is_transparent|alignas|async_[a-z_]+|size|empty|data)$/;
const identRe = /\b(?:class|struct|enum(?:\s+class)?)\s+([A-Za-z_][A-Za-z0-9_]*)|\busing\s+([A-Za-z_][A-Za-z0-9_]*)\s*=/g;
// 注意：必须允许 `[[nodiscard]]` 等属性前缀，否则本仓库大量带属性的声明会被整条漏掉（曾因此得出 nonPascal=0 的伪绿）。
const fnRe = /^\s*(?:template\s*<[^>]*>\s*)?(?:(?:inline|constexpr|consteval|static|virtual|explicit|friend|\[\[[a-z_]+\]\])[ \t]+)*auto[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(/gm;

// 标准库/第三方规定的**小写函数名**：按 file + name 精确登记，不做全局放过（全局放过会让任何同名函数免检）。
// 每项必须写清它对应哪条上游签名，评审时才能核对"是不是真的 ABI"。
const MandatedFnAbi = new Map([
  ["Prism/Foundation/Utility/Diagnose/Detail/AsyncBackendState.hpp", new Map([
    ["lock", "std::lock_guard<Diagnose::Detail::EpochGate> 的 BasicLockable 规定成员名"],
    ["unlock", "std::lock_guard<Diagnose::Detail::EpochGate> 的 BasicLockable 规定成员名"]])],
  ["Prism/Account/Failure.hpp", new Map([
    ["name", "std::error_category::name() 的覆写（返回 const char*）"],
    ["message", "std::error_category::message(int) 的覆写"]])],
  ["Prism/Foundation/Utility/Text/FixedText.hpp", new Map([
    ["format", "std::formatter<...>::format(const T&, FormatContext&) 的规定签名"]])],
  ["Prism/Transport/Detail/TlsOperations.hpp", new Map([
    ["call_handler", "Asio completion handler invoker 要求的 call_handler() 名字"],
    ["tracking_name", "boost/asio/ssl/detail/io.hpp 规定的 Operation::tracking_name() 钩子"]])],
  ["Prism/Transport/Detail/IoCompletion.hpp", new Map([
    ["allocate", "std::allocator_traits<CompletionAllocator>::allocate 的规定成员名"],
    ["deallocate", "std::allocator_traits<CompletionAllocator>::deallocate 的规定成员名"]])],
]);
const MandatedTypeAbi = new Map([
  ["Prism/Operations/Web/Loader.hpp", new Map([
    ["meta", "glz::meta<ResourceDescriptor/ResourceManifest> 的规定类型特化名"]])],
  ["Prism/Transport/Detail/IoCompletion.hpp", new Map([
    ["is_always_equal", "std::allocator_traits 的规定类型名"],
    ["rebind", "std::allocator_traits 的 allocator::rebind<U> 类型定制点"],
    ["other", "allocator::rebind<U>::other 的规定类型名"]])],
]);
const AbiExemptedTypes = [];
// 「兼容层命名」的显式例外：由外部协议/线格式规定的名字，不是项目自建的旧接口通道。
const CompatNamingExceptions = new Map([
  ["Prism/Protocols/Vmess/Types.hpp", new Map([
    ["Legacy", "VMess 安全类型字节 0x01 的协议既定名称（wire 值由协议规定）；改名属命名优化，不是兼容层违规"]])],
]);
const abiExemptedFns = [];
// Asio/标准库的**定制点名称**（customization point / 概念要求）：小写是规定，不是项目命名违规。
// 这里按名字全局豁免，但每一次命中仍写入 findings.abiExemptedFunctions，保持逐条可审。
const StdAsioCptNames = new Map([
  ["get_executor", "Asio execution_context / async_result 要求的定制点"],
  ["get_allocator", "Asio async_alloc_result 要求的定制点"],
  ["get_cancellation_slot", "Asio async_result 要求的定制点"],
  ["lowest_layer", "Asio 分层 transport 协议要求"],
  ["next_layer", "Asio 分层 transport 协议要求"],
  ["native_handle", "Asio/标准句柄访问器约定"],
  ["make_error_code", "std::error_code 枚举 ADL 定制点（名字由标准规定）"],
  ["name", "std::error_category::name() 覆写"],
  ["message", "std::error_category::message(int) 覆写"],
  ["call_handler", "Asio completion handler invoker 要求"],
  ["require", "Asio execution::require/prefer 定制点"],
  ["prefer", "Asio execution::prefer 定制点"],
]);
const compatExempted = [];

// 前向声明耦合：include 图与 CMake target 都看不见 `namespace Prism::Quic { class Server; }` 这类名字级依赖。
// 把命名空间解析回模块目录（优先 Prism/Protocols/<Ns>，再 Prism/<Ns>），再套用同一方向规则。
function moduleOfNamespace(ns) {
  const cand = [`Prism/Protocols/${ns}`, `Prism/${ns}`];
  for (const c of cand) {
    if (fs.existsSync(path.join(root, "Include", c)) || fs.existsSync(path.join(root, "Src", c))) return c + "/";
  }
  return null;
}
const fwdRe = /namespace\s+Prism::([A-Za-z0-9_]+)\s*\{[^}]*\b(?:class|struct)\s+([A-Za-z0-9_]+)\s*;[^}]*\}/g;

// 顶层逗号切分参数（跳过 <> () {} 与字符常量），用于 AGENTS.md「通常 ≤2 参数」度量。
function splitParams(src) {
  const out = [];
  let depth = 0, cur = "";
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if ("<([{".includes(c)) depth++;
    else if (">)]}".includes(c)) depth--;
    else if (c === "'" && /'/.test(src.slice(i + 1, i + 4))) { const e = src.indexOf("'", i + 2); if (e > i) { cur += src.slice(i, e + 1); i = e; continue; } }
    if (c === "," && depth === 0) { out.push(cur.trim()); cur = ""; continue; }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out.filter(Boolean);
}

// 仅匹配项目规定的尾随返回类型声明式；构造/运算符/非 auto 返回不在本度量内（口径写进报告）。
const declRe = /^[ \t]*(?:(?:inline|constexpr|static|friend|explicit|virtual)[ \t]+)*auto[ \t]+([A-Za-z_~][A-Za-z0-9_]*)[ \t]*\(/gm;

function balanceClose(text, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < text.length; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")") { depth--; if (depth === 0) return i; }
  }
  return -1;
}

// 等长脱敏：注释与字符串内容替换为空格，保留换行与偏移，使行号仍对应原文件。
function blankOut(text) {
  let out = text.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "));
  out = out.replace(/\/\/[^\n]*/g, (m) => " ".repeat(m.length));
  out = out.replace(/"(?:[^"\\\n]|\\.)*"/g, (m) => '"' + " ".repeat(Math.max(0, m.length - 2)) + '"');
  return out;
}

function paramMetrics(code, file, abiFile = file) {
  let scanned = 0;
  const rows = [];
  for (const m of code.matchAll(declRe)) {
    const openIdx = m.index + m[0].length - 1;
    const close = balanceClose(code, openIdx);
    if (close === -1) continue;
    const inner = code.slice(openIdx + 1, close);
    const params = splitParams(inner);
    scanned++;
    const required = params.filter((p) => !p.includes("=")).length;
    if (params.length > 2) {
      const line = code.slice(0, m.index).split("\n").length;
      rows.push({ file, abiFile, line, name: m[1], params: params.length, required });
    }
  }
  return { scanned, rows };
}

for (const p of files) {
  const r = rel(p);
  const raw = fs.readFileSync(p, "utf8");
  const code = strip(raw);

  includeRe.lastIndex = 0;
  let m;
  while ((m = includeRe.exec(code))) {
    const spec = m[1];
    if (!spec.startsWith("Prism/")) continue;
    for (const rule of RULES) {
      if (new RegExp(rule.owner).test(r) && new RegExp(rule.forbidden.source).test(spec) && !new RegExp(rule.owner).test(spec)) {
        findings.includeDirection.push(`${r} -> ${spec} (${rule.why})`);
      }
    }
  }

  for (const fwd of code.matchAll(fwdRe)) {
    const ns = fwd[1];
    const target = moduleOfNamespace(ns);
    if (!target) continue;
    for (const rule of RULES) {
      if (new RegExp(rule.owner).test(r) && new RegExp(rule.forbidden.source).test(target) && !new RegExp(rule.owner).test(target)) {
        findings.forwardDeclCoupling.push(`${r} 前向声明 Prism::${ns}::${fwd[2]} → ${target} (${rule.why})`);
        break;
      }
    }
  }

  // include 行不参与命名/兼容层判定，避免把 <X/Compatible.hpp> 当成声明。
  const codeNoInc = code.replace(/^[ \t]*#\s*include[^\n]*$/gm, "");

  {
    const hits = [...codeNoInc.matchAll(/\b(Legacy|Compat(?:ible|ibility)?|ForwardingWrapper)\b/g)].map((x) => x[1]);
    const allowed = CompatNamingExceptions.get(r);
    const unexempted = hits.filter((h) => !(allowed && allowed.has(h)));
    if (!unexempted.length && hits.length) {
      for (const h of hits) compatExempted.push(`${r}: “${h}” —— ${allowed.get(h)}`);
    } else if (unexempted.length) {
      findings.compatLayer.push(`${r}: 兼容层命名（${[...new Set(unexempted)].join(", ")}）`);
    }
  }
  if (/\bstatic_assert\(\s*false\b/.test(code)) findings.compatLayer.push(`${r}: 存在 static_assert(false) 占位`);

  const shape = codeNoInc.match(/\b(?:class|struct|enum(?:\s+class)?)\s+(Error|Failure|Code|ErrorCode|ProviderError|ProviderFailure)\b/g);
  if (shape) findings.duplicateErrorShapes.push(`${r}: ${[...new Set(shape)].join(" | ")}`);

  const tern = (code.match(/[^?]\?\s*[^:]+:/g) || []).length;
  if (tern) { findings.ternaryFiles++; findings.ternaryCount += tern; }

  identRe.lastIndex = 0;
  const offenders = [];
  let id;
  while ((id = identRe.exec(code))) {
    const name = id[1] ?? id[2];
    const MandatedType = MandatedTypeAbi.get(r)?.get(name);
    if (MandatedType) { AbiExemptedTypes.push(`${r}: ${name} —— ${MandatedType}`); continue; }
    if (!name || name === "detail" || STD_ABI_NAMES.test(name) || NS_ALIASES.has(name.toLowerCase())) continue;
    if (!/^[A-Z]/.test(name)) offenders.push(`类型 ${name}`);
  }
  for (const fn of code.matchAll(fnRe)) {
    const name = fn[1];
    const mandated = MandatedFnAbi.get(r);
    if (mandated && mandated.has(name)) { abiExemptedFns.push(`${r}: ${name}() —— ${mandated.get(name)}`); continue; }
    if (StdAsioCptNames.has(name)) { abiExemptedFns.push(`${r}: ${name}() —— ${StdAsioCptNames.get(name)}`); continue; }
    if (/^(operator|main|test)$/.test(name) || ABI_HOOKS.has(name) || /^async_[a-z_]+$/.test(name) || name === "begin" || name === "end") continue;
    if (!/^[A-Z]/.test(name)) offenders.push(`函数 ${name}`);
  }
  if (offenders.length) findings.nonPascalIdentifiers.push(`${r}: ${[...new Set(offenders)].join(", ")}`);

  const hasDoc = /@brief|@file/.test(raw);
  if (!hasDoc) findings.missingChineseDoxygen.push(`${r}: 无 @file/@brief`);
  else if (!/[一-鿿]/.test(raw.split(/\n/).filter((l) => /@brief|@details|@return|@note/.test(l)).join("\n"))) findings.missingChineseDoxygen.push(`${r}: Doxygen 描述非中文`);
}

// 参数个数度量（AGENTS.md：通常 ≤2，复杂边界 ≤3；>3 为硬违规）
let paramScanned = 0;
const over2 = [];
for (const p of files) {
  const abiFile = path.relative(root, p).split(path.sep).join("/");
  const pm = paramMetrics(blankOut(fs.readFileSync(p, "utf8")), rel(p), abiFile);
  paramScanned += pm.scanned;
  over2.push(...pm.rows);
}
over2.sort((a, b) => b.params - a.params || a.file.localeCompare(b.file));

// [[nodiscard]] 覆盖度量（计划 §M35/M36 要求，此前四份门禁均未查）。
// 只识别项目自身的尾随返回形状，是**结构性下界**；是否「值得」加 nodiscard 属人工判断。
// 注：曾在此尝试加「经典返回类型」检测，正则实测产出 448 条里绝大多数是构造函数、operator 与
// control flow 的误报（且第一版因为分隔符写错而报 0，即伪绿），故撤下——该判据需要真解析器，不用正则硬凑。
const trailingRe = /^[ \t]*(\[\[nodiscard\]\][ \t]*)?(?:(?:inline|constexpr|static|friend|explicit|virtual|co_return)[ \t]+)*auto[ \t]+([A-Za-z_~][A-Za-z0-9_]*)[ \t]*\(/gm;
function signatureMetrics(code, file) {
  const missingNodiscard = [];
  for (const m of code.matchAll(trailingRe)) {
    if (m[1]) continue; // 已带 [[nodiscard]]
    const openIdx = m.index + m[0].length - 1;
    const close = balanceClose(code, openIdx);
    if (close === -1) continue;
    const tail = code.slice(close + 1, close + 160);
    const ret = tail.match(/->[ \t]*((?:const[ \t]+|unsigned[ \t]+)?[^\s;,{()]{1,60}(?:[ \t]*[*&])?)/);
    if (!ret) continue;                       // 无尾随返回类型（构造函数/运算符等形状）
    const type = ret[1];
    if (/^void$/.test(type)) continue;         // 不返回值的函数不需要
    // 名字限定形式也必须排除（Net::awaitable<void>、boost::asio::awaitable<void> 等）
    if (/(?:^|::)(?:awaitable|task|generator)<[ \t]*void[ \t]*>/.test(type)) continue;
    const line = code.slice(0, m.index).split("\n").length;
    missingNodiscard.push({ file, line, name: m[2], type });
  }
  return { missingNodiscard };
}
const nodiscardRows = [];
for (const p of files) {
  const sm = signatureMetrics(blankOut(fs.readFileSync(p, "utf8")), rel(p));
  nodiscardRows.push(...sm.missingNodiscard);
}
nodiscardRows.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);

// 公共接口契约文档覆盖率（人工审查辅助指标，不是合规证明）：
// 对入口/传输/网络/契约模块里的 class/struct，统计其前置文档块是否提到
// 所有权、取消、半关闭、关闭者、executor 这五类语义中的若干类。
const CONTRACT_DIRS = ["Prism/Boundary/", "Prism/Transport/", "Prism/Net/", "Prism/Contract/", "Prism/Runtime/Session/"];
const SEMANTIC_MARKS = [
  ["所有权", /所有权|owning|owner|拥有|持有|保活/],
  ["取消", /取消|cancel/i],
  ["半关闭", /半关闭|half[- ]?close|shutdown/i],
  ["最终关闭者", /最终关闭|closer|关闭者|负责关闭/],
  ["executor", /executor|执行器|strand/i],
];

function contractDocMetrics(relPath, rawText) {
  if (!CONTRACT_DIRS.some((d) => relPath.startsWith(d))) return { classes: 0, documented: 0, semanticSets: [0, 0, 0, 0, 0], missing: [] };
  const lines = rawText.split("\n");
  let classes = 0, documented = 0;
  const semanticSets = [0, 0, 0, 0, 0];
  const missing = [];
  for (let i = 0; i < lines.length; i++) {
    // 仅统计命名空间层/一层嵌套的声明；类内深层嵌套类型（State、Release 等）不算公共接口。
    const m = lines[i].match(/^[ \t]{0,4}(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)\b/);
    if (!m) continue;
    if (/\b(class|struct)\b.*;/.test(lines[i]) && !/\{|$/.test(lines[i])) continue;
    classes++;
    // 向上收集完整文档块：遇到注释起始 /** 停止；遇到结构性行（空行、};、#、其它声明）判定为无文档。
    let doc = "";
    for (let j = i - 1, guard = 0; j >= 0 && guard < 40; j--, guard++) {
      const l = lines[j].trim();
      if (l === "" || /^\}\s*;?$/.test(l) || /^#/.test(l)) break;
      doc = lines[j] + "\n" + doc;
      if (l.startsWith("/**") || l.startsWith("/*") || l.startsWith("///")) break;
    }
    if (/@brief|@details/.test(doc)) documented++;
    let hits = 0;
    SEMANTIC_MARKS.forEach(([name, re], idx) => { if (re.test(doc)) { semanticSets[idx]++; hits++; } });
    if (hits < 3) missing.push(`${relPath}:${i + 1} ${m[1]}（提到 ${hits}/5 类语义）`);
  }
  return { classes, documented, semanticSets, missing };
}

let contractClasses = 0, contractDocumented = 0, contractMissing = [];
const contractSemanticTotals = [0, 0, 0, 0, 0];
for (const p of files) {
  const cm = contractDocMetrics(rel(p), fs.readFileSync(p, "utf8"));
  contractClasses += cm.classes;
  contractDocumented += cm.documented;
  cm.semanticSets.forEach((v, i) => { contractSemanticTotals[i] += v; });
  contractMissing.push(...cm.missing);
}
contractMissing.sort((a, b) => (a.match(/(\d)\/5/) || [])[1] === "0" ? -1 : b.match(/(\d)\/5/)?.[1] === "0" ? 1 : a.localeCompare(b));

const entries = files.map((p) => `${rel(p)}=${crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex")}`).sort();
const manifest = crypto.createHash("sha256").update(entries.join("\n")).digest("hex");

// 第三方回调 ABI 登记表（计划 §W0-E 要求扫描排除第三方 ABI，且 §M35/M36 要求逐个登记例外）。
// 每项必须写明对应的上游签名，命中即豁免「超过 3 个参数」判定，但仍在 findings 里逐条输出以便审计。
// 未鉴权变更型管理路由（计划 §M34 与 issues.md E-1 的机检化：修复后必须归 0，防止回归）。
// 判定：管理请求路径文件中不存在任何鉴权检查点时，MakePostRoute 的每一条路由臂都算未鉴权变更端点。
const OPS_PATH = "Include/Prism/Operations/Routes/RouteDispatch.hpp";
const OPS_REQUEST_PATH_FILES = [
  OPS_PATH,
  "Include/Prism/Operations/HttpConnection.hpp",
  "Include/Prism/Operations/Router.hpp",
  "Src/Prism/Application/OperationsStartup.hpp",
];
// 必须是**真实检查构造**，不能是散文里的词：`origin-form`、`{"vary", "origin"}` 这类命中曾让本规则出现假阴性（安全判据最坏的一类 bug）。
// 因此 Origin 必须与同行校验谓词共现；`authoriz` 要求后接非字母（排除 authorizer 之外的歧义拼法无风险）。
const OPS_AUTH_TOKEN_RE = /RequestSecurity::IsAuthorized\s*\(|command.?token|x-admin-token|csrf|verify.?token|authoriz(?:e|ation)\b/i;
const OPS_ORIGIN_CHECK_RE = /[A-Za-z_][A-Za-z0-9_]*Origin[A-Za-z0-9_]*[^\n]{0,60}(?:==|!=|\.empty|Check|Verify|Valid|Mismatch|Missing|Reject)|(?:==|!=|Check|Verify|Valid|Mismatch|Missing|Reject)[^\n]{0,60}[A-Za-z_][A-Za-z0-9_]*Origin[A-Za-z0-9_]*/;
const OPS_ORIGIN_NOUN_RE = /\b(?:Check|Verify|Validate|Match|Matches|Compare|Require)Origin[A-Za-z0-9_]*\b|\b[A-Za-z0-9_]+::(?:Check|Verify|Validate|Match|Compare|Require)Origin\b|\b[A-Za-z0-9_]*Origin(?:Check|Checks|Verify|Verification|Validation|Match|Matches|Matcher|Required)\b/;
// 只在**去注释后的代码**上判定：散文里的 `origin-form`、`{"vary","origin"}` 不得让安全判据闭嘴。
const hasAuthCheckpoint = (rawText) => {
  const code = strip(rawText);
  return OPS_AUTH_TOKEN_RE.test(code) || OPS_ORIGIN_CHECK_RE.test(code) || OPS_ORIGIN_NOUN_RE.test(code);
};
findings.unauthenticatedMutatingRoutes = [];
findings.operationsAuthCheckpointFiles = 0;
if (fs.existsSync(path.join(root, OPS_PATH))) {
  for (const f of OPS_REQUEST_PATH_FILES) {
    const abs = path.join(root, f);
    if (fs.existsSync(abs) && hasAuthCheckpoint(fs.readFileSync(abs, "utf8"))) findings.operationsAuthCheckpointFiles++;
  }
  if (findings.operationsAuthCheckpointFiles === 0) {
    const opsLines = fs.readFileSync(path.join(root, OPS_PATH), "utf8").split("\n");
    const start = opsLines.findIndex((l) => /MakePostRoute/.test(l) && /\(/.test(l) && !/Dispatch\(/.test(l));
    if (start >= 0) {
      let pending = null; // 同一条 if 里可能比较多个段（如 Accounts/{id}/Revoke），取最后一段作端点名
      const flush = () => {
        if (pending) {
          findings.unauthenticatedMutatingRoutes.push(`${OPS_PATH}:${pending.line} POST 臂 "${pending.name}"（管理请求路径 4 个文件内鉴权检查点为 0）`);
          pending = null;
        }
      };
      for (let i = start; i < opsLines.length; i++) {
        if (i > start && /^\s{0,4}(?:\[\[nodiscard\]\]\s*)?(?:inline\s+)?auto\s+[A-Z]/.test(opsLines[i])) break; // 下一个函数
        const m = opsLines[i].match(/Segments\[\dU?\]\s*==\s*"([A-Za-z_]+)"/);
        if (!m) { flush(); continue; }
        const prev = i > 0 ? opsLines[i - 1] : "";
        if (!/Segments\[/.test(prev)) { flush(); pending = { line: i + 1, name: m[1] }; }
        else if (pending) pending = { line: pending.line, name: m[1] };
      }
      flush();
    }
  }
}

const isForeignAbi = (r) => GetPrismAbiContract(r.abiFile, r.name, r.params) !== undefined;
const abiExemptSeen = over2.filter((r) => r.params > 3 && isForeignAbi(r));

const summary = {
  capturedAt: new Date().toISOString(),
  productionHeaders: files.filter((file) => /\.hpp$/i.test(file)).length,
  productionSources: files.filter((file) => /\.cpp$/i.test(file)).length,
  sourceManifestSha256: manifest,
  counts: {
    includeDirection: findings.includeDirection.length,
    forwardDeclCoupling: findings.forwardDeclCoupling.length,
    compatLayer: findings.compatLayer.length,
    duplicateErrorShapes: findings.duplicateErrorShapes.length,
    nonPascalIdentifiers: findings.nonPascalIdentifiers.length,
    missingChineseDoxygen: findings.missingChineseDoxygen.length,
    ternaryFiles: findings.ternaryFiles,
    ternaryExpressions: findings.ternaryCount,
    paramDeclarationsScanned: paramScanned,
    paramsOverTwo: over2.length,
    paramsOverThree: over2.filter((r) => r.params > 3).length,
    paramsOverThreeAbiExempt: abiExemptSeen.length,
    paramsOverThreeViolations: over2.filter((r) => r.params > 3 && !isForeignAbi(r)).length,
    requiredParamsOverTwo: over2.filter((r) => r.required > 2).length,
    contractInterfaceClasses: contractClasses,
    contractDocWithBrief: contractDocumented,
    contractDocUnder3Semantics: contractMissing.length,
    missingNodiscard: nodiscardRows.length,
    abiExemptedFunctions: abiExemptedFns.length,
    abiExemptedTypes: AbiExemptedTypes.length,
    compatNamingExemptions: compatExempted.length,
    unauthenticatedMutatingRoutes: findings.unauthenticatedMutatingRoutes.length,
  },
  contractSemanticsCoverage: Object.fromEntries(SEMANTIC_MARKS.map(([name], i) => [name, `${contractSemanticTotals[i]}/${contractClasses}`])),
  contractMethod: "仅覆盖 Boundary/Transport/Net/Contract/Runtime-Session 模块的 class/struct 前置文档块；关键词命中是**人工审查辅助指标**，不构成契约正确性证明，也不替代层 4/7 的运行验证。",
  paramMethod: "仅统计项目规定的尾随返回类型声明（auto Name(...)）；构造函数、运算符与非 auto 返回形式未纳入，故为下界。required 为不含默认值的参数数。超过 3 参的第三方回调 ABI 由本门禁内的 ForeignAbiRegistry 逐个豁免（file+name 精确登记，命中项在 findings.paramsAbiExempt 里逐条输出，不做正则猜测）；paramsOverThreeViolations 是排除 ABI 后的真违规数。与 AST 门禁共用 PrismAbiContracts.mjs 的唯一精确 file/name/count 上游 ABI 登记。",
};
const fullDump = process.argv.includes("--full");
findings.paramsOverTwo = (fullDump ? over2 : over2.slice(0, 25))
  .map((r) => `${r.file}:${r.line} ${r.name}(${r.params} 参, 必选 ${r.required})${isForeignAbi(r) ? " [ABI 豁免]" : ""}`);
findings.paramsOverTwoTruncated = !fullDump && over2.length > 25;
findings.paramsAbiExempt = abiExemptSeen.map((r) => `${r.file}:${r.line} ${r.name}(${r.params} 参)`);
findings.paramsOverThreeViolations = over2.filter((r) => r.params > 3 && !isForeignAbi(r))
  .map((r) => `${r.file}:${r.line} ${r.name}(${r.params} 参, 必选 ${r.required})`);
findings.abiExemptedFunctions = abiExemptedFns;
findings.abiExemptedTypes = AbiExemptedTypes;
findings.compatNamingExemptions = compatExempted;
findings.missingNodiscard = (fullDump ? nodiscardRows : nodiscardRows.slice(0, 40))
  .map((x) => `${x.file}:${x.line} ${x.name}() -> ${x.type}`);
findings.missingNodiscardTruncated = !fullDump && nodiscardRows.length > 40;
findings.signatureMethod = "**结构性下界指标，用于定位缺口，不是合规证明。** 判定：带尾随 `-> T` 的 `auto Name(...)` 声明且 T 不以 void 开头、也不是 awaitable/task/generator<void>，其声明行未出现 [[nodiscard]]。构造函数、运算符、宏内声明及其他不符合上述签名形态的形式未纳入；扫描范围包括 Include/Prism 与 Src/Prism 下的 .hpp/.cpp。是否真的值得加 [[nodiscard]] 必须逐条人工判断（忽略返回值是否构成错误），不得为把数字做低而批量加标注。曾尝试同时做「经典返回类型」检测，正则实测把构造函数/operator/control flow 全部误报（第一版甚至因分隔符写错而报 0，即伪绿），已撤下：该判据需要真解析器。";
findings.contractDocGaps = fullDump ? contractMissing : contractMissing.slice(0, 40);
console.log(JSON.stringify({ summary, findings }, null, 2));
process.exit(findings.includeDirection.length + findings.forwardDeclCoupling.length + findings.unauthenticatedMutatingRoutes.length === 0 ? 0 : 1);
