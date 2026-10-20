/** check_prism_reachability.mjs — 只读可达性门禁：CMake↔磁盘双向、链接可达闭包、悬空 include、尺寸与大小写陷阱，输出带源码哈希。 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const root = process.cwd();
const sourceRootPath = path.join(root, "Src");
const normalizedPathKey = (filePath) => path.resolve(filePath).replace(/\\/g, "/").toLowerCase();
const PROD_ROOTS = [path.join(root, "Include", "Prism"), path.join(root, "Src", "Prism")];
const PROD_CMAKE = path.join(root, "Src", "Prism", "CMakeLists.txt");
const TEST_CMAKE = path.join(root, "tests", "Prism", "CMakeLists.txt");
const FINAL_TARGETS = ["Prism"];
const LIMITS = { productionHeaderLines: 600, testCppLines: 800 };

// 行数必须按「内容行」算：`split("\n").length` 对以换行结尾的文件多算一行，于是正好 800 行的测试
// 被报成 801、被判超限。AGENTS.md 的判据是「不超过 800 行」，off-by-one 会制造无意义的拆文件动作。
function countLines(text) {
  const parts = text.split("\n");
  if (parts.length > 0 && parts[parts.length - 1] === "") parts.pop();
  return parts.length;
}

const readIf = (p) => { try { return fs.readFileSync(p, "utf8"); } catch { return null; } };
function bracketArgumentEnd(text, start) {
  const opener = text.slice(start).match(/^\[(=*)\[/);
  if (!opener) return null;
  const closing = `]${opener[1]}]`;
  const closingIndex = text.indexOf(closing, start + opener[0].length);
  return closingIndex === -1 ? text.length : closingIndex + closing.length;
}

function quotedArgumentEnd(text, start) {
  if (text[start] !== '"') return null;
  let index = start + 1;
  while (index < text.length) {
    if (text[index] === "\\") { index += 2; continue; }
    if (text[index] === '"') return index + 1;
    index++;
  }
  return text.length;
}

function stripComments(text) {
  let output = "";
  let index = 0;
  while (index < text.length) {
    const quotedEnd = quotedArgumentEnd(text, index);
    if (quotedEnd !== null) {
      output += text.slice(index, quotedEnd);
      index = quotedEnd;
      continue;
    }
    const bracketEnd = bracketArgumentEnd(text, index);
    if (bracketEnd !== null) {
      output += text.slice(index, bracketEnd);
      index = bracketEnd;
      continue;
    }
    if (text[index] === "\\") {
      output += text.slice(index, index + 2);
      index += 2;
      continue;
    }
    if (text[index] !== "#") {
      output += text[index++];
      continue;
    }

    const bracketComment = bracketArgumentEnd(text, index + 1);
    if (bracketComment !== null) {
      const comment = text.slice(index, bracketComment);
      output += comment.replace(/[^\n]/g, " ");
      index = bracketComment;
      continue;
    }
    while (index < text.length && text[index] !== "\n") {
      output += " ";
      index++;
    }
  }
  return output;
}
const rel = (p) => path.relative(root, p).split(path.sep).join("/");

function listCmds(text) {
  const out = [];
  const recognized = new Map([
    ["add_library", "add_library"], ["add_executable", "add_executable"], ["target_sources", "target_sources"],
    ["target_include_directories", "target_include_directories"], ["target_link_libraries", "target_link_libraries"],
    ["linkprismtargets", "LinkPrismTargets"], ["add_subdirectory", "add_subdirectory"], ["include", "include"],
    ["addprismtest", "AddPrismTest"], ["prismaddinterfacetarget", "PrismAddInterfaceTarget"],
    ["prismaddstatictarget", "PrismAddStaticTarget"], ["set", "set"], ["list", "list"],
    ["set_source_files_properties", "set_source_files_properties"], ["foreach", "foreach"], ["endforeach", "endforeach"],
    ["while", "while"], ["endwhile", "endwhile"],
    ["function", "function"], ["endfunction", "endfunction"], ["macro", "macro"], ["endmacro", "endmacro"],
    ["if", "if"], ["elseif", "elseif"], ["else", "else"], ["endif", "endif"],
  ]);
  let index = 0;
  while (index < text.length) {
    const quotedEnd = quotedArgumentEnd(text, index);
    if (quotedEnd !== null) { index = quotedEnd; continue; }
    const bracketEnd = bracketArgumentEnd(text, index);
    if (bracketEnd !== null) { index = bracketEnd; continue; }
    const name = text.slice(index).match(/^[A-Za-z_][A-Za-z0-9_]*/);
    if (!name) { index++; continue; }
    const commandName = name[0];
    index += commandName.length;
    while (/\s/.test(text[index] ?? "")) index++;
    if (text[index] !== "(") continue;

    const bodyStart = index + 1;
    let depth = 1;
    index = bodyStart;
    while (index < text.length && depth > 0) {
      const commandQuotedEnd = quotedArgumentEnd(text, index);
      if (commandQuotedEnd !== null) { index = commandQuotedEnd; continue; }
      const commandBracketEnd = bracketArgumentEnd(text, index);
      if (commandBracketEnd !== null) { index = commandBracketEnd; continue; }
      if (text[index] === "\\") { index += 2; continue; }
      if (text[index] === "(") depth++;
      else if (text[index] === ")") depth--;
      index++;
    }
    if (depth !== 0) break;
    const canonical = recognized.get(commandName.toLowerCase());
    if (canonical) out.push({ cmd: canonical, body: text.slice(bodyStart, index - 1) });
  }
  return out;
}

function normalizeLinkEntry(token) {
  let value = token.replace(/"/g, "");
  let linkOnly = false;
  for (let depth = 0; depth < 4; depth++) {
    const wrapper = value.match(/^\$<(LINK_ONLY|BUILD_INTERFACE):(.*)>$/);
    if (!wrapper) break;
    if (wrapper[1] === "LINK_ONLY") linkOnly = true;
    value = wrapper[2];
  }
  return { value, linkOnly };
}

/** 展开静态可判定的 foreach(... IN ITEMS ...)；保留 if/endif 等配置分支供联合清单扫描。 */
function expandForeachItems(commands) {
  const expanded = [];
  for (let index = 0; index < commands.length; index++) {
    const current = commands[index];
    if (current.cmd !== "foreach") {
      if (current.cmd !== "endforeach") expanded.push(current);
      continue;
    }

    let depth = 1;
    let end = index + 1;
    for (; end < commands.length && depth > 0; end++) {
      if (commands[end].cmd === "foreach") depth++;
      else if (commands[end].cmd === "endforeach") depth--;
    }
    if (depth !== 0) {
      expanded.push(...commands.slice(index));
      break;
    }
    const endIndex = end - 1;
    const tokens = current.body.split(/[\s;]+/).filter(Boolean).map((token) => token.replace(/"/g, ""));
    const variable = tokens[0];
    const isItems = tokens[1]?.toUpperCase() === "IN" && tokens[2]?.toUpperCase() === "ITEMS";
    if (!variable || !isItems) {
      expanded.push(...commands.slice(index, end));
      index = endIndex;
      continue;
    }

    const body = commands.slice(index + 1, endIndex);
    const variablePattern = new RegExp(`\\$\\{${variable}\\}`, "g");
    for (const value of tokens.slice(3)) {
      const substituted = body.map(({ cmd, body: commandBody }) => ({
        cmd,
        body: commandBody.replace(variablePattern, value),
      }));
      expanded.push(...expandForeachItems(substituted));
    }
    index = endIndex;
  }
  return expanded;
}

function collectCMake(entry, baseDir, acc, variables = new Map(), listDir = path.dirname(entry), inheritedConditions = []) {
  const text = readIf(entry);
  if (text === null) { acc.missingCMake.push(path.relative(root, entry)); return acc; }
  acc.cmakeFiles.add(entry);
  const conditionTokens = [...inheritedConditions];
  const conditionFrames = [];
  const expandDirectoryPrefix = (token) => token
    .replace(/^\$\{(?:CMAKE_SOURCE_DIR|PROJECT_SOURCE_DIR)\}(?=[/\\]|$)/, root.replace(/\\/g, "/"))
    .replace(/^\$\{CMAKE_CURRENT_SOURCE_DIR\}(?=[/\\]|$)/, baseDir.replace(/\\/g, "/"))
    .replace(/^\$\{CMAKE_CURRENT_LIST_DIR\}(?=[/\\]|$)/, listDir.replace(/\\/g, "/"))
    .replace(/\\/g, "/");
  const directoryValues = (token, command, seen = new Set(), reportUnresolved = true) => {
    const raw = token.replace(/"/g, "");
    const buildInterface = raw.match(/^\$<BUILD_INTERFACE:(.*)>$/);
    if (buildInterface) return directoryValues(buildInterface[1], command, seen, reportUnresolved);
    if (/^\$<INSTALL_INTERFACE:.*>$/.test(raw)) return [];
    const clean = expandDirectoryPrefix(raw);
    const variable = clean.match(/^\$\{([A-Za-z_][A-Za-z0-9_]*)\}(.*)$/);
    if (variable) {
      const name = variable[1];
      if (seen.has(name) || !variables.has(name)) {
        if (reportUnresolved) acc.unresolvedCMakeDirectories.push(`${rel(entry)}: ${command} uses unresolved directory expression ${clean}`);
        return [];
      }
      const nested = new Set(seen);
      nested.add(name);
      return variables.get(name).flatMap((value) => directoryValues(`${value}${variable[2]}`, command, nested, reportUnresolved));
    }
    if (clean.includes("$")) {
      if (reportUnresolved) acc.unresolvedCMakeDirectories.push(`${rel(entry)}: ${command} uses unresolved directory expression ${clean}`);
      return [];
    }
    return [clean];
  };
  const assignedValues = (tokens) => tokens.flatMap((token) => {
    const clean = expandDirectoryPrefix(token.replace(/"/g, ""));
    const variable = clean.match(/^\$\{([A-Za-z_][A-Za-z0-9_]*)\}(.*)$/);
    if (!variable || !variables.has(variable[1])) return [clean];
    return variables.get(variable[1]).map((value) => `${value}${variable[2]}`);
  });
  const includeDirectoryMayReferenceProject = (token) => {
    const normalized = token.replace(/\\/g, "/");
    return /\$\{(?:PROJECT_SOURCE_DIR|CMAKE_SOURCE_DIR|CMAKE_CURRENT_SOURCE_DIR|CMAKE_CURRENT_LIST_DIR)\}/i.test(normalized) ||
      /(?:^|\/)\b(?:Include|Src|tests)\b(?:\/|$)/i.test(normalized) ||
      /\$<TARGET_PROPERTY:[^,>]*(?:Prism|TestSupport)/i.test(normalized);
  };
  const norm = (t) => {
    const expanded = expandDirectoryPrefix(t);
    if (/^\$\{/.test(expanded) || (/^[A-Za-z_][A-Za-z0-9_-]*:/.test(expanded) && !/^[A-Za-z]:[\\/]/.test(expanded))) return null;
    return rel(path.resolve(expanded.startsWith(root.replace(/[\\]/g, "/")) || /^[A-Za-z]:/.test(expanded) ? expanded : path.join(baseDir, expanded)));
  };
  const sourceValues = (token, command, seen = new Set()) => {
    const clean = expandDirectoryPrefix(token.replace(/"/g, ""));
    const variable = clean.match(/^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/);
    if (variable) {
      const name = variable[1];
      if (seen.has(name) || !variables.has(name)) {
        acc.unresolvedCMakeSources.push(`${rel(entry)}: ${command} uses unresolved source variable ${clean}`);
        return [];
      }
      const nested = new Set(seen);
      nested.add(name);
      return variables.get(name).flatMap((value) => sourceValues(value, command, nested));
    }
    if (clean.includes("$")) {
      acc.unresolvedCMakeSources.push(`${rel(entry)}: ${command} uses unresolved source expression ${clean}`);
      return [];
    }
    return /\.(hpp|cpp|cxx|cc|h)$/i.test(clean) ? [clean] : [];
  };
  const dir = baseDir;
  const commands = expandForeachItems(listCmds(stripComments(text)));
  for (let commandIndex = 0; commandIndex < commands.length; commandIndex++) {
    const { cmd, body } = commands[commandIndex];
    if (cmd === "function" || cmd === "macro") {
      let definitionDepth = 1;
      while (definitionDepth > 0 && commandIndex + 1 < commands.length) {
        commandIndex++;
        const nestedCommand = commands[commandIndex].cmd;
        if (nestedCommand === "function" || nestedCommand === "macro") definitionDepth++;
        else if (nestedCommand === "endfunction" || nestedCommand === "endmacro") definitionDepth--;
      }
      continue;
    }
    if (cmd === "endfunction" || cmd === "endmacro") continue;
    if (cmd === "foreach" || cmd === "while") {
      let loopDepth = 1;
      while (loopDepth > 0 && commandIndex + 1 < commands.length) {
        commandIndex++;
        const nestedCommand = commands[commandIndex].cmd;
        if (nestedCommand === "foreach" || nestedCommand === "while") loopDepth++;
        else if (nestedCommand === "endforeach" || nestedCommand === "endwhile") loopDepth--;
      }
      continue;
    }
    if (cmd === "endforeach" || cmd === "endwhile") continue;
    if (cmd === "if") {
      const id = `${rel(entry)}#${commandIndex}`;
      const branchValue = literalConditionValue(body);
      const frame = {
        id,
        tokenIndex: conditionTokens.length,
        branch: 0,
        nextBranch: 1,
        previousDefinitelyTrue: branchValue === true,
      };
      conditionFrames.push(frame);
      conditionTokens.push(`${id}:0${branchValue === false ? ":NEVER" : ""}`);
      continue;
    }
    if (cmd === "elseif") {
      const frame = conditionFrames[conditionFrames.length - 1];
      if (frame) {
        const branchValue = literalConditionValue(body);
        frame.branch = frame.nextBranch++;
        const impossible = frame.previousDefinitelyTrue || branchValue === false;
        conditionTokens[frame.tokenIndex] = `${frame.id}:${frame.branch}${impossible ? ":NEVER" : ""}`;
        if (branchValue === true) frame.previousDefinitelyTrue = true;
      }
      continue;
    }
    if (cmd === "else") {
      const frame = conditionFrames[conditionFrames.length - 1];
      if (frame) {
        frame.branch = "else";
        conditionTokens[frame.tokenIndex] = `${frame.id}:else${frame.previousDefinitelyTrue ? ":NEVER" : ""}`;
      }
      continue;
    }
    if (cmd === "endif") {
      const frame = conditionFrames.pop();
      if (frame) conditionTokens.length = frame.tokenIndex;
      continue;
    }
    const toks = body.split(/[\s;]+/).filter(Boolean);
    const name = toks[0];
    if (cmd === "set") {
      variables.set(name, assignedValues(toks.slice(1)));
      continue;
    }
    if (cmd === "list") {
      const operation = name?.toUpperCase();
      const variable = toks[1];
      if (operation === "APPEND" && variable) {
        variables.set(variable, [...(variables.get(variable) ?? []), ...assignedValues(toks.slice(2))]);
      } else if (variable) {
        variables.delete(variable);
      }
      continue;
    }
    if (cmd === "include") {
      const includeToken = name?.replace(/"/g, "") ?? "";
      if (includeToken.includes("PrismLinks.cmake")) {
        for (const includeFile of directoryValues(includeToken, cmd)) {
          const resolved = path.resolve(dir, includeFile);
          collectCMake(resolved, baseDir, acc, variables, path.dirname(resolved), [...conditionTokens]);
        }
      }
      continue;
    }
    if (cmd === "set_source_files_properties") {
      const properties = toks.indexOf("PROPERTIES");
      const language = toks.indexOf("LANGUAGE", properties + 1);
      if (properties !== -1 && language !== -1 && toks[language + 1] === "CXX") {
        for (const src of toks.slice(0, properties)) {
          for (const source of sourceValues(src, cmd)) {
            const p = norm(source);
            if (p) acc.tuRoots.add(p);
          }
        }
      }
      continue;
    }
    if (/^Add(?:Prism|Contract|Production)Test$/.test(cmd)) {
      const src = name?.replace(/"/g, "");
      const sources = src ? sourceValues(src, cmd) : [];
      if (sources.length === 1 && /\.cpp$/i.test(sources[0])) {
        const source = sources[0];
        const tname = path.basename(source).replace(/\.cpp$/i, "");
        acc.targets.add(tname);
        acc.targetTypes.set(tname, "EXECUTABLE");
        recordTargetPath(acc, tname, conditionTokens);
        recordIncludeDirectory(acc, tname, path.join(root, "tests"), "PRIVATE");
        recordIncludeDirectory(acc, tname, path.join(root, "Include"), "PRIVATE");
        const p = norm(source);
        if (p) recordSource(acc, p, tname);
      } else if (sources.length > 1) {
        acc.unresolvedCMakeSources.push(`${rel(entry)}: ${cmd} expects one test source, found ${sources.length}`);
      }
      continue;
    }
    if (cmd === "add_subdirectory") {
      const sub = toks[0]?.replace(/"/g, "");
      if (sub) {
        for (const directory of directoryValues(sub, cmd)) {
          const subdirectory = path.resolve(dir, directory);
          acc.declared.push(rel(subdirectory));
          collectCMake(path.join(subdirectory, "CMakeLists.txt"), subdirectory, acc, new Map(variables), subdirectory,
            [...conditionTokens]);
        }
      }
      continue;
    }
    if (cmd === "add_library" || cmd === "add_executable") {
      const aliasIndex = toks.findIndex((token) => token.toUpperCase() === "ALIAS");
      if (aliasIndex !== -1) {
        acc.targets.add(name);
        acc.targetTypes.set(name, "ALIAS");
        recordTargetPath(acc, name, conditionTokens);
        if (toks[aliasIndex + 1]) acc.aliases.set(name, toks[aliasIndex + 1]);
        continue;
      }
      acc.targets.add(name);
      recordTargetPath(acc, name, conditionTokens);
      const declaration = toks.slice(1).map((token) => token.toUpperCase());
      if (cmd === "add_executable") acc.targetTypes.set(name, "EXECUTABLE");
      else if (declaration.includes("INTERFACE")) acc.targetTypes.set(name, "INTERFACE_LIBRARY");
      else {
        const libraryKind = ["STATIC", "SHARED", "MODULE", "OBJECT"].find((kind) => declaration.includes(kind));
        acc.targetTypes.set(name, libraryKind ? `${libraryKind}_LIBRARY` : "UNKNOWN_LIBRARY");
      }
      for (const token of toks.slice(1)) {
        for (const source of sourceValues(token, cmd)) {
          const p = norm(source);
          if (p) recordSource(acc, p, name);
        }
      }
      continue;
    }
    if (cmd === "PrismAddInterfaceTarget" || cmd === "PrismAddStaticTarget") {
      acc.targets.add(name);
      recordTargetPath(acc, name, conditionTokens);
      if (cmd === "PrismAddInterfaceTarget") {
        acc.targetTypes.set(name, "INTERFACE_LIBRARY");
        recordIncludeDirectory(acc, name, path.join(root, "Include"), "INTERFACE");
      } else {
        acc.targetTypes.set(name, "STATIC_LIBRARY");
        recordIncludeDirectory(acc, name, path.join(root, "Include"), "PUBLIC");
        recordIncludeDirectory(acc, name, path.join(root, "Src"), "PRIVATE");
      }
      let section = "";
      for (const token of toks.slice(1)) {
        const clean = token.replace(/"/g, "");
        if (["HEADERS", "PRIVATE_HEADERS", "SOURCES"].includes(clean)) { section = clean; continue; }
        if (!["HEADERS", "PRIVATE_HEADERS", "SOURCES"].includes(section)) continue;
        for (const value of sourceValues(clean, cmd)) {
          const sourcePath = norm(value);
          if (sourcePath) recordSource(acc, sourcePath, name);
        }
      }
      continue;
    }
    if (cmd === "target_include_directories") {
      let scope = "";
      for (const token of toks.slice(1)) {
        const clean = token.replace(/"/g, "");
        if (["PRIVATE", "PUBLIC", "INTERFACE"].includes(clean)) { scope = clean; continue; }
        if (["SYSTEM", "BEFORE", "AFTER"].includes(clean)) continue;
        if (!scope) scope = acc.targetTypes.get(name) === "INTERFACE_LIBRARY" ? "INTERFACE" : "PRIVATE";
        const reportUnresolved = includeDirectoryMayReferenceProject(clean);
        for (const directory of directoryValues(clean, cmd, new Set(), reportUnresolved)) {
          recordIncludeDirectory(acc, name, path.resolve(baseDir, directory), scope);
        }
      }
      continue;
    }
    if (cmd === "target_sources") {
      const rest = toks.slice(1).filter((t) => !/^(INTERFACE|PUBLIC|PRIVATE|FILE_SET|EXCLUDE_FROM_ALL|BASE_DIRS)$/.test(t));
      for (const r of rest) {
        for (const source of sourceValues(r, cmd)) {
          const p = norm(source);
          if (p) recordSource(acc, p, name);
        }
      }
      continue;
    }
    if (cmd === "target_link_libraries" || cmd === "LinkPrismTargets") {
      const consumer = name;
      const values = toks.slice(1).map((token) => token.replace(/"/g, ""));
      const defaultScope = acc.targetTypes.get(consumer) === "INTERFACE_LIBRARY" ? "INTERFACE" :
        acc.targetTypes.get(consumer) === "EXECUTABLE" ? "PRIVATE" : "PUBLIC";
      let scope = defaultScope;
      let signature = "MODERN";
      let configScope = "GENERAL";
      if (cmd === "LinkPrismTargets" && ["INTERFACE", "PUBLIC", "PRIVATE"].includes(values[0]?.toUpperCase())) {
        scope = values.shift().toUpperCase();
      }
      for (const value of values) {
        const upper = value.toUpperCase();
        if (["INTERFACE", "PUBLIC", "PRIVATE"].includes(upper)) {
          scope = upper;
          signature = "MODERN";
          continue;
        }
        if (upper === "LINK_PUBLIC" || upper === "LINK_PRIVATE") {
          scope = upper === "LINK_PUBLIC" ? "PUBLIC" : "PRIVATE";
          signature = "LEGACY";
          continue;
        }
        if (upper === "LINK_INTERFACE_LIBRARIES") {
          scope = "INTERFACE";
          signature = "LEGACY_INTERFACE";
          continue;
        }
        if (["DEBUG", "OPTIMIZED", "GENERAL"].includes(upper)) { configScope = upper; continue; }
        const normalized = normalizeLinkEntry(value);
        const linkConditions = [...conditionTokens];
        if (configScope !== "GENERAL") linkConditions.push(`CMAKE_LINK_CONFIGURATION:${configScope}`);
        const edges = acc.edges.get(consumer) ?? new Set();
        edges.add(normalized.value);
        acc.edges.set(consumer, edges);
        if (scope !== "INTERFACE") {
          recordLinkPath(acc.directLinkConditionPaths, consumer, normalized.value, linkConditions);
        }
        const propagatesLink = scope !== "PRIVATE" ||
          (signature === "MODERN" && acc.targetTypes.get(consumer) === "STATIC_LIBRARY");
        if (propagatesLink) {
          recordLinkPath(acc.interfaceLinkConditionPaths, consumer, normalized.value, linkConditions);
        }
        if (scope !== "PRIVATE" && !normalized.linkOnly) {
          const interfaceEdges = acc.interfaceEdges.get(consumer) ?? new Set();
          interfaceEdges.add(normalized.value);
          acc.interfaceEdges.set(consumer, interfaceEdges);
        }
        configScope = "GENERAL";
      }
    }
  }
  return acc;
}

function recordSource(acc, sourcePath, target) {
  const owners = acc.sourceOwners.get(sourcePath) ?? new Set();
  owners.add(target);
  acc.sourceOwners.set(sourcePath, owners);
  acc.sources.set(sourcePath, target);
}

function recordTargetPath(acc, target, conditions) {
  const paths = acc.targetConditionPaths.get(target) ?? new Map();
  const path = [...conditions];
  paths.set(JSON.stringify(path), path);
  acc.targetConditionPaths.set(target, paths);
}

function literalConditionValue(expression) {
  const tokens = expression.trim().split(/\s+/).filter(Boolean).map((token) =>
    token.replace(/^(["'])(.*)\1$/, "$2").toUpperCase());
  if (tokens.length === 1) {
    if (["", "0", "OFF", "NO", "N", "FALSE", "IGNORE", "NOTFOUND"].includes(tokens[0]) ||
        tokens[0].endsWith("-NOTFOUND")) return false;
    if (["1", "ON", "YES", "Y", "TRUE"].includes(tokens[0])) return true;
  }
  if (tokens.length === 2 && tokens[0] === "NOT") {
    const operand = literalConditionValue(tokens[1]);
    if (operand !== null) return !operand;
  }
  return null;
}

function recordLinkPath(linkPaths, consumer, dependency, conditions) {
  const dependencies = linkPaths.get(consumer) ?? new Map();
  const paths = dependencies.get(dependency) ?? new Map();
  const path = [...conditions];
  paths.set(JSON.stringify(path), path);
  dependencies.set(dependency, paths);
  linkPaths.set(consumer, dependencies);
}

function recordIncludeDirectory(acc, target, includeDirectory, scope = "PRIVATE") {
  if (!target) return;
  const directory = path.resolve(includeDirectory);
  if (scope !== "INTERFACE") {
    const directories = acc.includeDirectories.get(target) ?? new Set();
    directories.add(directory);
    acc.includeDirectories.set(target, directories);
  }
  if (scope === "PRIVATE") {
    const directories = acc.privateIncludeDirectories.get(target) ?? new Set();
    directories.add(directory);
    acc.privateIncludeDirectories.set(target, directories);
  }
  if (scope === "PUBLIC" || scope === "INTERFACE") {
    const directories = acc.interfaceIncludeDirectories.get(target) ?? new Set();
    directories.add(directory);
    acc.interfaceIncludeDirectories.set(target, directories);
  }
}

const newAcc = () => ({ targets: new Set(), targetTypes: new Map(), sources: new Map(), sourceOwners: new Map(),
  includeDirectories: new Map(), privateIncludeDirectories: new Map(), interfaceIncludeDirectories: new Map(),
  edges: new Map(), interfaceEdges: new Map(), targetConditionPaths: new Map(),
  directLinkConditionPaths: new Map(), interfaceLinkConditionPaths: new Map(), aliases: new Map(),
  tuRoots: new Set(), cmakeFiles: new Set(), declared: [],
  missingCMake: [], unresolvedCMakeSources: [], unresolvedCMakeDirectories: [] });
const prod = collectCMake(PROD_CMAKE, path.join(root, "Src", "Prism"), newAcc());
const test = collectCMake(TEST_CMAKE, path.join(root, "tests", "Prism"), newAcc());
collectCMake(path.join(root, "tests", "TestSupport", "CMakeLists.txt"),
  path.join(root, "tests", "TestSupport"), test);

function walk(dir, filter, acc = []) {
  if (!fs.existsSync(dir)) return acc;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, filter, acc);
    else if (filter(e.name)) acc.push(full);
  }
  return acc;
}

const prodHeaders = PROD_ROOTS.flatMap((directory) => walk(directory, (n) => /\.(hpp|h|cpp|cxx|cc)$/i.test(n)));
const testFiles = walk(path.join(root, "tests", "Prism"), (n) => /\.(hpp|cpp)$/i.test(n));
const testSupportHeaders = walk(path.join(root, "tests", "TestSupport"), (n) => /\.(hpp|h)$/i.test(n));

// 链接闭包：INTERFACE 库沿边传播。
function closure(seeds, edges, aliases = new Map()) {
  const resolveAlias = (target) => {
    const visited = new Set();
    let current = target;
    while (aliases.has(current) && !visited.has(current)) {
      visited.add(current);
      current = aliases.get(current);
    }
    return current;
  };
  const seen = new Set();
  const queue = seeds.map(resolveAlias);
  while (queue.length) {
    const t = resolveAlias(queue.pop());
    if (seen.has(t)) continue;
    seen.add(t);
    for (const dep of edges.get(t) ?? []) queue.push(resolveAlias(dep));
  }
  return seen;
}
const reachableTargets = closure(FINAL_TARGETS, prod.edges, prod.aliases);

// 测试链接闭包由测试 target 的边进入生产 target，再沿静态库边继续展开。
// PRIVATE 静态库依赖仍会作为 LINK_ONLY 接口要求传给最终链接者。
const testDirectLinkConditionPaths = new Map();
const testInterfaceLinkConditionPaths = new Map();
const testTargetConditionPaths = new Map();
const testLinkAliases = new Map([...prod.aliases, ...test.aliases]);
for (const acc of [prod, test]) {
  for (const [target, paths] of acc.targetConditionPaths) {
    const combined = testTargetConditionPaths.get(target) ?? new Map();
    for (const [key, path] of paths) combined.set(key, path);
    testTargetConditionPaths.set(target, combined);
  }
  for (const [target, dependencies] of acc.directLinkConditionPaths) {
    const combinedDependencies = testDirectLinkConditionPaths.get(target) ?? new Map();
    for (const [dependency, paths] of dependencies) {
      const combinedPaths = combinedDependencies.get(dependency) ?? new Map();
      for (const [key, path] of paths) combinedPaths.set(key, path);
      combinedDependencies.set(dependency, combinedPaths);
    }
    testDirectLinkConditionPaths.set(target, combinedDependencies);
  }
  for (const [target, dependencies] of acc.interfaceLinkConditionPaths) {
    const combinedDependencies = testInterfaceLinkConditionPaths.get(target) ?? new Map();
    for (const [dependency, paths] of dependencies) {
      const combinedPaths = combinedDependencies.get(dependency) ?? new Map();
      for (const [key, path] of paths) combinedPaths.set(key, path);
      combinedDependencies.set(dependency, combinedPaths);
    }
    testInterfaceLinkConditionPaths.set(target, combinedDependencies);
  }
}

function canonicalTarget(target) {
  const seen = new Set();
  let current = target;
  while (testLinkAliases.has(current) && !seen.has(current)) {
    seen.add(current);
    current = testLinkAliases.get(current);
  }
  return current;
}

function targetAvailableUnder(target, conditions) {
  const paths = testTargetConditionPaths.get(target);
  if (!paths) return true;
  const conditionSet = new Set(conditions);
  return [...paths.values()].some((path) => !path.some((condition) => condition.endsWith(":NEVER")) &&
    path.every((condition) => conditionSet.has(condition)));
}

function linkClosureForConditions(target, conditions) {
  const conditionSet = new Set(conditions);
  const seen = new Set();
  const queue = [{ target: canonicalTarget(target), direct: true }];
  while (queue.length > 0) {
    const entry = queue.pop();
    const current = canonicalTarget(entry.target);
    if (seen.has(current) || !targetAvailableUnder(current, conditions)) continue;
    seen.add(current);
    const linkPaths = entry.direct ? testDirectLinkConditionPaths : testInterfaceLinkConditionPaths;
    for (const [dependency, paths] of linkPaths.get(current) ?? []) {
      const applies = [...paths.values()].some((path) =>
        path.every((condition) => conditionSet.has(condition)));
      if (!applies) continue;
      if (!targetAvailableUnder(dependency, conditions)) continue;
      const resolved = canonicalTarget(dependency);
      if (targetAvailableUnder(resolved, conditions)) queue.push({ target: resolved, direct: false });
    }
  }
  return seen;
}

function testTargetLinksOwner(target, owner) {
  const ownerType = prod.targetTypes.get(owner);
  if (!prod.targets.has(owner) || ownerType === undefined || ownerType === "ALIAS") return false;
  const paths = testTargetConditionPaths.get(target);
  const conditions = paths?.size ? [...paths.values()] : [[]];
  const resolvedOwner = canonicalTarget(owner);
  return conditions.every((path) => linkClosureForConditions(target, path).has(resolvedOwner));
}
const missingTestOwnerLinkSeen = new Set();

function resolveIncludeDirectories(acc, inheritedExports = new Map(), inheritedAliases = new Map()) {
  const aliases = new Map([...inheritedAliases, ...acc.aliases]);
  const resolveAlias = (target) => {
    const visited = new Set();
    let current = target;
    while (aliases.has(current) && !visited.has(current)) {
      visited.add(current);
      current = aliases.get(current);
    }
    return current;
  };
  const exported = new Map([...acc.targets].map((target) => [
    target, new Set(acc.interfaceIncludeDirectories.get(target) ?? []),
  ]));
  const exportedBy = (target) => {
    const resolved = resolveAlias(target);
    return exported.get(resolved) ?? inheritedExports.get(resolved) ?? new Set();
  };
  let changed = true;
  while (changed) {
    changed = false;
    for (const target of acc.targets) {
      const directories = exported.get(target);
      for (const dependency of acc.interfaceEdges.get(target) ?? []) {
        for (const directory of exportedBy(dependency)) {
          if (directories.has(directory)) continue;
          directories.add(directory);
          changed = true;
        }
      }
    }
  }

  const compile = new Map();
  for (const target of acc.targets) {
    const directories = new Set(acc.includeDirectories.get(target) ?? []);
    if (acc.targetTypes.get(target) === "INTERFACE_LIBRARY") {
      for (const directory of exported.get(target) ?? []) directories.add(directory);
    }
    for (const dependency of acc.edges.get(target) ?? []) {
      for (const directory of exportedBy(dependency)) directories.add(directory);
    }
    compile.set(target, directories);
  }
  return { compile, exported };
}
const prodIncludeDirectories = resolveIncludeDirectories(prod);
const testIncludeDirectories = resolveIncludeDirectories(test, prodIncludeDirectories.exported, prod.aliases);
// target_sources 记录到的是文件所属 target；文件可达 = 其 target 在闭包内。
const registered = new Map(prod.sources);

const problems = { missingRequiredRoots: [], missingCMake: [...new Set([...prod.missingCMake, ...test.missingCMake])], unresolvedCMakeSources: [...new Set([...prod.unresolvedCMakeSources, ...test.unresolvedCMakeSources])], unresolvedCMakeDirectories: [...new Set([...prod.unresolvedCMakeDirectories, ...test.unresolvedCMakeDirectories])], registeredMissing: [], caseMismatch: [], diskUnregistered: [], duplicateProductionSourceOwners: [], duplicateTestSourceOwners: [], unknownTestSourceTargets: [], unregisteredTestSources: [], unreachableRegistered: [], missingTestOwnerLinks: [], privateSourceIncludes: [], publicSourceIncludeDirectories: [], danglingIncludes: { production: [], registeredTest: [], unregisteredTest: [] }, tuRootIncluders: [], sourceOutsideSrc: [], oversize: { production: [], test: [] }, caseCollisions: [] };

for (const [acc, includeDirectories] of [[prod, prodIncludeDirectories], [test, testIncludeDirectories]]) {
  for (const [target, directories] of includeDirectories.exported) {
    if ([...directories].some((directory) => normalizedPathKey(directory) === normalizedPathKey(sourceRootPath))) {
      problems.publicSourceIncludeDirectories.push(`${target} exports the private Src include root`);
    }
  }
}

const requiredFiles = [PROD_CMAKE, TEST_CMAKE];
const requiredDirectories = [...PROD_ROOTS, path.join(root, "tests", "Prism")];
for (const p of requiredFiles) {
  if (!fs.existsSync(p) || !fs.statSync(p).isFile()) problems.missingRequiredRoots.push(rel(p));
}
for (const p of requiredDirectories) {
  if (!fs.existsSync(p) || !fs.statSync(p).isDirectory()) problems.missingRequiredRoots.push(rel(p));
}

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
  if ((r.endsWith(".cpp") || r.endsWith(".cxx") || r.endsWith(".cc")) && r.startsWith("Include/Prism/")) {
    problems.sourceOutsideSrc.push(r);
  }
  const lines = countLines(fs.readFileSync(p, "utf8"));
  if (/\.hpp$/i.test(r) && lines > LIMITS.productionHeaderLines) problems.oversize.production.push(`${r}: ${lines}`);
}
for (const [relPath, owners] of prod.sourceOwners) {
  if (/^Src\/Prism\/.*\.(?:cpp|cxx|cc)$/i.test(relPath) && owners.size > 1) {
    problems.duplicateProductionSourceOwners.push(`${relPath} (targets ${[...owners].sort().join(", ")})`);
  }
}

// 注册判定必须大小写折叠：磁盘目录名与 CMake 声明不一致时（见 caseMismatch），
// 精确匹配会把已登记测试误分成“未登记”，从而掩盖真实的编译阻塞。
const registeredTests = new Map();
for (const relPath of test.sources.keys()) registeredTests.set(relPath.toLowerCase(), relPath);
const testOwnersByCaseFold = new Map();
for (const [relPath, owners] of test.sourceOwners) {
  const key = relPath.toLowerCase();
  const combined = testOwnersByCaseFold.get(key) ?? new Set();
  for (const owner of owners) combined.add(owner);
  testOwnersByCaseFold.set(key, combined);
  const unknownOwners = [...owners].filter((owner) => !test.targets.has(owner));
  if (unknownOwners.length > 0) {
    problems.unknownTestSourceTargets.push(`${relPath} (unknown targets ${unknownOwners.sort().join(", ")})`);
  }
}
for (const [relPath, target] of test.sources) {
  if (!fs.existsSync(path.join(root, relPath))) problems.registeredMissing.push(`${relPath} (test target ${target})`);
}
for (const p of testFiles) {
  const r = rel(p);
  if (!/\.(cpp)$/i.test(r)) continue;
  const source = fs.readFileSync(p, "utf8");
  if (/\b(?:TEST|TEST_F|TEST_P|TYPED_TEST|TYPED_TEST_P)\s*\(/.test(source)) {
    const owners = testOwnersByCaseFold.get(r.toLowerCase()) ?? new Set();
    if (owners.size > 1) {
      problems.duplicateTestSourceOwners.push(`${r} (targets ${[...owners].sort().join(", ")})`);
    }
  }
  if (!registeredTests.has(r.toLowerCase()) &&
      !/^tests\/Prism\/(?:Performance|Stress)\//i.test(r)) {
    problems.unregisteredTestSources.push(r);
  }
  const lines = countLines(fs.readFileSync(p, "utf8"));
  if (lines > LIMITS.testCppLines) problems.oversize.test.push(`${r}: ${lines}`);
}

// 悬空 include：解析公共 Include/ 与私有 Src/ 的 <Prism/...> 路径。
const includeRe = /#\s*include\s*([<"])([^">]+)[>"]/g;
// LANGUAGE CXX 头文件承载唯一翻译单元，生产头和测试不得再 include 它。
// 同时解析根路径和相对路径，避免只检查 Prism/... 而漏掉局部 include。
const tuRootsByPath = new Map([...prod.tuRoots].map((p) => [path.resolve(root, p).toLowerCase(), p]));
const testHeaderOwners = new Map();

function isWithinSourceRoot(filePath) {
  const relative = path.relative(sourceRootPath, filePath);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function isProjectInclude(kind, spec) {
  const normalizedSpec = spec.replace(/\\/g, "/").toLowerCase();
  return /^(?:prism|tests|testsupport)\//.test(normalizedSpec) ||
    (kind === '"' && /\.(?:h|hpp)$/i.test(spec));
}

function includeCandidates(filePath, kind, spec, target, isTest) {
  const candidates = [];
  if (kind === '"') candidates.push(path.resolve(path.dirname(filePath), spec));
  const acc = isTest ? test : prod;
  const includeDirectories = (isTest ? testIncludeDirectories : prodIncludeDirectories).compile.get(target) ?? new Set();
  const privateRootKey = normalizedPathKey(sourceRootPath);
  const canUsePrivateRoot = isTest || rel(filePath).startsWith("Src/Prism/");
  for (const includeDirectory of includeDirectories) {
    if (normalizedPathKey(includeDirectory) === privateRootKey &&
        (!canUsePrivateRoot || !hasPrivateSourceRoot(acc, target))) continue;
    candidates.push(path.resolve(includeDirectory, spec));
  }
  return candidates;
}

function hasPrivateSourceRoot(acc, target) {
  return [...(acc.privateIncludeDirectories.get(target) ?? [])]
    .some((directory) => normalizedPathKey(directory) === normalizedPathKey(sourceRootPath));
}

function resolveProjectInclude(filePath, kind, spec, target, isTest) {
  for (const candidate of includeCandidates(filePath, kind, spec, target, isTest)) {
    const status = exactPathStatus(candidate);
    if (status.exists && status.exact) return candidate;
  }
  return null;
}
function collectTestHeaderOwners(filePath, target, visited) {
  const key = normalizedPathKey(filePath);
  const owners = testHeaderOwners.get(key) ?? new Set();
  owners.add(target);
  testHeaderOwners.set(key, owners);
  const visitKey = `${key}|${target}`;
  if (visited.has(visitKey)) return;
  visited.add(visitKey);

  const fileText = readIf(filePath);
  if (fileText === null) return;
  const code = fileText.replace(/\/\*[\s\S]*?\*\//g, (comment) => comment.replace(/[^\n]/g, " "))
    .replace(/^[ \t]*\/\/[^\n]*/gm, "");
  includeRe.lastIndex = 0;
  let match;
  while ((match = includeRe.exec(code))) {
    const kind = match[1];
    const spec = match[2];
    if (!isProjectInclude(kind, spec)) continue;
    const included = resolveProjectInclude(filePath, kind, spec, target, true);
    if (included && /^tests\/(?:Prism|TestSupport)\//i.test(rel(included)) && /\.(?:h|hpp)$/i.test(included)) {
      collectTestHeaderOwners(included, target, visited);
    }
  }
}

for (const filePath of testFiles) {
  const relative = rel(filePath);
  if (!/\.cpp$/i.test(relative) || /^tests\/Prism\/(?:Performance|Stress)\//i.test(relative)) continue;
  const owners = test.sourceOwners.get(relative);
  if (!owners) continue;
  for (const target of owners) collectTestHeaderOwners(filePath, target, new Set());
}

// 多协议 TestSupport umbrella 会声明多组可选 inline helper；只按 include 文本会要求每个消费方
// 链接所有模块。单一 production owner 的 support header 可精确归属；单个公头的多 owner 逐个验证。
const unambiguousTestSupportOwnerChecks = new Set();
const ambiguousTestSupportOwnerSkips = [];
for (const filePath of testSupportHeaders) {
  const consumers = testHeaderOwners.get(normalizedPathKey(filePath)) ?? new Set();
  for (const target of consumers) {
    const fileText = readIf(filePath);
    if (fileText === null) continue;
    const code = fileText.replace(/\/\*[\s\S]*?\*\//g, (comment) => comment.replace(/[^\n]/g, " "))
      .replace(/^[ \t]*\/\/[^\n]*/gm, "");
    const ownerTargets = new Set();
    const ownerHeaders = new Set();
    includeRe.lastIndex = 0;
    let match;
    while ((match = includeRe.exec(code))) {
      if (!isProjectInclude(match[1], match[2])) continue;
      const included = resolveProjectInclude(filePath, match[1], match[2], target, true);
      if (!included || !/^Include\/Prism\//i.test(rel(included))) continue;
      const owners = prod.sourceOwners.get(rel(included)) ?? new Set();
      if (owners.size === 0) continue;
      ownerHeaders.add(rel(included));
      for (const owner of owners) ownerTargets.add(owner);
    }
    if (ownerTargets.size === 1 || ownerHeaders.size === 1) {
      unambiguousTestSupportOwnerChecks.add(`${normalizedPathKey(filePath)}|${target}`);
    } else if (ownerTargets.size > 1 && ownerHeaders.size > 1) {
      ambiguousTestSupportOwnerSkips.push({
        header: rel(filePath),
        consumerTarget: target,
        owners: [...ownerTargets].sort(),
        publicHeaders: [...ownerHeaders].sort(),
      });
    }
  }
}

function ownersForInclude(filePath, isTest) {
  if (!isTest) return [...(prod.sourceOwners.get(rel(filePath)) ?? [])];
  const consumers = testHeaderOwners.get(normalizedPathKey(filePath)) ?? new Set();
  if (consumers.size > 0) return [...consumers];
  return [...(test.sourceOwners.get(rel(filePath)) ?? [])]
    .filter((target) => test.targetTypes.get(target) !== "INTERFACE_LIBRARY");
}

function danglingOf(fileText, filePath, isTest) {
  const out = [];
  if (fileText === null) return out;
  // 去掉块注释与行注释，避免注释里的示例被当成真实 include。
  const code = fileText.replace(/\/\*[\s\S]*?\*\//g, (comment) => comment.replace(/[^\n]/g, " "))
    .replace(/^[ \t]*\/\/[^\n]*/gm, "");
  const owners = ownersForInclude(filePath, isTest);
  let m;
  includeRe.lastIndex = 0;
  while ((m = includeRe.exec(code))) {
    const kind = m[1];
    const spec = m[2];
    const includedRoot = [path.resolve(root, spec), path.resolve(path.dirname(filePath), spec)]
      .map((p) => tuRootsByPath.get(p.toLowerCase())).find((p) => p !== undefined);
    if (includedRoot !== undefined) {
      const line = code.slice(0, m.index).split("\n").length;
      problems.tuRootIncluders.push(`${rel(filePath)}:${line} -> ${includedRoot}`);
    }
    if (!isProjectInclude(kind, spec)) continue;
    for (const target of owners) {
      const candidates = includeCandidates(filePath, kind, spec, target, isTest);
      let found = false;
      let includedPath = null;
      for (const candidate of candidates) {
        const status = exactPathStatus(candidate);
        if (status.exists && !status.exact) {
          problems.caseMismatch.push(`include case mismatch: ${rel(filePath)} -> ${spec}`);
          continue;
        }
        if (status.exists) { found = true; includedPath = candidate; break; }
      }

      const testFile = rel(filePath);
      const shouldCheckTestOwner = isTest &&
        (/^tests\/Prism\//i.test(testFile) || unambiguousTestSupportOwnerChecks.has(`${normalizedPathKey(filePath)}|${target}`));
      if (shouldCheckTestOwner && found && includedPath &&
          /^Include\/Prism\//i.test(rel(includedPath))) {
        const headerOwners = prod.sourceOwners.get(rel(includedPath)) ?? new Set();
        for (const owner of headerOwners) {
          if (testTargetLinksOwner(target, owner)) continue;
          const ownerType = prod.targetTypes.get(owner);
          const ownerKind = !prod.targets.has(owner) || ownerType === undefined || ownerType === "ALIAS" ?
            "undeclared" : ownerType === "INTERFACE_LIBRARY" ? "INTERFACE" : "compiled";
          const detail = ownerKind === "undeclared" ? `owner ${owner} is not a declared production target` :
            `test target ${target} does not link public header owner ${owner} [${ownerKind}]`;
          const finding = `${rel(filePath)} -> ${rel(includedPath)} (${detail})`;
          if (missingTestOwnerLinkSeen.has(finding)) continue;
          missingTestOwnerLinkSeen.add(finding);
          problems.missingTestOwnerLinks.push(finding);
        }
      }

      const privateCandidate = /^prism\//i.test(spec) ? path.join(sourceRootPath, spec.replace(/^prism\//i, "Prism/")) :
        (kind === '"' ? path.resolve(path.dirname(filePath), spec) : "");
      if (privateCandidate && isWithinSourceRoot(privateCandidate)) {
        const status = exactPathStatus(privateCandidate);
        const hasPrivateRoot = hasPrivateSourceRoot(isTest ? test : prod, target);
        const canUsePrivateRoot = isTest || rel(filePath).startsWith("Src/Prism/");
        if (status.exists && status.exact && (!canUsePrivateRoot || !hasPrivateRoot)) {
          problems.privateSourceIncludes.push(`${rel(filePath)} -> ${spec} (target ${target} lacks the required private Src boundary)`);
        }
      }
      if (!found) out.push(spec);
    }
  }
  return out;
}

function exactPathStatus(candidate) {
  const relative = path.relative(root, candidate);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    return { exists: fs.existsSync(candidate), exact: true };
  }
  let current = root;
  let exact = true;
  for (const part of relative.split(path.sep).filter(Boolean)) {
    let entries = [];
    try { entries = fs.readdirSync(current); } catch { return { exists: false, exact }; }
    const exactEntry = entries.find((entry) => entry === part);
    const matchedEntry = exactEntry ?? entries.find((entry) => entry.toLowerCase() === part.toLowerCase());
    if (!matchedEntry) return { exists: false, exact };
    if (!exactEntry) exact = false;
    current = path.join(current, matchedEntry);
  }
  return { exists: true, exact };
}
for (const p of prodHeaders) {
  const d = danglingOf(readIf(p), p, false);
  for (const spec of d) problems.danglingIncludes.production.push(`${rel(p)} -> ${spec}`);
}
for (const p of testFiles) {
  const r = rel(p);
  if (/^tests\/Prism\/(?:Performance|Stress)\//i.test(r)) continue;
  const d = danglingOf(readIf(p), p, true);
  for (const spec of d) {
    const declared = registeredTests.get(r.toLowerCase());
    if (declared !== undefined) {
      const note = declared === r ? "" : ` (CMake 声明为 ${declared})`;
      problems.danglingIncludes.registeredTest.push(`${r} -> ${spec}${note}`);
    } else problems.danglingIncludes.unregisteredTest.push(`${r} -> ${spec}`);
  }
}
for (const p of testSupportHeaders) {
  const d = danglingOf(readIf(p), p, true);
  for (const spec of d) problems.danglingIncludes.unregisteredTest.push(`${rel(p)} -> ${spec}`);
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
walkDeclared("tests/Prism");
walkDeclared("Src/Prism");
problems.secondOrderCaseDivergence = [...secondOrder.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, n]) => `refs=${n}  ${k}`);

const scannerPath = path.join(root, "scripts", "check_prism_reachability.mjs");
const scanned = [...new Set([...prodHeaders, ...testFiles, ...prod.cmakeFiles, ...test.cmakeFiles,
  ...testSupportHeaders,
  ...(fs.existsSync(scannerPath) ? [scannerPath] : [])])];
const digest = crypto.createHash("sha256").update(scanned.sort().map((p) => `${rel(p)}=${crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex")}`).join("\n")).digest("hex");

const conditionEvaluation = {
  supportedFalseLiterals: ["FALSE", "0", "OFF", "NO", "N", "IGNORE", "NOTFOUND", "<name>-NOTFOUND"],
  supportedTrueLiterals: ["TRUE", "1", "ON", "YES", "Y"],
  supportedUnary: "NOT <one supported literal>",
  otherExpressions: "Not evaluated; conservatively treated as potentially reachable.",
};

const summary = {
  capturedAt: new Date().toISOString(),
  sourceManifestSha256: digest,
  translationUnitRoots: [...prod.tuRoots].sort(),
  counts: Object.fromEntries(Object.entries(problems).map(([k, v]) => [k, Array.isArray(v) ? v.length : Object.keys(v).reduce((n, kk) => n + v[kk].length, 0)])),
  testOwnerLinkCoverage: {
    status: ambiguousTestSupportOwnerSkips.length === 0 ? "complete" : "partial",
    ambiguousTestSupportSkipCount: ambiguousTestSupportOwnerSkips.length,
    ambiguousTestSupportSkips: ambiguousTestSupportOwnerSkips.sort((left, right) =>
      left.header.localeCompare(right.header) || left.consumerTarget.localeCompare(right.consumerTarget)),
  },
  conditionEvaluation,
  reachableTargets: [...reachableTargets].sort(),
  unreachableTargetList: [...prod.targets].filter((t) => !reachableTargets.has(t)).sort(),
  missingCMake: prod.missingCMake.concat(test.missingCMake),
};
console.log(JSON.stringify({ summary, problems }, null, 2));
const total = Object.values(summary.counts).reduce((a, b) => a + b, 0);
process.exit(total === 0 ? 0 : 1);
