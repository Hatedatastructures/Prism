import { GetPrismAbiContract } from './PrismAbiContracts.mjs';
// 使用 CodeGraph 已安装的 C++ 语法树检查真实函数、lambda 和参数；不构建或改写源码。
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { parseArgs } from 'node:util';

const { values } = parseArgs({ options: {
  repo: { type: 'string', default: path.resolve(import.meta.dirname, '..') },
  'parser-lib': { type: 'string' },
  scope: { type: 'string', multiple: true, default: ['Include/Prism', 'Src/Prism'] },
  report: { type: 'string' },
} });
const require = createRequire(import.meta.url);

function LocateParser() {
  if (values['parser-lib']) return path.resolve(values['parser-lib']);
  const search = [process.cwd()];
  if (process.env.APPDATA) search.push(path.join(process.env.APPDATA, 'npm'));
  const shim = require.resolve('@colbymchenry/codegraph/package.json', { paths: search });
  const runtimeRequire = createRequire(shim);
  const bundle = runtimeRequire.resolve(`@colbymchenry/codegraph-${process.platform}-${process.arch}/package.json`);
  return path.join(path.dirname(bundle), 'lib');
}

function Sources(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(directory, entry.name);
    return entry.isDirectory() ? Sources(full) : /\.(?:hpp|cpp)$/.test(entry.name) ? [full] : [];
  }).sort();
}

function FunctionDeclarator(node) {
  if (!node) return null;
  if (node.type === 'function_declarator') return node;
  for (const child of node.namedChildren) {
    const found = FunctionDeclarator(child);
    if (found) return found;
  }
  return null;
}

function CountParameters(node) {
  const parameters = node.childForFieldName('parameters');
  if (!parameters) return null;
  return parameters.namedChildren.filter(child =>
    child.type === 'parameter_declaration' ||
    child.type === 'optional_parameter_declaration' ||
    child.type === 'variadic_parameter_declaration').length;
}

const parserLib = LocateParser();
const { Parser, Language } = require(path.join(parserLib, 'node_modules/web-tree-sitter/tree-sitter.cjs'));
await Parser.init();
const language = await Language.load(path.join(parserLib, 'dist/extraction/wasm/tree-sitter-cpp.wasm'));
const parser = new Parser();
parser.setLanguage(language);
// 仅重解析语法库误判的空列表默认参数；占位保持所有行、列和字符偏移，源码不改写。
function ParseWithDefaultRecovery(source) {
  let tree = parser.parse(source);
  if (!tree) return { tree, recoveries: [] };
  const edits = [], recoveries = [], pending = [tree.rootNode];
  while (pending.length) {
    const node = pending.pop();
    if (node.type === 'ERROR' && node.parent?.type === 'function_definition' &&
        node.namedChildren.length === 1 && node.namedChildren[0].type === 'init_declarator' &&
        /^[A-Za-z_]\w*\s*\([\s\S]*\)\s*->$/.test(node.text) &&
        source.slice(node.startIndex, node.endIndex) === node.text) {
      const defaults = [...node.text.matchAll(/=\s*\{\s*\}/g)];
      for (const match of defaults) {
        edits.push({ start: node.startIndex + match.index,
          text: match[0].replace('{', '0').replace('}', ' ') });
      }
      if (defaults.length) recoveries.push({ start: node.startPosition.row + 1,
        end: node.endPosition.row + 1, type: node.type,
        reason: 'braced-default-declarator-parser-limit', signature: node.text });
    }
    pending.push(...node.namedChildren);
  }
  if (!edits.length) return { tree, recoveries };
  let parseSource = source;
  for (const edit of edits.sort((left, right) => right.start - left.start)) {
    parseSource = parseSource.slice(0, edit.start) + edit.text +
      parseSource.slice(edit.start + edit.text.length);
  }
  tree.delete();
  tree = parser.parse(parseSource);
  return { tree, recoveries };
}
// 只从宏本身的预处理定义识别 TEST 展开，不跨定义匹配后续普通测试。
function HasComboTestDefinition(tree) {
  const pending = [tree.rootNode];
  while (pending.length) {
    const node = pending.pop();
    if (node.type === 'preproc_function_def' &&
        node.childForFieldName('name')?.text === 'DEFINE_COMBO_TEST' &&
        /\bTEST\s*\(/.test(node.childForFieldName('value')?.text ?? '')) return true;
    pending.push(...node.namedChildren);
  }
  return false;
}
const result = { capturedAt: new Date().toISOString(), parserLib, files: [],
  functions: 0, lambdas: 0, declarations: 0, foreignAbi: [], problems: [], parseErrors: [], parseRecoveries: [] };

const scopes = Array.isArray(values.scope) ? values.scope : [values.scope];
for (const scope of scopes) {
  const scopeDirectory = path.resolve(values.repo, scope);
  if (!fs.existsSync(scopeDirectory)) throw new Error(`检查范围不存在：${scope}`);
  const isTestScope = path.relative(values.repo, scopeDirectory).replaceAll('\\', '/').startsWith('Test/');
  for (const file of Sources(scopeDirectory)) {
    const bytes = fs.readFileSync(file);
    const source = bytes.toString('utf8');
    const relative = path.relative(values.repo, file).replaceAll('\\', '/');
    const lines = source.split('\n').length - (source.endsWith('\n') ? 1 : 0);
    result.files.push({ path: relative, sha256: crypto.createHash('sha256').update(bytes).digest('hex'), lines });
    const extension = path.extname(file).toLowerCase();
    const fileLimit = isTestScope ? 800 : extension === '.hpp' ? 600 : null;
    if (fileLimit !== null && lines > fileLimit)
      result.problems.push({ kind: 'header', path: relative, lines, limit: fileLimit });
    const { tree, recoveries } = ParseWithDefaultRecovery(source);
    if (!tree) throw new Error(`无法解析 ${relative}`);
    result.parseRecoveries.push(...recoveries.map(recovery => ({ path: relative, ...recovery })));
    // 这两个 CPP 的已核生成宏展开为 TEST 函数定义，调用末尾不需要表达式分号。
    const testDefinitionMacro =
      ['Test/Prism/Integration/Layering/CarrierIntegrityTest.cpp',
        'Test/Prism/Integration/Layering/CarrierThroughputTest.cpp'].some(
          file => file.toLowerCase() === relative.toLowerCase()) &&
      HasComboTestDefinition(tree);
    const stack = [tree.rootNode];
    while (stack.length) {
      const node = stack.pop();
      const position = { path: relative, start: node.startPosition.row + 1, end: node.endPosition.row + 1 };
      if (node.type === 'ERROR' || node.isMissing) {
        // 缺失节点必须位于默认参数的列表初始化中；真实语法错误与函数正文不豁免。
        const bracedDefault = node.isMissing && node.type === 'type_identifier' &&
          node.parent?.type === 'compound_literal_expression' &&
          node.parent.namedChildren.length === 2 &&
          node.parent.namedChildren[1].type === 'initializer_list' &&
          node.parent.parent?.type === 'optional_parameter_declaration';
        const macroDefinition = testDefinitionMacro && node.isMissing && node.type === ';' &&
          node.parent?.type === 'expression_statement' &&
          node.parent.namedChildren.length === 1 &&
          node.parent.namedChildren[0].type === 'call_expression' &&
          node.parent.namedChildren[0].childForFieldName('function')?.text === 'DEFINE_COMBO_TEST';
        (bracedDefault || macroDefinition ? result.parseRecoveries : result.parseErrors).push({ ...position, type: node.type,
          reason: bracedDefault ? 'braced-default-argument-parser-limit' :
            macroDefinition ? 'test-definition-macro-parser-limit' : 'unclassified' });
      }
      if (node.type === 'function_definition') {
        ++result.functions;
        const body = node.childForFieldName('body');
        const declarator = FunctionDeclarator(node.childForFieldName('declarator'));
        if (body) {
          const bodyLines = body.endPosition.row - body.startPosition.row + 1;
          if (bodyLines > 120) result.problems.push({ kind: 'function', ...position,
            name: declarator?.childForFieldName('declarator')?.text ?? '<unnamed>', bodyLines, limit: 120 });
        }
      }
      if (node.type === 'lambda_expression') {
        ++result.lambdas;
        const body = node.childForFieldName('body');
        const bodyLines = body ? body.endPosition.row - body.startPosition.row + 1 : 0;
        const spanLines = position.end - position.start + 1;
        if (spanLines > 10) result.problems.push({ kind: 'lambda', ...position, spanLines, bodyLines, limit: 10 });
      }
      if (node.type === 'function_declarator') {
        ++result.declarations;
        const count = CountParameters(node);
        if (count > 3) {
          const name = node.childForFieldName('declarator')?.text ?? '<unnamed>';
          const abi = GetPrismAbiContract(relative, name, count);
          if (abi?.count === count) result.foreignAbi.push({ ...position, name, count,
            contract: abi.contract, signature: source.slice(node.startIndex, node.endIndex) });
          else result.problems.push({ kind: 'parameters', ...position, name, count, limit: 3 });
        }
      }
      // 缺失分号、括号等标点节点没有名字，仍必须作为真实语法错误检查。
      stack.push(...node.namedChildren, ...node.children.filter(child => !child.isNamed && child.isMissing));
    }
    tree.delete();
  }
}
parser.delete();
if (values.report) fs.writeFileSync(path.resolve(values.report), JSON.stringify(result, null, 2) + '\n');
const counts = Object.fromEntries(['header', 'function', 'lambda', 'parameters'].map(kind =>
  [kind, result.problems.filter(problem => problem.kind === kind).length]));
console.log(JSON.stringify({ scope: scopes.join(','), files: result.files.length, functions: result.functions,
  lambdas: result.lambdas, declarations: result.declarations, counts, parseErrors: result.parseErrors.length,
  parseErrorDetails: result.parseErrors,
  foreignAbiContracts: result.foreignAbi.length,
  parseRecoveries: result.parseRecoveries.length,
  bracedDefaultRecoveries: result.parseRecoveries.filter(recovery => recovery.reason.startsWith('braced-default-')).length,
  testDefinitionMacroRecoveries: result.parseRecoveries.filter(recovery => recovery.reason === 'test-definition-macro-parser-limit').length,
  report: values.report ?? null }, null, 2));
if (!values.report && result.problems.length) console.log(JSON.stringify(result.problems, null, 2));
process.exitCode = result.parseErrors.length ? 2 : result.problems.length ? 1 : 0;
