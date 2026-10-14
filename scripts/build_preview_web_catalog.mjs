import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';

const Root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const Directory = path.resolve(process.argv[2] ?? '');
const Expected = path.resolve(Root, 'build/Web');
function SamePath(Left, Right) {
    if (process.platform === 'win32') return Left.toLowerCase() === Right.toLowerCase();
    return Left === Right;
}
if (!SamePath(Directory, Expected) || !SamePath(path.resolve(process.cwd()), Root) ||
    !fs.existsSync(path.join(Root, 'Preview/Application/Startup/Start.hpp')))
    throw new Error('资源清单只能生成到执行树已有 build/Web');
const CanonicalRoot = fs.realpathSync(Directory);
const MaxFileBytes = 4 * 1024 * 1024;
const MaxTotalBytes = 64 * 1024 * 1024;
const Types = new Map([
    ['.html', 'text/html; charset=utf-8'], ['.js', 'text/javascript; charset=utf-8'],
    ['.css', 'text/css; charset=utf-8'], ['.svg', 'image/svg+xml'], ['.png', 'image/png'],
    ['.ico', 'image/x-icon'], ['.woff2', 'font/woff2'],
]);

function ValidatePath(Value) {
    if (typeof Value !== 'string' || Value.length > 256 ||
        !/^[A-Za-z0-9._/-]+$/.test(Value) || Value.startsWith('/') ||
        Value.split('/').some(Segment => Segment === '' || Segment === '.' || Segment === '..'))
        throw new Error('构建清单含非法资源路径');
}

function ReadOwnedFile(Value, Limit) {
    ValidatePath(Value);
    const Canonical = fs.realpathSync(path.join(CanonicalRoot, Value));
    const Relative = path.relative(CanonicalRoot, Canonical);
    if (Relative === '' || Relative === '..' || Relative.startsWith(`..${path.sep}`) ||
        path.isAbsolute(Relative)) throw new Error('资源路径越界');
    const Stat = fs.statSync(Canonical);
    if (!Stat.isFile() || Stat.size > Limit) throw new Error('资源容量或文件类型不合规');
    const Bytes = fs.readFileSync(Canonical);
    if (Bytes.length !== Stat.size) throw new Error('资源读取期间变更');
    return Bytes;
}

// 只消费本次 Vite 输出图，旧 hash 文件不因仍在 build 中而重新发布。
const Manifest = JSON.parse(ReadOwnedFile('.vite/manifest.json', 1024 * 1024).toString('utf8'));
if (!Manifest || Array.isArray(Manifest) || typeof Manifest !== 'object')
    throw new Error('Vite 清单形状不正确');
const Entries = Object.values(Manifest);
if (Entries.length === 0 || Entries.length > 512) throw new Error('Vite 清单容量不正确');
const Resources = new Set(['index.html']);
for (const Entry of Entries) {
    if (!Entry || typeof Entry !== 'object' || typeof Entry.file !== 'string')
        throw new Error('Vite 资源描述不正确');
    Resources.add(Entry.file);
    for (const Key of ['css', 'assets']) {
        if (Entry[Key] === undefined) continue;
        if (!Array.isArray(Entry[Key])) throw new Error('Vite 依赖列表不正确');
        for (const Value of Entry[Key]) {
            ValidatePath(Value);
            Resources.add(Value);
        }
    }
}
if (Resources.size > 512) throw new Error('发布资源数量超限');
const Assets = [];
let Total = 0;
for (const Relative of [...Resources].sort()) {
    ValidatePath(Relative);
    const ContentType = Types.get(path.extname(Relative));
    if (!ContentType) throw new Error('发布资源没有明确媒体类型');
    const Bytes = ReadOwnedFile(Relative, MaxFileBytes);
    Total += Bytes.length;
    if (Total > MaxTotalBytes) throw new Error('发布资源总容量超限');
    const Immutable = Relative.startsWith('assets/') && /-[A-Za-z0-9_-]{8,}\.[A-Za-z0-9]+$/.test(Relative);
    Assets.push({path:Relative, content_type:ContentType,
        sha256:crypto.createHash('sha256').update(Bytes).digest('hex'), size:Bytes.length,
        immutable:Immutable});
}
const Bytes = Buffer.from(JSON.stringify({version:1, assets:Assets}, null, 2)+'\n', 'utf8');
const Destination = path.join(CanonicalRoot, 'catalog.json');
if (fs.existsSync(Destination) && fs.lstatSync(Destination).isSymbolicLink())
    throw new Error('禁止覆盖符号链接清单');
fs.writeFileSync(Destination, Bytes);
console.log(JSON.stringify({stage:'CatalogGenerated', directory:CanonicalRoot,
    resources:Assets.length, totalBytes:Total,
    catalogSha256:crypto.createHash('sha256').update(Bytes).digest('hex')}));
