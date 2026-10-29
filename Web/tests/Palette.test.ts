/**
 * @file Palette.test.ts
 * @brief 验证主题色的唯一来源、CSS 声明和浅深主题对比度。
 * @see https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html
 */
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import test from 'node:test';
import { dirname, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import postcss, { type Root, type Rule } from 'postcss';

type RgbColor = Readonly<{ Red: number; Green: number; Blue: number }>;
type ThemePalette = Readonly<{ Name: string; Properties: ReadonlyMap<string, string> }>;
type ContrastRequirement = Readonly<{ Foreground: string; Background: string; Minimum: number }>;

const TestDirectory = dirname(fileURLToPath(import.meta.url));
const StylesDirectory = resolve(TestDirectory, '../src/Styles');
const PalettePath = resolve(StylesDirectory, 'Palette.css');
const ThemePath = resolve(StylesDirectory, 'Theme.css');
const DarkThemeSelector = ":root[data-theme='dark']";
const ForbiddenColorLiteral = /#(?:[\da-f]{3,4}|[\da-f]{6}|[\da-f]{8})\b|\b(?:rgba?|hsla?|oklch|lab)\s*\(/i;
const PaletteColorSeed = /#(?:[\da-f]{3,4}|[\da-f]{6}|[\da-f]{8})\b|\b(?:rgba?|hsla?|oklch|lab|color-mix)\s*\(|\b(?:transparent|currentcolor)\b/i;
const VariableReference = /var\(\s*(--[\w-]+)/gi;

/** @brief 递归收集目录中的 CSS 文件并按路径排序。 */
async function FindCssFiles(Directory: string): Promise<string[]> {
    const Files: string[] = [];
    for (const Entry of await readdir(Directory, { withFileTypes: true })) {
        const EntryPath = join(Directory, Entry.name);
        if (Entry.isDirectory()) Files.push(...await FindCssFiles(EntryPath));
        else if (Entry.isFile() && extname(Entry.name).toLowerCase() === '.css') Files.push(EntryPath);
    }
    return Files.sort();
}

/** @brief 读取并解析 CSS AST，解析失败时保留具体文件路径。 */
async function ReadStylesheet(Path: string): Promise<Root> {
    return postcss.parse(await readFile(Path, 'utf8'), { from: Path });
}

/** @brief 收集指定主题规则中的自定义属性及其级联覆盖值。 */
function ReadCustomProperties(RuleValue: Rule): Map<string, string> {
    const Properties = new Map<string, string>();
    RuleValue.walkDecls(Declaration => {
        if (Declaration.prop.startsWith('--')) Properties.set(Declaration.prop, Declaration.value.trim());
    });
    return Properties;
}

/** @brief 从色板字面量和 var 别名推导所有颜色 token 名称。 */
function ReadPaletteColorTokens(Rules: readonly Rule[]): Set<string> {
    const ValuesByToken = new Map<string, string[]>();
    for (const RuleValue of Rules) {
        RuleValue.walkDecls(Declaration => {
            if (!Declaration.prop.startsWith('--')) return;
            const Values = ValuesByToken.get(Declaration.prop) ?? [];
            Values.push(Declaration.value.trim());
            ValuesByToken.set(Declaration.prop, Values);
        });
    }

    const ColorTokens = new Set<string>();
    for (const [Token, Values] of ValuesByToken) {
        if (Values.some(Value => PaletteColorSeed.test(Value))) ColorTokens.add(Token);
    }

    let AddedToken = true;
    while (AddedToken) {
        AddedToken = false;
        for (const [Token, Values] of ValuesByToken) {
            if (ColorTokens.has(Token)) continue;
            if (!Values.some(Value => Array.from(Value.matchAll(VariableReference))
                .some(Match => ColorTokens.has(Match[1] ?? '')))) continue;
            ColorTokens.add(Token);
            AddedToken = true;
        }
    }
    return ColorTokens;
}

/** @brief 展开十六进制或纯 var 别名；遇到透明度、循环或其他语法时明确失败。 */
function ResolveColor(Value: string, Properties: ReadonlyMap<string, string>, Trail = new Set<string>()): RgbColor {
    const Normalized = Value.trim();
    const Alias = /^var\(\s*(--[\w-]+)\s*\)$/i.exec(Normalized);
    if (Alias) {
        const Token = Alias[1];
        if (!Token) throw new Error(`颜色别名无效：${Normalized}`);
        if (Trail.has(Token)) throw new Error(`颜色别名存在循环：${[...Trail, Token].join(' -> ')}`);
        const Target = Properties.get(Token);
        if (Target === undefined) throw new Error(`颜色别名未定义：${Token}`);
        Trail.add(Token);
        return ResolveColor(Target, Properties, Trail);
    }

    const HexMatch = /^#([\da-f]{3}|[\da-f]{4}|[\da-f]{6}|[\da-f]{8})$/i.exec(Normalized);
    if (!HexMatch?.[1]) throw new Error(`不支持的主题颜色表达式：${Normalized}`);
    const Hex = HexMatch[1];
    const ShortHex = Hex.length === 3 || Hex.length === 4;
    const ComponentLength = ShortHex ? 1 : 2;
    const Components = Array.from({ length: Hex.length / ComponentLength }, (_, Index) => {
        const Part = Hex.slice(Index * ComponentLength, (Index + 1) * ComponentLength);
        return Number.parseInt(ShortHex ? Part + Part : Part, 16);
    });
    const HasAlpha = Hex.length === 4 || Hex.length === 8;
    const Alpha = HasAlpha ? Components[3] : 255;
    if (Alpha !== 255) throw new Error(`对比度颜色必须完全不透明：${Normalized}`);
    return { Red: Components[0] ?? 0, Green: Components[1] ?? 0, Blue: Components[2] ?? 0 };
}

/**
 * @brief 按 W3C WCAG 2.2 的 sRGB 公式计算相对亮度。
 * @details 通道先按 0.04045 分段线性化，再使用 0.2126/0.7152/0.0722 加权。
 */
function RelativeLuminance(Color: RgbColor): number {
    const Linearize = (Channel: number): number => {
        const Srgb = Channel / 255;
        return Srgb <= 0.04045 ? Srgb / 12.92 : ((Srgb + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * Linearize(Color.Red) + 0.7152 * Linearize(Color.Green) + 0.0722 * Linearize(Color.Blue);
}

/** @brief 按较亮与较暗相对亮度之比计算未舍入的 WCAG 对比度。 */
function ContrastRatio(Foreground: RgbColor, Background: RgbColor): number {
    const ForegroundLuminance = RelativeLuminance(Foreground);
    const BackgroundLuminance = RelativeLuminance(Background);
    const Brighter = Math.max(ForegroundLuminance, BackgroundLuminance);
    const Darker = Math.min(ForegroundLuminance, BackgroundLuminance);
    return (Brighter + 0.05) / (Darker + 0.05);
}

/** @brief 检查有领域含义的主题与颜色配对，不舍入比例。 */
function AssertContrast(Theme: ThemePalette, Requirement: ContrastRequirement): void {
    const ForegroundValue = Theme.Properties.get(Requirement.Foreground);
    const BackgroundValue = Theme.Properties.get(Requirement.Background);
    if (ForegroundValue === undefined) throw new Error(`${Theme.Name} 色板缺少 token ${Requirement.Foreground}`);
    if (BackgroundValue === undefined) throw new Error(`${Theme.Name} 色板缺少 token ${Requirement.Background}`);
    const Ratio = ContrastRatio(ResolveColor(ForegroundValue, Theme.Properties), ResolveColor(BackgroundValue, Theme.Properties));
    assert.ok(Ratio >= Requirement.Minimum,
        `${Theme.Name}: ${Requirement.Foreground} / ${Requirement.Background} = ${Ratio}，要求至少 ${Requirement.Minimum}`);
}

test('主题色只由唯一 Palette 规则持有且首先导入', async () => {
    const Palette = await ReadStylesheet(PalettePath);
    const PaletteRules: Rule[] = [];
    Palette.walkRules(RuleValue => {
        if (RuleValue.selector.trim().startsWith(':root')) PaletteRules.push(RuleValue);
    });
    assert.deepEqual(PaletteRules.map(RuleValue => RuleValue.selector.trim()), [':root', DarkThemeSelector]);

    const LightRules = PaletteRules.filter(RuleValue => RuleValue.selector.trim() === ':root');
    const DarkRules = PaletteRules.filter(RuleValue => RuleValue.selector.trim() === DarkThemeSelector);
    assert.equal(LightRules.length, 1, 'Palette.css 必须恰有一个浅色 :root 规则');
    assert.equal(DarkRules.length, 1, `Palette.css 必须恰有一个 ${DarkThemeSelector} 规则`);

    const ColorTokens = ReadPaletteColorTokens([LightRules[0]!, DarkRules[0]!]);
    const Overrides: string[] = [];
    for (const FileName of ['Prism.css', 'ControlDeck.css']) {
        const Path = resolve(StylesDirectory, FileName);
        const Stylesheet = await ReadStylesheet(Path);
        Stylesheet.walkDecls(Declaration => {
            if (Declaration.prop === '--sidebar-width' || !ColorTokens.has(Declaration.prop)) return;
            Overrides.push(`${FileName}:${Declaration.source?.start?.line ?? '?'} ${Declaration.prop}`);
        });
    }
    assert.deepEqual(Overrides, [], 'Prism.css 与 ControlDeck.css 不得覆盖 Palette 颜色 token');

    const ThemeStylesheet = await ReadStylesheet(ThemePath);
    const Imports: string[] = [];
    ThemeStylesheet.walkAtRules('import', AtRule => Imports.push(AtRule.params.trim().replace(/^(['"])(.*)\1$/, '$2')));
    assert.equal(Imports[0], './Palette.css', 'Theme.css 必须先导入 Palette.css');
});

test('Palette 之外的样式声明不包含颜色字面量', async () => {
    const Files = await FindCssFiles(StylesDirectory);
    const Violations: string[] = [];
    for (const Path of Files) {
        if (Path === PalettePath) continue;
        const Stylesheet = await ReadStylesheet(Path);
        Stylesheet.walkDecls(Declaration => {
            if (!ForbiddenColorLiteral.test(Declaration.value)) return;
            const FileName = relative(StylesDirectory, Path);
            Violations.push(`${FileName}:${Declaration.source?.start?.line ?? '?'} ${Declaration.prop}: ${Declaration.value}`);
        });
    }
    assert.deepEqual(Violations, [], '色板以外的 CSS 声明只能引用主题 token 或使用允许的透明色表达式');
});

test('浅色与深色主题的文字、状态、图表和控件颜色满足对比度合同', async () => {
    const Palette = await ReadStylesheet(PalettePath);
    const LightRules = Palette.nodes.filter(Node => Node.type === 'rule' && Node.selector.trim() === ':root') as Rule[];
    const DarkRules = Palette.nodes.filter(Node => Node.type === 'rule' && Node.selector.trim() === DarkThemeSelector) as Rule[];
    assert.equal(LightRules.length, 1, '缺少唯一浅色主题规则');
    assert.equal(DarkRules.length, 1, '缺少唯一深色主题规则');

    const LightProperties = ReadCustomProperties(LightRules[0]!);
    const DarkProperties = new Map([...LightProperties, ...ReadCustomProperties(DarkRules[0]!)]);
    const ThemeProperties: readonly ThemePalette[] = [
        { Name: '浅色', Properties: LightProperties },
        { Name: '深色', Properties: DarkProperties },
    ];
    const ContrastRequirements: ContrastRequirement[] = [];

    for (const Foreground of ['--ink', '--ink-soft', '--muted', '--muted-light', '--plot-axis']) {
        for (const Background of ['--surface', '--surface-subtle', '--surface-selected', '--frame-surface', '--canvas']) {
            ContrastRequirements.push({ Foreground, Background, Minimum: 4.5 });
        }
    }

    for (const Status of [
        { Foreground: '--success', Surface: '--success-surface' },
        { Foreground: '--warning', Surface: '--warning-surface' },
        { Foreground: '--danger', Surface: '--danger-surface' },
        { Foreground: '--info', Surface: '--info-surface' },
    ]) {
        ContrastRequirements.push({ Foreground: Status.Foreground, Background: Status.Surface, Minimum: 4.5 });
        ContrastRequirements.push({ Foreground: Status.Foreground, Background: '--surface-selected', Minimum: 4.5 });
    }
    ContrastRequirements.push({ Foreground: '--muted', Background: '--warning-surface', Minimum: 4.5 });
    ContrastRequirements.push({ Foreground: '--on-accent', Background: '--accent', Minimum: 4.5 });
    ContrastRequirements.push({ Foreground: '--on-danger', Background: '--danger-action', Minimum: 4.5 });

    for (const Foreground of ['--nav-ink', '--nav-muted', '--nav-brand']) {
        ContrastRequirements.push({ Foreground, Background: '--nav-bg', Minimum: 4.5 });
    }
    ContrastRequirements.push({ Foreground: '--nav-ink', Background: '--nav-control', Minimum: 4.5 });
    ContrastRequirements.push({ Foreground: '--nav-active-ink', Background: '--nav-active-bg', Minimum: 4.5 });
    for (const Foreground of ['--signal-ink', '--signal-muted', '--signal-accent', '--signal-success', '--signal-warning', '--signal-danger']) {
        ContrastRequirements.push({ Foreground, Background: '--signal-surface', Minimum: 4.5 });
    }
    ContrastRequirements.push({ Foreground: '--signal-line', Background: '--signal-surface', Minimum: 3 });

    for (const Foreground of ['--plot-line', '--plot-line-soft', '--plot-line-faint']) {
        ContrastRequirements.push({ Foreground, Background: '--surface', Minimum: 3 });
    }
    for (const Foreground of ['--focus', '--control-border']) {
        for (const Background of ['--surface', '--surface-subtle']) {
            ContrastRequirements.push({ Foreground, Background, Minimum: 3 });
        }
    }

    for (const Theme of ThemeProperties) {
        for (const Requirement of ContrastRequirements) AssertContrast(Theme, Requirement);
    }
});

test('Palette 浅色采用 Slate，深色采用中性灰阶并保留图表语义', async () => {
    const Palette = await ReadStylesheet(PalettePath);
    const LightRule = Palette.nodes.find(Node => Node.type === 'rule' && Node.selector.trim() === ':root') as Rule | undefined;
    const DarkRule = Palette.nodes.find(Node => Node.type === 'rule' && Node.selector.trim() === DarkThemeSelector) as Rule | undefined;
    assert.ok(LightRule, '缺少浅色 Shadcn Admin 色板');
    assert.ok(DarkRule, '缺少深色 Shadcn Admin 色板');

    const Light = ReadCustomProperties(LightRule);
    const Dark = new Map([...Light, ...ReadCustomProperties(DarkRule)]);
    assert.deepEqual(Object.fromEntries([
        ['--canvas', Light.get('--canvas')], ['--ink', Light.get('--ink')], ['--accent', Light.get('--accent')],
        ['--surface-subtle', Light.get('--surface-subtle')], ['--line', Light.get('--line')],
        ['--plot-line', Light.get('--plot-line')], ['--plot-line-soft', Light.get('--plot-line-soft')],
    ]), {
        '--canvas': '#ffffff', '--ink': '#020817', '--accent': '#0f172a', '--surface-subtle': '#f1f5f9',
        '--line': '#e2e8f0', '--plot-line': '#0f766e', '--plot-line-soft': '#c2410c',
    });
    assert.deepEqual(Object.fromEntries([
        ['--canvas', Dark.get('--canvas')], ['--ink', Dark.get('--ink')], ['--accent', Dark.get('--accent')],
        ['--surface-subtle', Dark.get('--surface-subtle')], ['--line', Dark.get('--line')],
    ]), {
        '--canvas': '#121212', '--ink': '#f5f5f5', '--accent': '#e5e5e5', '--surface-subtle': '#292929',
        '--line': '#404040',
    });
});

test('sRGB 亮度与对比度公式保留 WCAG 已知值', () => {
    const Black = { Red: 0, Green: 0, Blue: 0 };
    const White = { Red: 255, Green: 255, Blue: 255 };
    assert.equal(RelativeLuminance(Black), 0);
    assert.equal(RelativeLuminance(White), 1);
    assert.equal(ContrastRatio(Black, White), 21);
    assert.equal(ContrastRatio(Black, Black), 1);
});
