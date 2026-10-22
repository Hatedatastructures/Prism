import { TimeLink as Link } from '../Features/TimeLink';
import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import {
    Activity, ArrowUpRight, Bell, ChartNoAxesCombined, Cpu, FileSliders, LayoutDashboard, Layers,
    Menu, Moon, Network, Router, ScrollText, Sun, Users, UsersRound, X,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router';
import type { AdminServices } from './AdminServices';
import { FormatTime } from '../Components/Ui';
import { Hint } from '../Components/Hint';
import { ResourceSearch } from './ResourceSearch';
import { ConfigurationDraftUnloadGuard } from './ConfigurationDraft';
import { WithTime } from '../Features/TimeRange';

type ThemePreference = 'system' | 'light' | 'dark';
const ThemeKey = 'prism-preview-theme:v2';

type NavItem = Readonly<{ Path: string; Label: string; Icon: LucideIcon; Index: string; End?: boolean }>;
type NavGroup = Readonly<{ Label: string; Items: readonly NavItem[] }>;

const Navigation: readonly NavGroup[] = [
    { Label: '运行', Items: [
        { Path: '/', Label: '运行概览', Icon: LayoutDashboard, Index: '01', End: true },
        { Path: '/events', Label: '事件流', Icon: Activity, Index: '02' },
        { Path: '/resources', Label: '资源分析', Icon: ChartNoAxesCombined, Index: '03' },
    ] },
    { Label: '代理资源', Items: [
        { Path: '/ingresses', Label: '代理入口', Icon: Router, Index: '04' },
        { Path: '/protocols', Label: '协议分析', Icon: Layers, Index: '05' },
        { Path: '/workers', Label: 'Worker', Icon: Cpu, Index: '06' },
        { Path: '/sessions', Label: 'Session 追踪', Icon: Network, Index: '07' },
    ] },
    { Label: '访问控制', Items: [
        { Path: '/accounts', Label: '代理账户', Icon: Users, Index: '08' },
        { Path: '/user-groups', Label: '用户组', Icon: UsersRound, Index: '09' },
    ] },
    { Label: '管理维护', Items: [
        { Path: '/configuration', Label: '配置', Icon: FileSliders, Index: '10' },
        { Path: '/operations', Label: '操作中心', Icon: ScrollText, Index: '11' },
    ] },
];

const PageNames: Readonly<Record<string, string>> = {
    '/': '运行概览', '/ingresses': '代理入口', '/workers': 'Worker', '/accounts': '代理账户',
    '/user-groups': '用户组', '/sessions': 'Session 追踪', '/events': '事件流',
    '/configuration': '配置', '/operations': '操作中心',
    '/protocols': '协议分析', '/resources': '资源分析',
};

function ReadPreference(): ThemePreference {
    try {
        const Value = window.localStorage.getItem(ThemeKey);
        if (Value === 'light' || Value === 'dark') return Value;
    } catch { /* 隐私模式下保持系统主题 */ }
    return 'light';
}

function HealthLabel(Value: string | undefined): string {
    if (Value === 'healthy') return '运行正常';
    if (Value === 'degraded') return '存在告警';
    if (Value === 'unhealthy') return '运行异常';
    if (Value === 'draining') return '正在排空';
    if (Value === 'sampling-failed') return '采样失败';
    return '等待采样';
}

/** @brief 移动导航打开期间约束焦点，退出时恢复原来的焦点与页面滚动。 */
function TrapNavigation(OnClose: () => void): () => void {
    const Previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const Sidebar = document.getElementById('primary-navigation');
    const Items = Array.from(Sidebar?.querySelectorAll<HTMLElement>('a[href], button:not([disabled])') ?? [])
        .filter(Item => Item.getClientRects().length > 0);
    const Overflow = document.body.style.overflow;
    const Desktop = window.matchMedia('(min-width: 761px)');
    document.body.style.overflow = 'hidden';
    Items[0]?.focus();
    function HandleKey(Event: globalThis.KeyboardEvent): void {
        if (Event.key === 'Escape') OnClose();
        if (Event.key !== 'Tab' || Items.length === 0) return;
        const Target = Event.shiftKey ? Items[Items.length - 1] : Items[0];
        const Edge = Event.shiftKey ? Items[0] : Items[Items.length - 1];
        if (document.activeElement !== Edge) return;
        Event.preventDefault();
        Target?.focus();
    }
    const Resize = (Event: MediaQueryListEvent): void => { if (Event.matches) OnClose(); };
    document.addEventListener('keydown', HandleKey);
    Desktop.addEventListener('change', Resize);
    return () => {
        document.body.style.overflow = Overflow;
        document.removeEventListener('keydown', HandleKey);
        Desktop.removeEventListener('change', Resize);
        Previous?.focus();
    };
}

export function AppShell(Input: Readonly<{ Services: AdminServices }>): ReactNode {
    const Location = useLocation();
    const Navigate = useNavigate();
    const [Preference, SetPreference] = useState<ThemePreference>(ReadPreference);
    const [SystemDark, SetSystemDark] = useState(() => window.matchMedia('(prefers-color-scheme: dark)').matches);
    const [MobileOpen, SetMobileOpen] = useState(false);
    const Overview = useQuery({
        queryKey: ['operations', 'overview'],
        queryFn: () => Input.Services.Data.GetOverview(),
        retry: false,
        staleTime: 1_000,
        refetchInterval: 5_000,
        refetchOnWindowFocus: true,
        refetchIntervalInBackground: false,
    });
    const Dark = Preference === 'dark' || Preference === 'system' && SystemDark;
    const Theme = Dark ? 'dark' : 'light';
    const CurrentPage = useMemo(() => PageNames[Location.pathname] ?? '代理运行面', [Location.pathname]);

    useEffect(() => {
        const Media = window.matchMedia('(prefers-color-scheme: dark)');
        SetSystemDark(Media.matches);
        const Update = (Event: MediaQueryListEvent): void => SetSystemDark(Event.matches);
        Media.addEventListener('change', Update);
        return () => Media.removeEventListener('change', Update);
    }, []);

    useEffect(() => {
        document.documentElement.dataset.theme = Theme;
        document.documentElement.style.colorScheme = Theme;
        document.querySelector('meta[name="theme-color"]')?.setAttribute('content', Dark ? '#090f16' : '#f4f6f8');
    }, [Theme]);

    useEffect(() => {
        try {
            if (Preference === 'system') window.localStorage.removeItem(ThemeKey);
            else window.localStorage.setItem(ThemeKey, Preference);
        } catch { /* 当前页面的主题仍保持可切换 */ }
    }, [Preference]);

    useEffect(() => SetMobileOpen(false), [Location.pathname, Location.search]);
    useEffect(() => {
        if (Input.Services.Mode !== 'demo') return;
        const Params = new URLSearchParams(Location.search);
        if (Params.get('source') === 'demo') return;
        Params.set('source', 'demo');
        Navigate({ pathname: Location.pathname, search: Params.toString() }, { replace: true });
    }, [Input.Services.Mode, Location.pathname, Location.search, Navigate]);

    useEffect(() => MobileOpen ? TrapNavigation(() => SetMobileOpen(false)) : undefined, [MobileOpen]);

    const ToggleTheme = (): void => SetPreference(Dark ? 'light' : 'dark');
    const SidebarClass = ['sidebar', MobileOpen ? 'sidebar-mobile-open' : '']
        .filter(Boolean).join(' ');
    const Health = Overview.isError ? 'sampling-failed' : Overview.data?.Health.Status;
    const ActiveIndex = Navigation.flatMap(Group => Group.Items)
        .find(Item => Item.Path === (Location.pathname === '/' ? '/' : Location.pathname.replace(/\/$/, '')))?.Index ?? '';

    return <div className="app-frame">
        <ConfigurationDraftUnloadGuard />
        <a className="skip-link" href="#main-content">跳到页面内容</a>
        {MobileOpen && <button className="mobile-scrim" aria-label="关闭导航菜单" onClick={() => SetMobileOpen(false)} />}
        <aside id="primary-navigation" className={SidebarClass} aria-label="主导航">
            <div className="sidebar-head">
                <div className="brand-row">
                    <NavLink className="brand" to={WithTime('/', new URLSearchParams(Location.search))} aria-label="Prism 运行概览" onClick={() => SetMobileOpen(false)}>
                        <img className="brand-mark" src="/PrismMark.svg" width="30" height="30" alt="" />
                        <span className="brand-copy"><strong>Prism</strong><small>Network operations</small></span>
                    </NavLink>
                    <button className="icon-button sidebar-close" type="button" onClick={() => SetMobileOpen(false)} aria-label="关闭导航">
                        <X size={19} aria-hidden="true" />
                    </button>
                </div>
                <p className="sidebar-caption">代理网络控制面<br /><span>Observed, not assumed.</span></p>
            </div>
            <ResourceSearch Services={Input.Services} />
            <nav className="primary-nav" aria-label="管理页面">
                {Navigation.map(Group => <div className="nav-group" key={Group.Label}>
                    <div className="nav-group-title">{Group.Label}<span>{String(Group.Items.length).padStart(2, '0')}</span></div>
                    {Group.Items.map(Item => <NavLink key={Item.Path} to={WithTime(Item.Path, new URLSearchParams(Location.search))}
                        onClick={() => SetMobileOpen(false)}
                        {...(Item.End === undefined ? {} : { end: Item.End })}
                        className={({ isActive }) => `nav-link group ${isActive ? 'nav-link-active' : ''}`}>
                        <span className="nav-icon"><Item.Icon size={18} strokeWidth={1.9} aria-hidden="true" /></span>
                        <span className="nav-label">{Item.Label}</span>
                        <span className="nav-index" aria-hidden="true">{Item.Index}</span>
                    </NavLink>)}
                </div>)}
            </nav>
            <div className="sidebar-lower">
                <NavLink className="sidebar-instance" to={WithTime('/operations', new URLSearchParams(Location.search))}>
                    <span className={`instance-led ${Input.Services.Mode === 'demo' ? 'instance-led-demo' : Health === 'healthy' ? 'instance-led-live' : 'instance-led-warn'}`} aria-hidden="true" />
                    <span><strong>{Input.Services.Mode === 'demo' ? 'DEMO FIXTURE' : 'LOCAL CONTROL'}</strong>
                        <small>{Input.Services.Mode === 'demo' ? '演示夹具 · 不连接后端' : `${HealthLabel(Health)} · PID ${Overview.data?.Process.Id ?? '—'}`}</small></span>
                    <ArrowUpRight size={14} aria-hidden="true" />
                </NavLink>
                <div className="sidebar-footnote"><span>Prism {Overview.data?.Process.GenerationId ? `G${Overview.data.Process.GenerationId}` : '—'}</span>
                    <span>{Input.Services.Mode === 'demo' ? 'LOCAL FIXTURE' : 'LIVE CONTROL'}</span></div>
            </div>
        </aside>

        <div className="workspace">
            <header className="topbar">
                <div className="topbar-leading">
                    <button className="icon-button mobile-menu" type="button" onClick={() => SetMobileOpen(true)}
                        aria-label="打开导航" aria-expanded={MobileOpen} aria-controls="primary-navigation"><Menu size={20} aria-hidden="true" /></button>
                    <div className="breadcrumb"><span>Workspace</span><span className="breadcrumb-slash">/</span><strong>{CurrentPage}</strong></div>
                    {Overview.data && <span className="runtime-context" title={`进程 ${Overview.data.Process.Id} · 阶段 ${Overview.data.Process.Phase}`}>
                        <span>PID {Overview.data.Process.Id}</span><i>·</i>G{Overview.data.Process.GenerationId}</span>}
                </div>
                <div className="topbar-trailing">
                    <div className="topbar-status" role="status">
                        <span className={`health-dot health-${Health ?? 'unknown'}`} aria-hidden="true" />
                        <span>{HealthLabel(Health)}</span>
                    </div>
                    <span className="topbar-index" aria-hidden="true">{ActiveIndex || '—'} / 11</span>
                    <time className="sample-chip" dateTime={Overview.data?.SampledAt} title="最近采样时间">{FormatTime(Overview.data?.SampledAt)}</time>
                    <Link className="icon-button topbar-icon" to="/events" aria-label="打开事件流" title="打开事件流">
                        <Bell size={17} aria-hidden="true" />
                    </Link>
                    <Hint Label={Dark ? '切换浅色主题' : '切换深色主题'}><button className="icon-button theme-toggle" type="button" onClick={ToggleTheme}
                        aria-label={Dark ? '切换浅色主题' : '切换深色主题'}>
                        {Dark ? <Sun size={17} aria-hidden="true" /> : <Moon size={17} aria-hidden="true" />}
                    </button></Hint>
                </div>
            </header>
            <main id="main-content" className="main-content" tabIndex={-1}>
                {Input.Services.Mode === 'demo' && <div className="source-banner" role="status"><strong>演示预览</strong><span>所有数值与操作均为本页测试夹具，未连接真实实例。</span><a href="/?source=live">切换真实实例</a></div>}
                {Input.Services.Mode === 'live' && Overview.isError && <div className="notice notice-info source-banner"><span>真实管理接口当前不可用；原有运行进程保持不变。</span><a href="/?source=demo">打开演示预览</a></div>}
                <Outlet context={Input.Services} />
            </main>
            <footer className="workspace-footer"><span>Prism <i>·</i> Observed, not assumed.</span>
                <span>{Input.Services.Mode === 'demo' ? '演示夹具 · 不连接后端' : '运行概览每 5 秒刷新 · 后台暂停'}</span></footer>
        </div>
    </div>;
}
