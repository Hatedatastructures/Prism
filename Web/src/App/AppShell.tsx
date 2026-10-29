/** @file Prism 前端使用 shadcn-admin 的认证应用框架承载运维路由。 */
import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { Activity, ChartNoAxesCombined, Cpu, FileSliders, LayoutDashboard, Layers, Network, Router, ScrollText, Users, UsersRound } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router';
import { SidebarInset, SidebarProvider } from '@/Components/ui/sidebar';
import { TooltipProvider } from '@/Components/ui/tooltip';
import { PrismAppSidebar } from '@/Components/Layout/PrismAppSidebar';
import type { PrismNavGroup } from '@/Components/Layout/PrismAppSidebar';
import { PrismHeader, PrismMain } from '@/Components/Layout/PrismHeader';
import { ConfigurationDraftUnloadGuard } from './ConfigurationDraft';
import type { AdminServices } from './AdminServices';

type Theme = 'light' | 'dark';
const ThemeKey = 'prism-shadcn-admin-theme';

const Navigation: readonly PrismNavGroup[] = [
    { Label: 'General', Icon: LayoutDashboard, Items: [{ Path: '/', Label: '运行概览', Icon: LayoutDashboard, End: true }, { Path: '/events', Label: '事件', Icon: Activity }, { Path: '/resources', Label: '资源', Icon: ChartNoAxesCombined }] },
    { Label: 'Proxy', Icon: Router, Items: [{ Path: '/ingresses', Label: '代理入口', Icon: Router }, { Path: '/protocols', Label: '协议', Icon: Layers }, { Path: '/workers', Label: '工作线程', Icon: Cpu }, { Path: '/sessions', Label: '连接', Icon: Network }] },
    { Label: 'Access Control', Icon: Users, Items: [{ Path: '/accounts', Label: '账户', Icon: Users }, { Path: '/user-groups', Label: '用户组', Icon: UsersRound }] },
    { Label: 'System', Icon: FileSliders, Items: [{ Path: '/configuration', Label: '配置', Icon: FileSliders }, { Path: '/operations', Label: '操作中心', Icon: ScrollText }] },
];
const PageNames: Readonly<Record<string, string>> = { '/': '运行概览', '/events': '事件', '/resources': '资源', '/ingresses': '代理入口', '/protocols': '协议', '/workers': '工作线程', '/sessions': '连接', '/accounts': '账户', '/user-groups': '用户组', '/configuration': '配置', '/operations': '操作中心' };

function ReadTheme(): Theme { try { return window.localStorage.getItem(ThemeKey) === 'dark' ? 'dark' : 'light'; } catch { return 'light'; } }

export function AppShell(Input: Readonly<{ Services: AdminServices }>): ReactNode {
    const Location = useLocation(), Navigate = useNavigate();
    const [Theme, SetTheme] = useState<Theme>(ReadTheme);
    const Search = useMemo(() => new URLSearchParams(Location.search), [Location.search]);
    const Overview = useQuery({ queryKey: ['operations', 'overview'], queryFn: () => Input.Services.Data.GetOverview(), retry: false, staleTime: 1_000, refetchInterval: 5_000, refetchOnWindowFocus: true, refetchIntervalInBackground: false });
    const Health = Overview.isError ? 'sampling-failed' : Overview.data?.Health.Status ?? 'waiting';
    useEffect(() => { const Root = document.documentElement; Root.classList.toggle('dark', Theme === 'dark'); Root.dataset.theme = Theme; Root.style.colorScheme = Theme; }, [Theme]);
    useEffect(() => { document.title = `${PageNames[Location.pathname] ?? 'Prism'} · Prism Control Plane`; }, [Location.pathname]);
    useEffect(() => { try { window.localStorage.setItem(ThemeKey, Theme); } catch { /* 私有模式下仅保持当前会话主题。 */ } }, [Theme]);
    useEffect(() => { if (Input.Services.Mode !== 'demo') return; const Next = new URLSearchParams(Location.search); if (Next.get('source') !== 'demo') { Next.set('source', 'demo'); Navigate({ pathname: Location.pathname, search: Next.toString() }, { replace: true }); } }, [Input.Services.Mode, Location.pathname, Location.search, Navigate]);
    return <TooltipProvider delayDuration={150}><SidebarProvider defaultOpen><ConfigurationDraftUnloadGuard /><a className="sr-only rounded-md bg-primary px-3 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50" href="#main-content">跳到主内容</a><PrismAppSidebar Groups={Navigation} Search={Search} Mode={Input.Services.Mode} Health={Health} ProcessId={Overview.data?.Process.Id} /><SidebarInset className="@container/content"><PrismHeader Services={Input.Services} Search={Search} Dark={Theme === 'dark'} OnThemeToggle={() => SetTheme(Value => Value === 'dark' ? 'light' : 'dark')} /><PrismMain>{Input.Services.Mode === 'live' && Overview.isError && <div className="mb-6 rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">真实管理接口不可用；原运行进程保持不变。<NavLink className="ml-2 font-medium underline underline-offset-4" to="/?source=demo">打开演示预览</NavLink></div>}<Outlet context={Input.Services} /></PrismMain></SidebarInset></SidebarProvider></TooltipProvider>;
}
