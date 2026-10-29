/** @file 基于 shadcn-admin AppSidebar 结构的 Prism 主导航。 */
import type { ReactNode } from 'react';
import { ChevronUp, CircleDot, Command, Ellipsis, MonitorCog, Settings2 } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { NavLink, useLocation } from 'react-router';
import { Avatar, AvatarFallback, AvatarBadge } from '@/Components/ui/avatar';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@/Components/ui/dropdown-menu';
import { Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarHeader, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarRail, useSidebar } from '@/Components/ui/sidebar';
import { WithTime } from '../../Features/TimeRange';

export type PrismNavItem = Readonly<{ Path: string; Label: string; Icon: LucideIcon; End?: boolean }>;
export type PrismNavGroup = Readonly<{ Label: string; Icon: LucideIcon; Items: readonly PrismNavItem[] }>;

function NavItem(Input: Readonly<{ Item: PrismNavItem; Search: URLSearchParams }>): ReactNode {
    const SidebarState = useSidebar();
    const Location = useLocation();
    const Active = Input.Item.End ? Location.pathname === Input.Item.Path : Input.Item.Path === '/' ? Location.pathname === '/' : Location.pathname.startsWith(Input.Item.Path);
    return <SidebarMenuItem><SidebarMenuButton asChild isActive={Active} tooltip={Input.Item.Label}>
        <NavLink to={WithTime(Input.Item.Path, Input.Search)} {...(Input.Item.End === undefined ? {} : { end: Input.Item.End })} onClick={() => SidebarState.setOpenMobile(false)}>
            {({ isActive }) => <><Input.Item.Icon aria-hidden="true" /><span data-active={isActive}>{Input.Item.Label}</span></>}
        </NavLink>
    </SidebarMenuButton></SidebarMenuItem>;
}

function PrismTeamSwitcher(): ReactNode {
    return <DropdownMenu><DropdownMenuTrigger asChild><SidebarMenu><SidebarMenuItem><SidebarMenuButton size="lg" className="data-open:bg-sidebar-accent data-open:text-sidebar-accent-foreground">
        <div className="flex size-8 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground"><Command className="size-4" aria-hidden="true" /></div>
        <div className="grid flex-1 text-left text-sm leading-tight"><span className="truncate font-semibold">Prism Control Plane</span><span className="truncate text-xs text-muted-foreground">运行管理</span></div><ChevronUp className="ml-auto size-4" aria-hidden="true" />
    </SidebarMenuButton></SidebarMenuItem></SidebarMenu></DropdownMenuTrigger><DropdownMenuContent className="w-64" align="start" side="right" sideOffset={8}>
        <DropdownMenuLabel>当前工作空间</DropdownMenuLabel><DropdownMenuItem><Command aria-hidden="true" />Prism Control Plane</DropdownMenuItem><DropdownMenuSeparator /><DropdownMenuItem disabled><MonitorCog aria-hidden="true" />运行实例由数据源确定</DropdownMenuItem>
    </DropdownMenuContent></DropdownMenu>;
}

function PrismNavGroup(Input: Readonly<{ Group: PrismNavGroup; Search: URLSearchParams }>): ReactNode {
    return <SidebarGroup className="py-1"><SidebarGroupContent><SidebarMenu>
        {Input.Group.Items.map(Item => <NavItem Item={Item} Search={Input.Search} key={Item.Path} />)}
    </SidebarMenu></SidebarGroupContent></SidebarGroup>;
}

function PrismNavUser(Input: Readonly<{ Mode: 'demo' | 'live'; Health: string; ProcessId?: string | undefined }>): ReactNode {
    return <DropdownMenu><DropdownMenuTrigger asChild><SidebarMenu><SidebarMenuItem><SidebarMenuButton size="lg" tooltip="实例状态">
        <Avatar size="default"><AvatarFallback>PR</AvatarFallback><AvatarBadge className={Input.Mode === 'demo' ? 'bg-slate-400' : Input.Health === 'healthy' ? 'bg-emerald-500' : 'bg-amber-500'}><CircleDot /></AvatarBadge></Avatar>
        <div className="grid flex-1 text-left text-sm leading-tight"><span className="truncate font-medium">{Input.Mode === 'demo' ? '演示工作空间' : 'Prism 实例'}</span><span className="truncate text-xs text-muted-foreground">{Input.Mode === 'demo' ? '示例数据，操作不出站' : Input.ProcessId ? `PID ${Input.ProcessId}` : '正在读取实例身份'}</span></div><Ellipsis className="ml-auto size-4" aria-hidden="true" />
    </SidebarMenuButton></SidebarMenuItem></SidebarMenu></DropdownMenuTrigger><DropdownMenuContent className="w-64" align="end" side="right" sideOffset={8}><DropdownMenuLabel>运行状态</DropdownMenuLabel><DropdownMenuItem disabled><CircleDot className={Input.Mode === 'demo' ? 'text-slate-500' : Input.Health === 'healthy' ? 'text-emerald-600' : 'text-amber-600'} aria-hidden="true" />{Input.Mode === 'demo' ? '演示模式' : Input.Health || '等待采样'}</DropdownMenuItem><DropdownMenuSeparator /><DropdownMenuItem disabled><Settings2 aria-hidden="true" />实例与权限在配置页管理</DropdownMenuItem></DropdownMenuContent></DropdownMenu>;
}

export function PrismAppSidebar(Input: Readonly<{ Groups: readonly PrismNavGroup[]; Search: URLSearchParams; Mode: 'demo' | 'live'; Health: string; ProcessId?: string | undefined }>): ReactNode {
    return <Sidebar variant="inset" collapsible="icon"><SidebarHeader><PrismTeamSwitcher /></SidebarHeader><SidebarContent>{Input.Groups.map(Group => <PrismNavGroup Group={Group} Search={Input.Search} key={Group.Label} />)}</SidebarContent><SidebarFooter><PrismNavUser Mode={Input.Mode} Health={Input.Health} ProcessId={Input.ProcessId} /></SidebarFooter><SidebarRail /></Sidebar>;
}
