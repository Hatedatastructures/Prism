/** @file 基于 Shadcn CommandDialog 的 Prism 全局资源搜索。 */
import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ArrowUpRight, Cpu, LayoutDashboard, Network, Search, Users } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router';
import { Button } from '@/Components/ui/button';
import { Command, CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandSeparator, CommandShortcut } from '@/Components/ui/command';
import type { AdminServices } from './AdminServices';
import { WithTime } from '../Features/TimeRange';

type SearchEntry = Readonly<{ Id: string; Label: string; Detail: string; Path: string; Icon: LucideIcon }>;
const Pages: readonly SearchEntry[] = [
    { Id: 'overview', Label: '运行概览', Detail: '流量与运行状态', Path: '/', Icon: LayoutDashboard },
    { Id: 'events', Label: '事件流', Detail: '按资源与级别定位事件', Path: '/events', Icon: Network },
    { Id: 'resources', Label: '资源分析', Detail: '内存、观测与历史', Path: '/resources', Icon: LayoutDashboard },
    { Id: 'ingresses', Label: '代理入口', Detail: '监听、绑定与承载能力', Path: '/ingresses', Icon: Network },
    { Id: 'protocols', Label: '协议分析', Detail: '类型、实例与统计覆盖', Path: '/protocols', Icon: Network },
    { Id: 'workers', Label: 'Worker', Detail: '邮箱、派发与接收状态', Path: '/workers', Icon: Cpu },
    { Id: 'sessions', Label: 'Session 追踪', Detail: '连接、阶段与关联资源', Path: '/sessions', Icon: Network },
    { Id: 'accounts', Label: '代理账户', Detail: '身份、额度与策略', Path: '/accounts', Icon: Users },
    { Id: 'groups', Label: '用户组', Detail: '成员与默认策略', Path: '/user-groups', Icon: Users },
    { Id: 'configuration', Label: '配置', Detail: '草稿、验证与应用', Path: '/configuration', Icon: LayoutDashboard },
    { Id: 'operations', Label: '操作中心', Detail: '查看实际操作结果', Path: '/operations', Icon: LayoutDashboard },
];

/** @brief 支持页面搜索与可用时的服务端资源搜索；未开放能力时不伪造全局结果。 */
export function ResourceSearch(Input: Readonly<{ Services: AdminServices }>): ReactNode {
    const [Open, SetOpen] = useState(false);
    const [Text, SetText] = useState('');
    const [Debounced, SetDebounced] = useState('');
    const Trigger = useRef<HTMLButtonElement>(null);
    const FocusRestore = useRef<HTMLElement | null>(null);
    const Navigate = useNavigate();
    const [Params] = useSearchParams();
    const CaptureFocus = (): void => {
        const Active = document.activeElement;
        FocusRestore.current = Active instanceof HTMLElement && Active !== document.body ? Active : Trigger.current;
    };
    const SetDialogOpen = (Value: boolean): void => {
        if (Value) CaptureFocus();
        SetOpen(Value);
    };
    useEffect(() => { const Timer = window.setTimeout(() => SetDebounced(Text.trim()), 250); return () => window.clearTimeout(Timer); }, [Text]);
    useEffect(() => {
        const Shortcut = (Event: KeyboardEvent): void => {
            if (Event.key.toLowerCase() !== 'k' || !(Event.ctrlKey || Event.metaKey)) return;
            Event.preventDefault();
            SetOpen(Value => {
                if (!Value) CaptureFocus();
                return !Value;
            });
        };
        document.addEventListener('keydown', Shortcut);
        return () => document.removeEventListener('keydown', Shortcut);
    }, []);
    const Bootstrap = useQuery({ queryKey: ['operations', 'bootstrap-identity', Input.Services.Mode], queryFn: () => Input.Services.Data.GetBootstrap({ Fresh: true }), retry: false, staleTime: 0,
        refetchInterval: Input.Services.Mode === 'live' ? 5_000 : false, refetchIntervalInBackground: false, refetchOnWindowFocus: true });
    const SearchAvailable = Bootstrap.data?.Capabilities.includes('search.read') === true && !Bootstrap.error;
    const Query = useQuery({ queryKey: ['operations', 'resource-search', Debounced], enabled: Open && Debounced.length > 0 && SearchAvailable, staleTime: 5_000, retry: false,
        queryFn: ({ signal }) => {
            if (!Input.Services.Data.Search) throw new Error('当前实例尚未提供全局资源搜索，请进入对应清单筛选');
            return Input.Services.Data.Search(Debounced, signal);
        } });
    const Select = (Path: string): void => { SetOpen(false); Navigate(WithTime(Path, Params)); };
    const PageMatches = Pages.filter(Entry => `${Entry.Label} ${Entry.Detail}`.toLowerCase().includes(Text.toLowerCase()));
    const Resources: readonly SearchEntry[] = Query.data?.map(Entry => ({ ...Entry, Id: `${Entry.Kind}:${Entry.Id}`,
        Detail: Entry.Kind === 'worker' ? `${Entry.Detail} · 当前 Worker 槽位` : Entry.Kind === 'account' ? `${Entry.Detail} · 查看当前账户` : Entry.Detail,
        Icon: Entry.Kind === 'worker' ? Cpu : Entry.Kind === 'account' ? Users : Network })) ?? [];
    const Status = !Debounced ? '输入关键字搜索页面和资源' : Bootstrap.error ? '无法确认服务端搜索能力；仍可搜索页面' : !SearchAvailable ? '当前实例未开放全局资源搜索；仍可搜索页面' : Query.isError ? Query.error.message : Query.isFetching ? '正在搜索服务端资源…' : `${Resources.length} 条服务端结果`;
    return <><Button ref={Trigger} type="button" variant="outline" className="w-full justify-center px-0 text-muted-foreground xl:justify-between xl:px-3" onClick={() => SetDialogOpen(true)} aria-label="搜索资源">
        <span className="flex items-center gap-2"><Search aria-hidden="true" /><span className="hidden xl:inline">搜索资源…</span></span><CommandShortcut className="hidden xl:inline">Ctrl K</CommandShortcut>
    </Button>
        <CommandDialog open={Open} onOpenChange={SetDialogOpen} onCloseAutoFocus={Event => {
            Event.preventDefault();
            FocusRestore.current?.focus();
            FocusRestore.current = null;
        }} title="搜索资源" description="搜索 Prism 页面和服务端资源。">
            <Command loop label="资源搜索关键字" shouldFilter={false}><CommandInput value={Text} onValueChange={SetText} placeholder="搜索账户、Worker、Session 或页面…" aria-label="资源搜索关键字" />
                <CommandList><CommandEmpty>{Debounced && !SearchAvailable ? '服务端未开放全局搜索；请尝试页面名称。' : '没有匹配资源，尝试名称、ID、来源或目标地址。'}</CommandEmpty>
                    {PageMatches.length > 0 && <CommandGroup heading="页面">{PageMatches.map(Entry => <SearchItem Value={Entry} OnSelect={Select} key={Entry.Id} />)}</CommandGroup>}
                    {PageMatches.length > 0 && Resources.length > 0 && <CommandSeparator />}
                    {Resources.length > 0 && <CommandGroup heading="服务端资源">{Resources.map(Entry => <SearchItem Value={Entry} OnSelect={Select} key={Entry.Id} />)}</CommandGroup>}
                </CommandList>
                <div className="border-t px-3 py-2 text-xs text-muted-foreground" role="status">{Status}</div>
            </Command>
        </CommandDialog>
    </>;
}

function SearchItem(Input: Readonly<{ Value: SearchEntry; OnSelect: (Path: string) => void }>): ReactNode {
    const Entry = Input.Value;
    return <CommandItem value={Entry.Id} onSelect={() => Input.OnSelect(Entry.Path)}><Entry.Icon aria-hidden="true" /><span className="min-w-0 flex-1"><strong className="block truncate font-medium">{Entry.Label}</strong><small className="block truncate text-muted-foreground">{Entry.Detail}</small></span><ArrowUpRight aria-hidden="true" /></CommandItem>;
}
