import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import * as Dialog from '@radix-ui/react-dialog';
import { Command } from 'cmdk';
import { ArrowUpRight, Cpu, LayoutDashboard, Network, Search, Users, X } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router';
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

/** @brief 明确全局搜索能力，防抖与取消过时请求；不把局部库存冒充全局结果。 */
export function ResourceSearch(Input: Readonly<{ Services: AdminServices }>): ReactNode {
    const [Open, SetOpen] = useState(false), [Text, SetText] = useState(''), [Debounced, SetDebounced] = useState('');
    const Navigate = useNavigate(), [Params] = useSearchParams();
    useEffect(() => { const Timer = setTimeout(() => SetDebounced(Text.trim()), 300); return () => clearTimeout(Timer); }, [Text]);
    const Query = useQuery({ queryKey: ['operations', 'resource-search', Debounced], enabled: Open && Debounced.length > 0, staleTime: 5000, retry: false,
        queryFn: ({ signal }) => {
            if (!Input.Services.Data.Search) throw new Error('当前实例尚未提供全局资源搜索，请进入对应清单筛选');
            return Input.Services.Data.Search(Debounced, signal);
        } });
    function Select(Path: string): void { SetOpen(false); Navigate(WithTime(Path, Params)); }
    useEffect(() => {
        function Shortcut(Event: KeyboardEvent): void {
            if (Event.key.toLowerCase() !== 'k' || !(Event.ctrlKey || Event.metaKey)) return;
            Event.preventDefault(); SetOpen(Value => !Value);
        }
        document.addEventListener('keydown', Shortcut);
        return () => document.removeEventListener('keydown', Shortcut);
    }, []);
    const PageMatches = Pages.filter(Entry => `${Entry.Label} ${Entry.Detail}`.toLowerCase().includes(Text.toLowerCase()));
    const Resources: readonly SearchEntry[] = Query.data?.map(Entry => ({ ...Entry, Id: `${Entry.Kind}:${Entry.Id}`,
        Detail: Entry.Kind === 'worker' ? `${Entry.Detail} · 当前 Worker 槽位；操作前核对进程与 Generation`
            : Entry.Kind === 'account' ? `${Entry.Detail} · 查看当前账户` : Entry.Detail,
        Icon: Entry.Kind === 'worker' ? Cpu : Entry.Kind === 'account' ? Users : Network })) ?? [];
    return <Dialog.Root open={Open} onOpenChange={SetOpen}>
        <Dialog.Trigger asChild><button className="resource-search-trigger" type="button" aria-label="搜索资源">
            <Search size={15} aria-hidden="true" /><span>搜索资源…</span><kbd>Ctrl K</kbd>
        </button></Dialog.Trigger>
        <Dialog.Portal><Dialog.Overlay className="dialog-overlay" />
            <Dialog.Content className="resource-search-dialog" aria-describedby="resource-search-description">
                <Dialog.Title className="sr-only">搜索资源</Dialog.Title>
                <Dialog.Description id="resource-search-description" className="sr-only">搜索页面以及服务端资源。使用方向键选择，回车打开。</Dialog.Description>
                <Command loop label="资源搜索关键字" shouldFilter={false}>
                    <div className="resource-search-input"><Search size={19} aria-hidden="true" />
                        <Command.Input value={Text} onValueChange={SetText} placeholder="搜索账户、Worker、Session 或页面…" aria-label="资源搜索关键字" />
                        <Dialog.Close className="icon-button" aria-label="关闭资源搜索"><X size={17} aria-hidden="true" /></Dialog.Close>
                    </div>
                    <Command.List><Command.Empty>没有匹配资源，尝试名称、ID、来源或目标地址。</Command.Empty>
                        {PageMatches.length > 0 && <Command.Group heading="页面">{PageMatches.map(Entry => <SearchItem key={Entry.Id} Value={Entry} OnSelect={Select} />)}</Command.Group>}
                        {Resources.length > 0 && <Command.Group heading="服务端资源">{Resources.map(Entry => <SearchItem key={Entry.Id} Value={Entry} OnSelect={Select} />)}</Command.Group>}
                    </Command.List>
                    <div className="resource-search-footer" role="status"><span>{!Debounced ? '输入关键字搜索服务端资源' : Query.isError ? Query.error.message : Query.isFetching ? '正在搜索资源…' : `${Resources.length} 条服务端结果 · 最多 20 条`}</span>
                        <span>↑ ↓ 选择 <kbd>Enter</kbd> 打开</span></div>
                </Command>
            </Dialog.Content>
        </Dialog.Portal>
    </Dialog.Root>;
}
function SearchItem(Input: Readonly<{ Value: SearchEntry; OnSelect: (Path: string) => void }>): ReactNode {
    const Entry = Input.Value;
    return <Command.Item value={Entry.Id} onSelect={() => Input.OnSelect(Entry.Path)}>
        <Entry.Icon size={17} aria-hidden="true" /><span><strong>{Entry.Label}</strong><small>{Entry.Detail}</small></span>
        <ArrowUpRight size={14} aria-hidden="true" />
    </Command.Item>;
}
