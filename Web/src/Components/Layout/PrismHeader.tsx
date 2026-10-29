/** @file 基于 shadcn-admin Header / Main 组合的 Prism 页面框架。 */
import type { ReactNode } from 'react';
import { Bell, Moon, Sun } from 'lucide-react';
import { NavLink } from 'react-router';
import { Button } from '@/Components/ui/button';
import { Separator } from '@/Components/ui/separator';
import { SidebarTrigger } from '@/Components/ui/sidebar';
import { ResourceSearch } from '../../App/ResourceSearch';
import type { AdminServices } from '../../App/AdminServices';

export function PrismHeader(Input: Readonly<{ Services: AdminServices; Search: URLSearchParams; Dark: boolean; OnThemeToggle: () => void }>): ReactNode {
    return <header className="z-50 h-16 shrink-0 border-b bg-background"><div className="flex h-full items-center gap-3 px-4 sm:gap-4">
        <SidebarTrigger variant="outline" className="max-md:scale-125" aria-label="展开或收起导航" /><Separator orientation="vertical" className="h-6" />
        {Input.Services.Mode === 'demo' && <div className="flex items-center gap-2 text-sm"><span className="font-medium">演示模式</span><NavLink className="hidden text-muted-foreground underline underline-offset-4 sm:inline" title="示例数据仅用于预览，操作不会影响真实实例" to="/?source=live">切换真实实例</NavLink></div>}<div className="ml-auto flex items-center gap-1.5"><div className="w-9 xl:w-64"><ResourceSearch Services={Input.Services} /></div><NavLink to={'/events?' + Input.Search.toString()} className="inline-flex size-8 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-accent-foreground" aria-label="查看事件流"><Bell className="size-4" aria-hidden="true" /></NavLink><Button variant="ghost" size="icon-sm" type="button" onClick={Input.OnThemeToggle} aria-label={Input.Dark ? '切换浅色主题' : '切换深色主题'}>{Input.Dark ? <Sun aria-hidden="true" /> : <Moon aria-hidden="true" />}</Button></div>
    </div></header>;
}

export function PrismMain(Input: Readonly<{ children: ReactNode }>): ReactNode {
    return <main id="main-content" tabIndex={-1} className="@container/content w-full min-w-0 flex-1 px-4 py-4 sm:px-5 xl:px-6">{Input.children}</main>;
}
