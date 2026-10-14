import { useState } from 'react';
import type { ReactNode } from 'react';
import { NavLink, Outlet } from 'react-router';
import type { AdminServices } from './AdminServices';
import { useOperationNotice } from '../Features/Operations/OperationStore';

const Navigation = [
    { Path: '/', Label: '概览', Mark: '01' },
    { Path: '/workers', Label: 'Worker', Mark: '02' },
    { Path: '/accounts', Label: '账户', Mark: '03' },
    { Path: '/sessions', Label: '会话与任务', Mark: '04' },
    { Path: '/events', Label: '事件', Mark: '05' },
    { Path: '/configuration', Label: '配置', Mark: '06' },
    { Path: '/operations', Label: '操作中心', Mark: '07' },
] as const;

export function AppShell(Input: Readonly<{ Services: AdminServices }>): ReactNode {
    const [Dark, SetDark] = useState(false);
    const Notice = useOperationNotice();
    let Theme = 'light';
    let ThemeLabel = '切换深色主题';
    if (Dark) {
        Theme = 'dark';
        ThemeLabel = '切换浅色主题';
    }
    return <div className="app-frame" data-theme={Theme}>
        <a className="skip-link" href="#main-content">跳到主要内容</a>
        <aside className="sidebar" aria-label="主导航">
            <div className="brand"><span className="brand-mark">P</span>
                <div><strong>Prism</strong><small>本机管理控制台</small></div></div>
            <nav className="primary-nav" aria-label="管理页面">
                <span className="nav-caption">工作区</span>
                {Navigation.map(Item => <NavLink key={Item.Path} to={Item.Path} end={Item.Path === '/'}
                    className="nav-link"><span className="nav-mark">{Item.Mark}</span>{Item.Label}</NavLink>)}
            </nav>
            <div className="sidebar-foot"><span className="connection-dot" aria-hidden="true" />
                仅限本机 loopback</div>
        </aside>
        <div className="workspace">
            <header className="topbar">
                <div className="process-pill"><span>管理进程</span>
                    <strong>{Input.Services.Bootstrap.Process}</strong>
                </div>
                <button className="theme-toggle" aria-pressed={Dark}
                    onClick={() => SetDark(!Dark)}>{ThemeLabel}</button>
            </header>
            <main id="main-content" className="main-content" tabIndex={-1}>
                {Notice.length > 0 && <div className="notice notice-warn" role="status">{Notice}</div>}
                <Outlet context={Input.Services} />
            </main>
            <footer className="workspace-footer">Prism Preview · API v{Input.Services.Bootstrap.ApiVersion}
                <span>页面仅展示本机 Operations 返回的数据</span></footer>
        </div>
    </div>;
}
