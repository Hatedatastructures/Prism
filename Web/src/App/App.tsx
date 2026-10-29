import { Component, lazy, Suspense } from 'react';
import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Route, Routes, useLocation } from 'react-router';
import { EmptyState } from '../Components/Ui';
import { Alert, AlertDescription, AlertTitle } from '../Components/ui/alert';
import { Button } from '../Components/ui/button';
import { DemoAdminDataSource } from '../Services/DemoAdminDataSource';
import { LiveAdminDataSource } from '../Services/LiveAdminDataSource';
import type { AdminServices } from './AdminServices';
import { AppShell } from './AppShell';
import '../Styles/Theme.css';

const OverviewPage = lazy(() => import('../Features/Overview/OverviewPage'));
const IngressesPage = lazy(() => import('../Features/Ingresses/IngressesPage'));
const WorkersPage = lazy(() => import('../Features/Workers/WorkersPage'));
const AccountsPage = lazy(() => import('../Features/Accounts/AccountsPage'));
const UserGroupsPage = lazy(() => import('../Features/UserGroups/UserGroupsPage'));
const SessionsPage = lazy(() => import('../Features/Sessions/SessionsPage'));
const EventsPage = lazy(() => import('../Features/Events/EventsPage'));
const ConfigurationPage = lazy(() => import('../Features/Configuration/ConfigurationPage'));
const OperationsPage = lazy(() => import('../Features/Operations/OperationsPage'));
const ProtocolsPage = lazy(() => import('../Features/Protocols/ProtocolsPage'));
const ResourcesPage = lazy(() => import('../Features/Resources/ResourcesPage'));

const QueryClientValue = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false, staleTime: 2_000 } },
});
const RequestedSource = new URLSearchParams(window.location.search).get('source');
const Demo = RequestedSource === 'demo' || (RequestedSource !== 'live' && import.meta.env.VITE_OPERATIONS_MODE === 'demo');
const Services: AdminServices = { Data: Demo ? new DemoAdminDataSource() : new LiveAdminDataSource(), Mode: Demo ? 'demo' : 'live' };

export function App(): ReactNode {
    return <QueryClientProvider client={QueryClientValue}>
        <BrowserRouter>
            <Routes>
                <Route element={<AppShell Services={Services} />}>
                    <Route index element={<LazyPage><OverviewPage /></LazyPage>} />
                    <Route path="ingresses" element={<LazyPage><IngressesPage /></LazyPage>} />
                    <Route path="workers" element={<LazyPage><WorkersPage /></LazyPage>} />
                    <Route path="accounts" element={<LazyPage><AccountsPage /></LazyPage>} />
                    <Route path="user-groups" element={<LazyPage><UserGroupsPage /></LazyPage>} />
                    <Route path="sessions" element={<LazyPage><SessionsPage /></LazyPage>} />
                    <Route path="events" element={<LazyPage><EventsPage /></LazyPage>} />
                    <Route path="configuration" element={<LazyPage><ConfigurationPage /></LazyPage>} />
                    <Route path="operations" element={<LazyPage><OperationsPage /></LazyPage>} />
                    <Route path="protocols" element={<LazyPage><ProtocolsPage /></LazyPage>} />
                    <Route path="resources" element={<LazyPage><ResourcesPage /></LazyPage>} />
                    <Route path="*" element={<EmptyState Title="页面不存在" Detail="请从左侧导航中选择一个管理页面。" />} />
                </Route>
            </Routes>
        </BrowserRouter>
    </QueryClientProvider>;
}

function LazyPage(Input: Readonly<{ children: ReactNode }>): ReactNode {
    const Location = useLocation();
    return <PageErrorBoundary key={Location.pathname}><Suspense fallback={<div className="flex min-h-48 items-center justify-center text-sm text-muted-foreground" role="status">正在打开页面…</div>}>
        {Input.children}
    </Suspense></PageErrorBoundary>;
}

type PageErrorState = Readonly<{ Failed: boolean; Message: string }>;

class PageErrorBoundary extends Component<Readonly<{ children: ReactNode }>, PageErrorState> {
    public constructor(Props: Readonly<{ children: ReactNode }>) {
        super(Props);
        this.state = { Failed: false, Message: '' };
    }

    public static getDerivedStateFromError(Failure: unknown): PageErrorState { return { Failed: true, Message: Failure instanceof Error ? Failure.message : '页面渲染失败' }; }

    public override render(): ReactNode {
        if (this.state.Failed) return <Alert variant="destructive"><AlertTitle>页面显示异常</AlertTitle><AlertDescription className="space-y-3">数据解析或页面渲染失败，可以切换页面后重试。{import.meta.env.DEV && <details><summary>开发诊断</summary><code className="mt-2 block whitespace-pre-wrap break-all rounded-md bg-background/60 p-2 text-xs">{this.state.Message}</code></details>}<Button type="button" variant="outline" size="sm" onClick={() => window.location.reload()}>重新加载</Button></AlertDescription></Alert>;
        return this.props.children;
    }
}
