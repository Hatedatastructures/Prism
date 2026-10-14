import { Component, lazy, Suspense, useEffect, useRef } from 'react';
import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { BrowserRouter, Route, Routes } from 'react-router';
import { ApiClient } from '../Api/ApiClient';
import type { Bootstrap } from '../Api/Bootstrap';
import { Bind } from '../Features/Operations/OperationStore';
import { LoadingState, FailureNotice, EmptyState } from '../Components/ResultView';
import type { AdminServices } from './AdminServices';
import { AppShell } from './AppShell';
import '../Styles/Theme.css';

const OverviewPage = lazy(() => import('../Features/Overview/OverviewPage'));
const WorkersPage = lazy(() => import('../Features/Workers/WorkersPage'));
const AccountsPage = lazy(() => import('../Features/Accounts/AccountsPage'));
const SessionsPage = lazy(() => import('../Features/Sessions/SessionsPage'));
const EventsPage = lazy(() => import('../Features/Events/EventsPage'));
const ConfigurationPage = lazy(() => import('../Features/Configuration/ConfigurationPage'));
const OperationsPage = lazy(() => import('../Features/Operations/OperationsPage'));

const Client = new ApiClient();
const QueryClientValue = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: true,
        refetchOnReconnect: true, refetchIntervalInBackground: false } },
});

export function App(): ReactNode {
    return <QueryClientProvider client={QueryClientValue}><BootstrapGate /></QueryClientProvider>;
}

function BootstrapGate(): ReactNode {
    const BootstrapQuery = useQuery({
        queryKey: ['bootstrap'],
        queryFn: ({ signal }) => Client.Bootstrap(signal),
        staleTime: 0,
        refetchInterval: 10000,
        refetchIntervalInBackground: false,
        retry: false,
    });
    if (BootstrapQuery.isPending) return <main className="startup-screen"><LoadingState Label="管理进程身份" /></main>;
    if (BootstrapQuery.isError) return <main className="startup-screen">
        <FailureNotice Failure={{ Kind: 'network', Message: '无法连接本机管理入口',
            HttpStatus: null, MayHaveExecuted: false }} OnRetry={() => void BootstrapQuery.refetch()} />
    </main>;
    const ResultValue = BootstrapQuery.data;
    if (!ResultValue.Ok) return <main className="startup-screen">
        <FailureNotice Failure={ResultValue.Failure} OnRetry={() => void BootstrapQuery.refetch()} />
    </main>;
    return <IdentityRouter Bootstrap={ResultValue.Value} />;
}

function IdentityRouter(Input: Readonly<{ Bootstrap: Bootstrap }>): ReactNode {
    const PreviousIdentity = useRef('');
    const Identity = `${Input.Bootstrap.Process}:${Input.Bootstrap.Incarnation}`;
    useEffect(() => {
        if (PreviousIdentity.current.length > 0 && PreviousIdentity.current !== Identity) {
            QueryClientValue.removeQueries({ predicate: Query => Query.queryKey[0] !== 'bootstrap' });
        }
        PreviousIdentity.current = Identity;
        Bind(Input.Bootstrap);
    }, [Identity, Input.Bootstrap]);
    const Services: AdminServices = { Client, Bootstrap: Input.Bootstrap };
    return <BrowserRouter key={Identity}>
        <Routes>
            <Route element={<AppShell Services={Services} />}>
                <Route index element={<LazyPage><OverviewPage /></LazyPage>} />
                <Route path="workers" element={<LazyPage><WorkersPage /></LazyPage>} />
                <Route path="accounts" element={<LazyPage><AccountsPage /></LazyPage>} />
                <Route path="sessions" element={<LazyPage><SessionsPage /></LazyPage>} />
                <Route path="events" element={<LazyPage><EventsPage /></LazyPage>} />
                <Route path="configuration" element={<LazyPage><ConfigurationPage /></LazyPage>} />
                <Route path="operations" element={<LazyPage><OperationsPage /></LazyPage>} />
                <Route path="*" element={<EmptyState Title="页面不存在" Detail="请从左侧导航选择管理页面。" />} />
            </Route>
        </Routes>
    </BrowserRouter>;
}

function LazyPage(Input: Readonly<{ children: ReactNode }>): ReactNode {
    return <PageErrorBoundary><Suspense fallback={<LoadingState Label="页面模块" />}>
        {Input.children}
    </Suspense></PageErrorBoundary>;
}

type PageErrorState = Readonly<{ Failed: boolean }>;

class PageErrorBoundary extends Component<Readonly<{ children: ReactNode }>, PageErrorState> {
    public constructor(Props: Readonly<{ children: ReactNode }>) {
        super(Props);
        this.state = { Failed: false };
    }

    public static getDerivedStateFromError(): PageErrorState {
        return { Failed: true };
    }

    public override render(): ReactNode {
        if (this.state.Failed) return <section className="notice notice-error" role="alert">
            <div><strong>此页面暂时无法显示</strong>
                <p>页面资源或内容未能加载。重新加载后可再次读取。</p></div>
            <button className="button button-secondary" onClick={() => window.location.reload()}>
                重新加载页面
            </button>
        </section>;
        return this.props.children;
    }
}
