import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { DecodeConfigurationQuery } from '../../Api/OperationsApi';
import type { ConfigurationSnapshot } from '../../Api/OperationsApi';
import { QueryView, SectionHeading } from '../../Components/ResultView';
import { HasCapability, useAdminServices } from '../UseOperations';
import { ConfigurationEditor } from './ConfigurationEditor';

export default function ConfigurationPage(): ReactNode {
    const Services = useAdminServices();
    const CanRead = HasCapability(Services, 'configuration.read');
    const [Snapshot, SetSnapshot] = useState<ConfigurationSnapshot | null>(null);
    const Query = useQuery({
        queryKey: ['configuration', Services.Bootstrap.Process, Services.Bootstrap.Incarnation],
        queryFn: ({ signal }) => Services.Client.Query({ Path: '/Operations/Configuration',
            Signal: signal, Decode: DecodeConfigurationQuery }),
        enabled: CanRead, retry: false, refetchOnWindowFocus: false,
    });
    const SnapshotIsCurrent = !Query.isError && Query.data?.Ok === true &&
        Query.data.Value.Status === 'ok' && Query.data.Value.Value !== null;
    useEffect(() => {
        const Value = Query.data;
        if (Value?.Ok && Value.Value.Status === 'ok' && Value.Value.Value !== null) {
            SetSnapshot(Value.Value.Value);
        }
    }, [Query.data]);
    return <>
        <SectionHeading Eyebrow="CONFIGURATION" Title="配置"
            Description="读取当前公开配置，比较变更后先校验，再以同一配置版本确认发布。" />
        {!CanRead && <div className="notice notice-unavailable" role="status">配置读取能力未发布。</div>}
        {CanRead && Snapshot === null && <section className="panel"><QueryView Query={Query} Label="公共配置"
            Children={() => null} /></section>}
        {CanRead && Snapshot !== null && <section className="panel">
            {!SnapshotIsCurrent && <div className="notice notice-warn" role="status">
                当前读取未确认配置版本；草稿和上次结果仍保留，但校验与应用已暂停。请重新读取当前版本。</div>}
            <ConfigurationEditor Snapshot={Snapshot} SnapshotIsCurrent={SnapshotIsCurrent}
                OnRefresh={() => Query.refetch()} />
        </section>}
    </>;
}
