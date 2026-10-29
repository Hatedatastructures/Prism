import type { ReactNode } from 'react';
import { ArrowDown, ArrowRight, ArrowUp, Network, Server } from 'lucide-react';
import { FormatBytes, FormatCount, FormatRate } from '../../Components/Ui';
import type { OverviewSnapshot } from '../../Services/AdminDataSource';
import { TimeLink } from '../TimeLink';

/** @brief 将当前快照压成一条可横向比较的运行读数带。 */
export function OverviewReadingsPanel(Input: Readonly<{ Snapshot: OverviewSnapshot }>): ReactNode {
    const Value = Input.Snapshot, Traffic = Value.Traffic;
    return <section className="grid grid-cols-2 border-y sm:grid-cols-4" aria-label="当前运行读数">
        <Reading Icon={<ArrowDown />} Label="下行速率" Value={FormatRate(Traffic.Available ? Traffic.DownBytesPerSecond : null)}
            Detail={`累计 ${Traffic.Available ? FormatBytes(Traffic.DownBytes) : '未提供'}`} />
        <Reading Icon={<ArrowUp />} Label="上行速率" Value={FormatRate(Traffic.Available ? Traffic.UpBytesPerSecond : null)}
            Detail={`累计 ${Traffic.Available ? FormatBytes(Traffic.UpBytes) : '未提供'}`} />
        <Reading Icon={<Network />} Label="活动 TCP Session" Value={FormatCount(Value.Counts.TcpSessions)}
            Detail={`UDP ${OptionalCount(Value.Counts.UdpConnections)} · QUIC ${OptionalCount(Value.Counts.QuicConnections)}`} Path="/sessions" />
        <Reading Icon={<Server />} Label="接收中 Worker" Value={`${FormatCount(Value.Counts.WorkersAccepting)} / ${FormatCount(Value.Counts.WorkersTotal)}`}
            Detail={`活跃账户 ${FormatCount(Value.Counts.ActiveAccounts)} / ${FormatCount(Value.Counts.ConfiguredAccounts)}`} Path="/workers" />
    </section>;
}

function Reading(Input: Readonly<{ Icon: ReactNode; Label: string; Value: string; Detail: string; Path?: string }>): ReactNode {
    const Content = <dl><dt className="flex items-center gap-1.5 text-xs text-muted-foreground"><span className="[&_svg]:size-3.5" aria-hidden="true">{Input.Icon}</span>{Input.Label}</dt>
        <dd className="mt-1 flex items-center gap-2 text-lg font-semibold tracking-tight tabular-nums">{Input.Value}{Input.Path && <ArrowRight className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />}</dd>
        <dd className="mt-0.5 text-xs text-muted-foreground">{Input.Detail}</dd></dl>;
    const ClassName = 'min-w-0 border-b py-3 sm:border-b-0 sm:border-r sm:px-4 sm:first:pl-0 sm:last:border-r-0';
    return Input.Path ? <TimeLink className={`${ClassName} block rounded-sm hover:bg-muted/30 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring`} to={Input.Path}>{Content}</TimeLink>
        : <div className={ClassName}>{Content}</div>;
}

function OptionalCount(Value: string | number | null): string { return Value === null ? '未提供' : FormatCount(Value); }
