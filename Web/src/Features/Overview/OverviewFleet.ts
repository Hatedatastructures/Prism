import type { WorkerRecord } from '../../Services/AdminDataSource.ts';

export type OverviewWorkerView = 'grid' | 'list';

/** @brief 概览 Worker 搜索只匹配已载入记录，不改变来源快照或服务端筛选范围。 */
export function FilterOverviewWorkers(
    Rows: readonly WorkerRecord[],
    Query: string,
): readonly WorkerRecord[] {
    const Value = Query.trim().toLocaleLowerCase();
    if (Value.length === 0) return Rows;
    return Rows.filter(Row =>
        [Row.Id, Row.Name, Row.State, Row.Health].join(' ').toLocaleLowerCase().includes(Value));
}
