import type { ReactNode } from 'react';
import { useBootstrapIdentity } from './UseOperations';

export function FilterScopeNotice(Input: Readonly<{ Collection: string }>): ReactNode {
    const Bootstrap = useBootstrapIdentity();
    const Global = Bootstrap.data?.Capabilities.includes(`${Input.Collection}.filter`);
    return <p className="filter-scope-note">{Global ? '搜索、状态与资源筛选由服务端执行。' : '搜索与筛选仅作用于已载入记录；继续载入可扩大范围，指定 ID 会单独核对。'}</p>;
}
