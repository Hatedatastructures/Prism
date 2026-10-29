import type { ReactNode } from 'react';
import { Card, CardContent } from '@/Components/ui/card';

/** 简短的当前快照读数，范围提示由调用方提供。 */
export function OverviewStat(Input: Readonly<{ Label: string; Value: string; Detail?: string; Icon?: ReactNode }>): ReactNode {
    return <Card className="min-w-0 gap-0 py-0 shadow-none"><CardContent className="px-4 py-4">
        <div className="flex items-center justify-between gap-2 text-sm font-medium"><span>{Input.Label}</span><span className="text-muted-foreground [&_svg]:size-4">{Input.Icon}</span></div>
        <div className="mt-2 text-2xl font-semibold tracking-tight tabular-nums">{Input.Value}</div>
        {Input.Detail && <p className="mt-1 truncate text-xs text-muted-foreground" title={Input.Detail}>{Input.Detail}</p>}
    </CardContent></Card>;
}
