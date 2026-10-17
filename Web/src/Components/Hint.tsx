import type { ReactElement, ReactNode } from 'react';
import * as Tooltip from '@radix-ui/react-tooltip';

/** @brief 为图标控件提供悬停和键盘聚焦说明，操作语义仍由子控件拥有。 */
export function Hint(Input: Readonly<{ Label: string; children: ReactElement }>): ReactNode {
    return <Tooltip.Provider delayDuration={300}><Tooltip.Root>
        <Tooltip.Trigger asChild>{Input.children}</Tooltip.Trigger>
        <Tooltip.Portal><Tooltip.Content className="control-tooltip" sideOffset={7}>
            {Input.Label}<Tooltip.Arrow className="control-tooltip-arrow" />
        </Tooltip.Content></Tooltip.Portal>
    </Tooltip.Root></Tooltip.Provider>;
}
