import type { ReactNode } from 'react';
import * as Select from '@radix-ui/react-select';
import { Check, ChevronDown } from 'lucide-react';

/** @brief 共享单选控件；Radix 拥有浮层、键盘选择及关闭后的焦点恢复。 */
export function SelectField(Input: Readonly<{
    Label: string; Value: string; Options: readonly Readonly<{ Value: string; Label: string }>[];
    OnChange: (Value: string) => void;
}>): ReactNode {
    return <Select.Root value={Input.Value} onValueChange={Input.OnChange}>
        <Select.Trigger className="select-trigger" aria-label={Input.Label}>
            <Select.Value /><Select.Icon><ChevronDown size={14} aria-hidden="true" /></Select.Icon>
        </Select.Trigger>
        <Select.Portal><Select.Content className="select-content" position="popper" sideOffset={6}>
            <Select.Viewport>{Input.Options.map(Option => <Select.Item className="select-item" value={Option.Value} key={Option.Value}>
                <Select.ItemText>{Option.Label}</Select.ItemText>
                <Select.ItemIndicator><Check size={14} aria-hidden="true" /></Select.ItemIndicator>
            </Select.Item>)}</Select.Viewport>
        </Select.Content></Select.Portal>
    </Select.Root>;
}
