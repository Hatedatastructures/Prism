import { useRef } from 'react';
import type { ReactNode } from 'react';
import { Search, X } from 'lucide-react';
import { SelectField } from './SelectField';

/** @brief 可清除的受控资源搜索输入框。 */
export function SearchField(Input: Readonly<{
    Label: string;
    Placeholder?: string;
    Value: string;
    OnValueChange: (Value: string) => void;
    ClassName?: string;
}>): ReactNode {
    const InputRef = useRef<HTMLInputElement>(null);
    const ClassName = ['search-field', 'resource-search-field', Input.ClassName]
        .filter(Boolean)
        .join(' ');

    function ClearValue(): void {
        Input.OnValueChange('');
        InputRef.current?.focus();
    }

    return <div className={ClassName}>
        <Search className="search-field-icon" size={16} aria-hidden="true" />
        <input
            ref={InputRef}
            className="search-field-input"
            aria-label={Input.Label}
            type="search"
            placeholder={Input.Placeholder}
            value={Input.Value}
            onChange={Event => Input.OnValueChange(Event.currentTarget.value)}
        />
        {Input.Value.length > 0 && <button
            className="search-field-clear"
            type="button"
            aria-label={`清除${Input.Label}`}
            onClick={ClearValue}
        >
            <X size={15} aria-hidden="true" />
        </button>}
    </div>;
}

/** @brief 基于 Radix Select 的受控资源筛选器。 */
export function FilterSelect(Input: Readonly<{
    Label: string;
    Value: string;
    Options: readonly Readonly<{ Value: string; Label: string }>[];
    OnValueChange: (Value: string) => void;
    Disabled?: boolean;
    ClassName?: string;
}>): ReactNode {
    return <SelectField
        Label={Input.Label}
        Value={Input.Value}
        Options={Input.Options}
        OnChange={Input.OnValueChange}
        Disabled={Input.Disabled ?? false}
        ClassName={['filter-select-trigger', Input.ClassName].filter(Boolean).join(' ')}
    />;
}
