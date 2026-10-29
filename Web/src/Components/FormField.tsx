import { useId } from 'react';
import type { HTMLInputTypeAttribute, InputHTMLAttributes, ReactNode } from 'react';

export type FormFieldProps = Readonly<{
    Label: string;
    Value: string;
    OnValueChange: (Value: string) => void;
    Hint?: ReactNode;
    Error?: ReactNode;
    Control?: 'input' | 'choice';
    Options?: readonly Readonly<{ Value: string; Label: string; Description?: string; Icon?: ReactNode }>[];
    InputType?: HTMLInputTypeAttribute;
    InputMode?: InputHTMLAttributes<HTMLInputElement>['inputMode'];
    Placeholder?: string;
    MaxLength?: number;
    Disabled?: boolean;
    Pending?: boolean;
    ClassName?: string;
    LabelClassName?: string;
    ControlClassName?: string;
}>;

export function FormField(Input: FormFieldProps): ReactNode {
    const Id = useId();
    const HasHint = Input.Hint !== undefined && Input.Hint !== null && Input.Hint !== false;
    const HasError = Input.Error !== undefined && Input.Error !== null && Input.Error !== false;
    const HintId = HasHint ? `${Id}-hint` : undefined;
    const ErrorId = HasError ? `${Id}-error` : undefined;
    const DescribedBy = [HintId, ErrorId].filter((Value): Value is string => !!Value).join(' ') || undefined;
    const LabelClassName = ['field-label', Input.LabelClassName].filter(Boolean).join(' ');
    const ControlClassName = ['field-input', Input.ControlClassName].filter(Boolean).join(' ');
    const Control = Input.Control === 'choice'
        ? <div id={Id} className={['segmented-choice-group', Input.ControlClassName].filter(Boolean).join(' ')}
            role="radiogroup" aria-labelledby={`${Id}-label`} aria-describedby={DescribedBy}
            aria-invalid={HasError || undefined} aria-busy={Input.Pending || undefined} aria-disabled={Input.Disabled || undefined}>
            {Input.Options?.map((Option, Index) => <label key={Option.Value} className="segmented-choice-option"
                data-selected={Input.Value === Option.Value}>
                {Option.Icon && <span className="segmented-choice-icon" aria-hidden="true">{Option.Icon}</span>}
                <span className="segmented-choice-copy"><strong>{Option.Label}</strong>
                    {Option.Description && <small id={`${Id}-option-${Index}-description`}>{Option.Description}</small>}
                </span>
                <input type="radio" name={Id} value={Option.Value} checked={Input.Value === Option.Value}
                    aria-label={Option.Label}
                    aria-describedby={Option.Description ? `${Id}-option-${Index}-description` : undefined}
                    onChange={() => Input.OnValueChange(Option.Value)} disabled={Input.Disabled} />
            </label>)}
        </div>
        : <input id={Id} className={ControlClassName} type={Input.InputType ?? 'text'} inputMode={Input.InputMode}
            value={Input.Value} onChange={Event => Input.OnValueChange(Event.target.value)}
            placeholder={Input.Placeholder} maxLength={Input.MaxLength} disabled={Input.Disabled}
            aria-invalid={HasError ? true : undefined} aria-describedby={DescribedBy} aria-busy={Input.Pending || undefined} />;

    return <div className={['field-shell', Input.ClassName].filter(Boolean).join(' ')}>
        {Input.Control === 'choice'
            ? <span id={`${Id}-label`} className={LabelClassName}>{Input.Label}</span>
            : <label htmlFor={Id} className={LabelClassName}>{Input.Label}</label>}
        {Control}
        {HasHint && <span id={HintId} className="field-hint">{Input.Hint}</span>}
        {HasError && <span id={ErrorId} className="field-error">{Input.Error}</span>}
    </div>;
}
