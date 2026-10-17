import { useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import type { ReactNode } from 'react';

export function ConfirmAction(Input: Readonly<{
    Label: string; Title: string; Description: string; ConfirmLabel: string;
    Disabled?: boolean; Busy?: boolean; Tone?: 'danger' | 'primary';
    OnConfirm: () => Promise<unknown>;
}>): ReactNode {
    const [Open, SetOpen] = useState(false);
    const [Submitting, SetSubmitting] = useState(false);
    const [Failure, SetFailure] = useState('');
    async function Confirm(): Promise<void> {
        if (Submitting || Input.Busy) return;
        SetFailure('');
        SetSubmitting(true);
        try {
            const Result: unknown = await Input.OnConfirm();
            if (typeof Result === 'object' && Result !== null && 'Ok' in Result && Result.Ok === false) {
                SetFailure('Message' in Result && typeof Result.Message === 'string'
                    ? Result.Message : 'Operations 未接受此操作。');
                return;
            }
            SetOpen(false);
        } catch (ErrorValue: unknown) {
            SetFailure(ErrorValue instanceof Error ? ErrorValue.message : '操作提交失败。');
        } finally {
            SetSubmitting(false);
        }
    }
    const Tone = Input.Tone === 'danger' ? 'button-danger' : 'button-primary';
    const ConfirmText = Submitting || Input.Busy ? '正在提交…' : Input.ConfirmLabel;
    return <Dialog.Root open={Open} onOpenChange={Value => { SetOpen(Value); if (Value) SetFailure(''); }}>
        <Dialog.Trigger asChild>
            <button type="button" className={'button ' + (Input.Tone === 'danger' ? 'button-danger-outline' : Tone)} disabled={Input.Disabled || Input.Busy}>{Input.Label}</button>
        </Dialog.Trigger>
        <Dialog.Portal>
            <Dialog.Overlay className="dialog-overlay" />
            <Dialog.Content className="dialog-content">
                <Dialog.Title>{Input.Title}</Dialog.Title>
                <Dialog.Description>{Input.Description}</Dialog.Description>
                {Failure.length > 0 && <div className="notice notice-danger dialog-error" role="alert">{Failure}</div>}
                <div className="dialog-actions">
                    <Dialog.Close asChild><button className="button button-secondary">返回</button></Dialog.Close>
                    <button className={'button ' + Tone} onClick={() => void Confirm()} disabled={Input.Busy || Submitting}>
                        {ConfirmText}
                    </button>
                </div>
            </Dialog.Content>
        </Dialog.Portal>
    </Dialog.Root>;
}
