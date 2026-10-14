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
    async function Confirm(): Promise<void> {
        if (Submitting || Input.Busy) return;
        SetSubmitting(true);
        try {
            await Input.OnConfirm();
        } finally {
            SetSubmitting(false);
            SetOpen(false);
        }
    }
    let Tone = 'button-primary';
    if (Input.Tone === 'danger') Tone = 'button-danger';
    let ConfirmText = Input.ConfirmLabel;
    if (Submitting || Input.Busy) ConfirmText = '正在提交…';
    return <Dialog.Root open={Open} onOpenChange={SetOpen}>
        <Dialog.Trigger asChild>
            <button className={`button ${Tone}`} disabled={Input.Disabled || Input.Busy}>
                {Input.Label}
            </button>
        </Dialog.Trigger>
        <Dialog.Portal>
            <Dialog.Overlay className="dialog-overlay" />
            <Dialog.Content className="dialog-content">
                <Dialog.Title>{Input.Title}</Dialog.Title>
                <Dialog.Description>{Input.Description}</Dialog.Description>
                <div className="dialog-actions">
                    <Dialog.Close asChild><button className="button button-secondary">返回</button></Dialog.Close>
                    <button className={`button ${Tone}`} onClick={() => void Confirm()}
                        disabled={Input.Busy || Submitting}>
                        {ConfirmText}
                    </button>
                </div>
            </Dialog.Content>
        </Dialog.Portal>
    </Dialog.Root>;
}
