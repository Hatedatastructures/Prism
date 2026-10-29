import { useRef, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { Button } from '@/Components/ui/button';
import { Alert, AlertDescription, AlertTitle } from '@/Components/ui/alert';
import { DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/Components/ui/dialog';
import type { ReactNode } from 'react';

export function ConfirmAction(Input: Readonly<{
    Label: string; Title: string; Description: string; ConfirmLabel: string;
    Disabled?: boolean; Busy?: boolean; Tone?: 'danger' | 'primary';
    OnConfirm: () => Promise<unknown>;
}>): ReactNode {
    const [Open, SetOpen] = useState(false);
    const [Submitting, SetSubmitting] = useState(false);
    const [Failure, SetFailure] = useState('');
    const SubmittingRef = useRef(false);
    const CancelButtonRef = useRef<HTMLButtonElement>(null);

    function HandleOpenChange(Value: boolean): void {
        if (!Value && SubmittingRef.current) return;
        SetOpen(Value);
        if (Value) SetFailure('');
    }

    async function Confirm(): Promise<void> {
        if (SubmittingRef.current || Input.Disabled || Input.Busy) return;
        SetFailure('');
        SubmittingRef.current = true;
        SetSubmitting(true);
        try {
            const Result: unknown = await Input.OnConfirm();
            if (typeof Result === 'object' && Result !== null && 'Ok' in Result && Result.Ok === false) {
                const Status = 'Status' in Result && typeof Result.Status === 'string' ? Result.Status : '';
                if (['accepted', 'running', 'unknown', 'interrupted'].includes(Status)) {
                    SetOpen(false);
                    return;
                }
                const Message = 'Message' in Result && typeof Result.Message === 'string'
                    ? Result.Message : '';
                SetFailure(Message.trim().length > 0 ? Message : 'Operations 未接受此操作。');
                return;
            }
            SetOpen(false);
        } catch (ErrorValue: unknown) {
            const Message = ErrorValue instanceof Error ? ErrorValue.message : '';
            SetFailure(Message.trim().length > 0 ? Message : '操作提交失败。');
        } finally {
            SubmittingRef.current = false;
            SetSubmitting(false);
        }
    }

    return <Dialog.Root open={Open} onOpenChange={HandleOpenChange}>
        <Dialog.Trigger asChild><Button type="button" variant={Input.Tone === 'danger' ? 'outline' : 'default'} disabled={Input.Disabled || Input.Busy}>{Input.Label}</Button></Dialog.Trigger>
        <DialogContent showCloseButton={false} aria-busy={Submitting}
            onOpenAutoFocus={Event => { Event.preventDefault(); CancelButtonRef.current?.focus(); }}
            onEscapeKeyDown={Event => { if (SubmittingRef.current) Event.preventDefault(); }}
            onInteractOutside={Event => { if (SubmittingRef.current) Event.preventDefault(); }}>
            <DialogHeader><DialogTitle>{Input.Title}</DialogTitle><DialogDescription>{Input.Description}</DialogDescription></DialogHeader>
            {Failure && <Alert variant="destructive"><AlertTitle>操作未完成</AlertTitle><AlertDescription>{Failure}</AlertDescription></Alert>}
            {Submitting && <p role="status" aria-live="polite" className="text-sm text-muted-foreground">正在提交请求…</p>}
            <DialogFooter><Dialog.Close asChild><Button ref={CancelButtonRef} variant="outline" disabled={Submitting}>返回</Button></Dialog.Close>
                <Button variant={Input.Tone === 'danger' ? 'destructive' : 'default'} onClick={() => void Confirm()} disabled={Input.Disabled || Input.Busy || Submitting}>{Submitting || Input.Busy ? '正在提交…' : Input.ConfirmLabel}</Button>
            </DialogFooter>
        </DialogContent>
    </Dialog.Root>;
}
