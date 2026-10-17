import { useEffect, useSyncExternalStore } from 'react';
import type { ConfigurationSnapshot } from '../Services/AdminDataSource.ts';

export type ConfigurationDraftSource = Readonly<{
    Mode: 'live' | 'demo';
    Identity: Readonly<{ InstanceKey: string; ProcessId: string; Incarnation: string }> | null;
}>;
export type ConfigurationDraft = Readonly<{
    Text: string;
    Baseline: ConfigurationSnapshot;
    Source: ConfigurationDraftSource;
    UpdatedAt: string;
}>;
type ConfigurationDraftInput = Pick<ConfigurationDraft, 'Text' | 'Baseline' | 'Source'>;

let CurrentDraft: ConfigurationDraft | null = null;
const Listeners = new Set<() => void>();

function Subscribe(Listener: () => void): () => void {
    Listeners.add(Listener);
    return () => Listeners.delete(Listener);
}

export function GetConfigurationDraft(): ConfigurationDraft | null {
    return CurrentDraft;
}

function HasDraft(): boolean {
    return CurrentDraft !== null;
}

export function useConfigurationDraft(): ConfigurationDraft | null {
    return useSyncExternalStore(Subscribe, GetConfigurationDraft, () => null);
}

export function SetConfigurationDraft(Input: ConfigurationDraftInput): boolean {
    if (CurrentDraft && !IsConfigurationDraftFor(CurrentDraft, Input.Source)) return false;
    if (CurrentDraft && CurrentDraft.Text === Input.Text && CurrentDraft.Baseline.Generation === Input.Baseline.Generation &&
        CurrentDraft.Baseline.Text === Input.Baseline.Text) return true;
    CurrentDraft = { ...Input, UpdatedAt: new Date().toISOString() };
    for (const Listener of Listeners) Listener();
    return true;
}

export function IsConfigurationDraftFor(Draft: ConfigurationDraft, Source: ConfigurationDraftSource): boolean {
    const Original = Draft.Source.Identity, Current = Source.Identity;
    return Draft.Source.Mode === Source.Mode && Original !== null && Current !== null &&
        Original.InstanceKey.length > 0 && Original.ProcessId.length > 0 && Original.Incarnation.length > 0 &&
        Current.InstanceKey.length > 0 && Current.ProcessId.length > 0 && Current.Incarnation.length > 0 &&
        Original.InstanceKey === Current.InstanceKey && Original.ProcessId === Current.ProcessId &&
        Original.Incarnation === Current.Incarnation;
}

export function ClearConfigurationDraft(): void {
    if (CurrentDraft === null) return;
    CurrentDraft = null;
    for (const Listener of Listeners) Listener();
}

/** @brief 跨路由保留的草稿只驻留内存，浏览器关闭前提醒用户。 */
export function ConfigurationDraftUnloadGuard(): null {
    const Dirty = useSyncExternalStore(Subscribe, HasDraft, () => false);
    useEffect(() => {
        if (!Dirty) return;
        const WarnBeforeUnload = (Event: BeforeUnloadEvent): void => {
            Event.preventDefault();
            Event.returnValue = '';
        };
        window.addEventListener('beforeunload', WarnBeforeUnload);
        return () => window.removeEventListener('beforeunload', WarnBeforeUnload);
    }, [Dirty]);
    return null;
}
