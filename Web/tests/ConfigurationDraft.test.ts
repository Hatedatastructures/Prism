import assert from 'node:assert/strict';
import test from 'node:test';
import { ClearConfigurationDraft, GetConfigurationDraft, IsConfigurationDraftFor, SetConfigurationDraft } from '../src/App/ConfigurationDraft.ts';
import type { ConfigurationDraftSource } from '../src/App/ConfigurationDraft.ts';

const Source: ConfigurationDraftSource = { Mode: 'live', Identity: {
    InstanceKey: 'prism-instance', ProcessId: '7', Incarnation: 'a'.repeat(32),
} };
const Baseline = { Text: '{"Runtime":{}}', Generation: '4', Reloadable: true, UpdatedAt: '2026-10-17T00:00:00.000Z' };

test('draft is usable only for the same known mode and Bootstrap instance identity', () => {
    ClearConfigurationDraft();
    assert.equal(SetConfigurationDraft({ Text: '{"Runtime":{"WorkerCount":2}}', Baseline, Source }), true);
    const Draft = GetConfigurationDraft();
    assert.ok(Draft);
    assert.equal(IsConfigurationDraftFor(Draft, Source), true);
    assert.equal(IsConfigurationDraftFor(Draft, { ...Source, Mode: 'demo' }), false);
    assert.equal(IsConfigurationDraftFor(Draft, { ...Source, Identity: { ...Source.Identity!, Incarnation: 'b'.repeat(32) } }), false);
    assert.equal(IsConfigurationDraftFor(Draft, { ...Source, Identity: null }), false);
    assert.equal(SetConfigurationDraft({ Text: '{}', Baseline, Source: { ...Source, Mode: 'demo' } }), false);
    assert.equal(GetConfigurationDraft()?.Source.Mode, 'live');
    ClearConfigurationDraft();
    assert.equal(GetConfigurationDraft(), null);
});
