import assert from 'node:assert/strict';
import test from 'node:test';
import { IntegerTicks } from '../src/Components/TimeSeriesGeometry.ts';

test('count axes retain zero and low peaks without duplicate labels', () => {
    assert.deepEqual(IntegerTicks(0), [0, 1]);
    assert.deepEqual(IntegerTicks(1), [0, 1]);
    assert.deepEqual(IntegerTicks(2), [0, 1, 2]);
});

test('count axes keep whole-number spacing and include their peak', () => {
    for (const Peak of [3, 7, 9, 27, 249, 2_486, 1_000_000]) {
        const Ticks = IntegerTicks(Peak);
        assert.equal(Ticks[0], 0);
        assert.ok(Ticks.at(-1)! >= Peak);
        assert.ok(Ticks.length <= 6);
        assert.equal(new Set(Ticks).size, Ticks.length);
        assert.ok(Ticks.every(Number.isInteger));
        assert.ok(Ticks.slice(1).every((Value, Index) => Value - Ticks[Index]! === Ticks[1]));
    }
});
