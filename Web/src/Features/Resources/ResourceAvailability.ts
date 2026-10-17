import { Fraction } from '../../Api/Analysis';
import { FormatBytes, FormatCount } from '../../Components/Ui';
import type { UInt64Value } from '../../Services/AdminDataSource';

export type MetricValueState = 'available' | 'unavailable' | 'missing' | 'zero-capacity' | 'invalid';
export type BytePoolUsage = Readonly<{ Value: number | null; State: MetricValueState }>;

export function AvailableBytes(Available: boolean, Value: UInt64Value | null): string {
    return Available && Value !== null ? FormatBytes(Value) : '未采集';
}

export function AvailableCount(Available: boolean, Value: UInt64Value | null): string {
    return Available && Value !== null ? FormatCount(Value) : '未采集';
}

export function DecideBytePoolUsage(
    Available: boolean,
    UsedBytes: UInt64Value | null,
    CapacityBytes: UInt64Value | null,
): BytePoolUsage {
    if (!Available) return { Value: null, State: 'unavailable' };
    if (UsedBytes === null || CapacityBytes === null) return { Value: null, State: 'missing' };
    if (BigInt(CapacityBytes) === 0n) return { Value: null, State: 'zero-capacity' };
    const Value = Fraction(UsedBytes, CapacityBytes);
    return Value === null ? { Value: null, State: 'invalid' } : { Value, State: 'available' };
}
