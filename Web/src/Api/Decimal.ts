import { Fail, Success } from './Result';
import type { Result } from './Result';

declare const DecimalIdentity: unique symbol;
/** @brief 无损 uint64 十进制值；所有身份、计数、游标与毫秒保持字符串。 */
export type Decimal = string & { readonly [DecimalIdentity]: true };
const Maximum = 18446744073709551615n;

/** @brief 拒绝数字、负号、前导零和溢出，避免 JSON 浮点身份静默失真。 */
export function DecodeDecimal(Value: unknown): Result<Decimal> {
    if (typeof Value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(Value) ||
        BigInt(Value) > Maximum) {
        return Fail({ Kind: 'contract', Message: '服务端返回了无效的 uint64 十进制值',
            HttpStatus: null, MayHaveExecuted: false });
    }
    return Success(Value as Decimal);
}

/** @brief 仅在日期可表示范围内转为 Number，身份与计数从不采用该转换。 */
export function FormatTime(Value: Decimal): string {
    const Milliseconds = BigInt(Value);
    if (Milliseconds === 0n) return '未提供';
    if (Milliseconds > 8640000000000000n) return '超出可显示日期范围';
    return new Intl.DateTimeFormat('zh-CN', {
        dateStyle: 'medium', timeStyle: 'medium', hour12: false,
    }).format(new Date(Number(Milliseconds)));
}

/** @brief BigInt 整数运算格式化字节，最大计数不会变成近似整数。 */
export function FormatBytes(Value: Decimal): string {
    const Bytes = BigInt(Value);
    const Units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'] as const;
    let Divisor = 1n;
    let Index = 0;
    while (Bytes / Divisor >= 1024n && Index < Units.length - 1) {
        Divisor *= 1024n;
        ++Index;
    }
    if (Index === 0) return `${Bytes.toLocaleString('zh-CN')} B`;
    const Whole = Bytes / Divisor;
    const Fraction = ((Bytes % Divisor) * 100n / Divisor).toString().padStart(2, '0');
    return `${Whole}.${Fraction} ${Units[Index]}`;
}
