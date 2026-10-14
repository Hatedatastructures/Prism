import { ContractFailure, ObjectValue, StringValue } from './Decode';
import { DecodeDecimal } from './Decimal';
import type { Decimal } from './Decimal';
import { Fail, Success } from './Result';
import type { Result } from './Result';

/** @brief 只公开值身份与能力；命令令牌留在 ApiClient 内存，不进入组件、日志或 storage。 */
export type Bootstrap = Readonly<{
    ApiVersion: '1'; Process: Decimal; Incarnation: string; Capabilities: readonly string[];
}>;

export type BootstrapCredential = Readonly<{ Public: Bootstrap; Token: string }>;

/** @brief api_version 不匹配即停止解码与命令发送，不能假定新版本兼容。 */
export function DecodeBootstrap(Input: unknown): Result<BootstrapCredential> {
    const Object = ObjectValue(Input);
    if (!Object.Ok) return Object;
    const Value = Object.Value;
    if (Value.api_version !== '1') return Fail({ Kind: 'version',
        Message: '管理 API 版本不匹配，请使用与当前主程序一致的页面',
        HttpStatus: null, MayHaveExecuted: false });
    const Process = DecodeDecimal(Value.process_id);
    const Incarnation = StringValue(Value.process_incarnation);
    const Token = StringValue(Value.command_token);
    if (!Process.Ok) return Process;
    if (!Incarnation.Ok) return Incarnation;
    if (!Token.Ok) return Token;
    if (Process.Value === '0' || !/^[0-9a-f]{32}$/.test(Incarnation.Value) ||
        !/^[0-9a-f]{64}$/.test(Token.Value) || !Array.isArray(Value.capabilities) ||
        Value.capabilities.length > 64 ||
        !Value.capabilities.every(Item => typeof Item === 'string' && /^[a-z]+(?:\.[a-z_]+)+$/.test(Item))) {
        return ContractFailure();
    }
    const Capabilities = Value.capabilities as string[];
    if (new Set(Capabilities).size !== Capabilities.length) return ContractFailure();
    return Success({ Public: { ApiVersion: '1', Process: Process.Value,
        Incarnation: Incarnation.Value, Capabilities: [...Capabilities] }, Token: Token.Value });
}
