import { Fail, Success } from './Result';
import type { Result } from './Result';

export type JsonObject = Readonly<Record<string, unknown>>;
export type Decoder<Value> = (Input: unknown) => Result<Value>;

/** @brief 只接受 JSON 对象；解码保留未知字段但禁止用字符串猜测正式状态。 */
export function ObjectValue(Input: unknown): Result<JsonObject> {
    if (Input === null || typeof Input !== 'object' || Array.isArray(Input)) return ContractFailure();
    return Success(Input as JsonObject);
}

export function ContractFailure(): Result<never> {
    return Fail({ Kind: 'contract', Message: '服务端响应与当前管理 API 契约不一致',
        HttpStatus: null, MayHaveExecuted: false });
}

export function StringValue(Input: unknown): Result<string> {
    if (typeof Input !== 'string') return ContractFailure();
    return Success(Input);
}

export function BooleanValue(Input: unknown): Result<boolean> {
    if (typeof Input !== 'boolean') return ContractFailure();
    return Success(Input);
}

export function EnumValue<const Values extends readonly string[]>(
    Input: unknown, Allowed: Values,
): Result<Values[number]> {
    if (typeof Input !== 'string' || !Allowed.includes(Input)) return ContractFailure();
    return Success(Input as Values[number]);
}

export function ArrayValue<Value>(Input: unknown, Decode: Decoder<Value>): Result<readonly Value[]> {
    if (!Array.isArray(Input) || Input.length > 1024) return ContractFailure();
    const Output: Value[] = [];
    for (const Item of Input) {
        const Decoded = Decode(Item);
        if (!Decoded.Ok) return Decoded;
        Output.push(Decoded.Value);
    }
    return Success(Output);
}
