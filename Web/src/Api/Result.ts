/** @brief API 普通失败按值返回；命令发送之后失联必须保留执行状态未知的事实。 */
export type ApiFailure = Readonly<{
    Kind: 'network' | 'cancelled' | 'http' | 'contract' | 'version' | 'authority' | 'incarnation';
    Message: string;
    HttpStatus: number | null;
    MayHaveExecuted: boolean;
}>;

export type Result<Value> =
    | Readonly<{ Ok: true; Value: Value }>
    | Readonly<{ Ok: false; Failure: ApiFailure }>;

/** @brief 成功值自有生命周期，不再借用响应流。 */
export function Success<Value>(Value: Value): Result<Value> {
    return { Ok: true, Value };
}

/** @brief 组装调用阶段已确认的错误，不猜测服务端业务状态。 */
export function Fail(Failure: ApiFailure): Result<never> {
    return { Ok: false, Failure };
}
