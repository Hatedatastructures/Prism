import { ReloadDocument } from './ConfigurationDocument';
import { DecodeBootstrap } from './Bootstrap';
import type { Bootstrap, BootstrapCredential } from './Bootstrap';
import { Fail, Success } from './Result';
import type { ApiFailure, Result } from './Result';

export type HttpResponseData = Readonly<{ Status: number; Payload: unknown; Text: string }>;
export type ResponseDecoder<Value> = (Input: HttpResponseData) => Result<Value>;

type Request = Readonly<{
    Path: string; Signal: AbortSignal | null; Method: 'GET' | 'POST';
    Body: string | null; Token: string | null;
}>;
const ResponseBudget = 2 * 1024 * 1024;

/** @brief 同源管理客户端是令牌唯一拥有者；查询可取消，变更请求绝不自动重发。 */
export class ApiClient {
    private Credential: BootstrapCredential | null = null;

    public async Bootstrap(Signal: AbortSignal): Promise<Result<Bootstrap>> {
        this.Credential = null;
        const Response = await this.Request({ Path: '/Operations/Bootstrap', Signal,
            Method: 'GET', Body: null, Token: null });
        if (!Response.Ok) return Response;
        if (Response.Value.Status !== 200) return this.HttpFailure(Response.Value.Status, false);
        const Decoded = DecodeBootstrap(Response.Value.Payload);
        if (!Decoded.Ok) return Fail({ ...Decoded.Failure,
            HttpStatus: Response.Value.Status, MayHaveExecuted: false });
        this.Credential = Decoded.Value;
        return Success(Decoded.Value.Public);
    }

    /** @brief Query 的 Signal 由 Query owner 管理；取消读取不推断业务关闭。 */
    public async Query<Value>(Input: Readonly<{
        Path: string; Signal: AbortSignal; Decode: ResponseDecoder<Value>;
    }>): Promise<Result<Value>> {
        const Response = await this.Request({ Path: Input.Path, Signal: Input.Signal,
            Method: 'GET', Body: null, Token: null });
        if (!Response.Ok) return Response;
        if (Response.Value.Status === 401 || Response.Value.Status === 403) {
            return this.HttpFailure(Response.Value.Status, false);
        }
        const Decoded = Input.Decode(Response.Value);
        if (!Decoded.Ok) return Fail({ ...Decoded.Failure,
            HttpStatus: Response.Value.Status, MayHaveExecuted: false });
        return Decoded;
    }

    /** @brief 单次 POST；凭据或进程身份变动先拒绝，网络失联保留执行状态未知。 */
    public async Command<Value>(Input: Readonly<{
        Path: string; Bootstrap: Bootstrap; Body: unknown; Decode: ResponseDecoder<Value>;
    }>): Promise<Result<Value>> {
        const Credential = this.Credential;
        if (Credential === null) {
            return Fail({ Kind: 'incarnation', Message: '当前管理凭据尚未确认，命令未发送；请重新连接后再确认操作',
                HttpStatus: null, MayHaveExecuted: false });
        }
        if (Credential.Public.Process !== Input.Bootstrap.Process ||
            Credential.Public.Incarnation !== Input.Bootstrap.Incarnation) {
            return Fail({ Kind: 'incarnation', Message: '进程身份已变化，请刷新后重新确认操作',
                HttpStatus: null, MayHaveExecuted: false });
        }
        const Body = this.EncodeCommandBody(Input.Body);
        if (!Body.Ok) return Body;
        const Response = await this.Request({ Path: Input.Path, Signal: null,
            Method: 'POST', Body: Body.Value, Token: Credential.Token });
        if (!Response.Ok) return Response;
        if (Response.Value.Status === 401 || Response.Value.Status === 403) {
            return this.HttpFailure(Response.Value.Status, false);
        }
        const Decoded = Input.Decode(Response.Value);
        if (!Decoded.Ok) {
            return Fail({ ...Decoded.Failure, HttpStatus: Response.Value.Status,
                MayHaveExecuted: this.CommandMayHaveExecuted(Response.Value.Status) });
        }
        return Decoded;
    }

    private EncodeCommandBody(Value: unknown): Result<string | null> {
        if (Value === null) return Success(null);
        if (Value instanceof ReloadDocument) return Success(Value.Encode());
        try {
            const Encoded = JSON.stringify(Value);
            if (Encoded === undefined) return this.BodyFailure('命令正文不能编码为 JSON');
            if (new TextEncoder().encode(Encoded).length > 65536) {
                return this.BodyFailure('命令正文超过 64 KiB 限值');
            }
            return Success(Encoded);
        } catch {
            return this.BodyFailure('命令正文验证失败，尚未发送');
        }
    }

    private BodyFailure(Message: string): Result<never> {
        return Fail({ Kind: 'contract', Message, HttpStatus: null, MayHaveExecuted: false });
    }

    private CommandMayHaveExecuted(Status: number): boolean {
        return Status === 200 || Status === 202 || Status === 409 || Status >= 500;
    }

    /** @brief 验证字面 loopback authority；不提供跨源 URL、proxy 或 CORS fallback。 */
    private ValidatePath(Path: string): Result<string> {
        if (!['127.0.0.1', 'localhost', '[::1]'].includes(window.location.hostname) ||
            window.location.protocol !== 'http:' || !Path.startsWith('/Operations/') ||
            Path.includes('#') || Path.includes('\\') || Path.includes('\r') || Path.includes('\n')) {
            return Fail({ Kind: 'authority', Message: '管理页面只能从本机管理监听器同源访问',
                HttpStatus: null, MayHaveExecuted: false });
        }
        const Url = new URL(Path, window.location.origin);
        if (Url.origin !== window.location.origin || !Url.pathname.startsWith('/Operations/')) {
            return Fail({ Kind: 'authority', Message: '请求不属于当前管理入口',
                HttpStatus: null, MayHaveExecuted: false });
        }
        return Success(Url.href);
    }

    private async Request(Input: Request): Promise<Result<HttpResponseData>> {
        const Url = this.ValidatePath(Input.Path);
        if (!Url.Ok) return Url;
        const RequestHeaders = new Headers({ Accept: 'application/json' });
        if (Input.Token !== null) RequestHeaders.set('Authorization', `Bearer ${Input.Token}`);
        if (Input.Body !== null) RequestHeaders.set('Content-Type', 'application/json');
        const Options: RequestInit = { method: Input.Method, headers: RequestHeaders,
            credentials: 'omit', cache: 'no-store', redirect: 'error', body: Input.Body };
        if (Input.Signal !== null) Options.signal = Input.Signal;
        try {
            const Response = await fetch(Url.Value, Options);
            if (!Response.headers.get('content-type')?.startsWith('application/json')) {
                return this.ResponseFailure(Input, Response.status, '服务端响应不是 JSON');
            }
            if (Input.Path === '/Operations/Bootstrap' &&
                Response.headers.get('cache-control') !== 'no-store') {
                return this.ResponseFailure(Input, Response.status, 'Bootstrap 缺少禁止缓存契约');
            }
            const Text = await this.ReadBounded(Response);
            if (!Text.Ok) {
                return Fail({ ...Text.Failure,
                    MayHaveExecuted: Input.Method === 'POST' &&
                        this.CommandMayHaveExecuted(Response.status) });
            }
            const Payload: unknown = JSON.parse(Text.Value);
            return Success({ Status: Response.status, Payload, Text: Text.Value });
        } catch (Error: unknown) {
            let Kind: ApiFailure['Kind'] = 'network';
            if (Input.Signal?.aborted) Kind = 'cancelled';
            if (Error instanceof SyntaxError) Kind = 'contract';
            return Fail({ Kind, Message: '管理连接未得到可验证响应', HttpStatus: null,
                MayHaveExecuted: Input.Method === 'POST' });
        }
    }

    private HttpFailure(Status: number, MayHaveExecuted: boolean): Result<never> {
        return Fail({ Kind: 'http', Message: `管理请求被拒绝（HTTP ${Status}）`,
            HttpStatus: Status, MayHaveExecuted });
    }

    private ResponseFailure(Input: Request, Status: number, Message: string): Result<never> {
        return Fail({ Kind: 'contract', Message, HttpStatus: Status,
            MayHaveExecuted: Input.Method === 'POST' && this.CommandMayHaveExecuted(Status) });
    }

    /** @brief 流式读取实际字节预算；超限取消该响应流，不在未知长度下无界分配。 */
    private async ReadBounded(Response: Response): Promise<Result<string>> {
        if (Response.body === null) return Fail({ Kind: 'contract', Message: '管理响应缺少正文',
            HttpStatus: Response.status, MayHaveExecuted: false });
        const Reader = Response.body.getReader();
        const Decoder = new TextDecoder('utf-8', { fatal: true });
        let Bytes = 0;
        let Text = '';
        try {
            for (;;) {
                const Chunk = await Reader.read();
                if (Chunk.done) break;
                Bytes += Chunk.value.byteLength;
                if (Bytes > ResponseBudget) {
                    await Reader.cancel();
                    return Fail({ Kind: 'contract', Message: '管理响应超过实际字节预算',
                        HttpStatus: Response.status, MayHaveExecuted: false });
                }
                Text += Decoder.decode(Chunk.value, { stream: true });
            }
            return Success(Text + Decoder.decode());
        } finally {
            Reader.releaseLock();
        }
    }
}

