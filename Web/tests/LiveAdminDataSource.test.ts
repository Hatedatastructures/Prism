import assert from 'node:assert/strict';
import test from 'node:test';
import { LiveAdminDataSource } from '../src/Services/LiveAdminDataSource.ts';
import { ChangeConfiguration } from '../src/Api/ConfigurationMutations.ts';

const Token = 'a'.repeat(64), Incarnation = 'b'.repeat(32);
const Bootstrap = { api_version: '2', instance_key: 'persisted', process_id: '1', process_incarnation: Incarnation, command_token: Token, capabilities: ['workers.drain', 'configuration.reload.validate', 'configuration.reload.apply'] };
const Worker = (Id: string, Process = '1', Generation = '4') => ({ id: Id, process: Process, generation: Generation,
    health: { status: 'healthy' }, queue: { depth: '0', capacity: '16' }, tasks: { started: '0', completed: '0', cancelled: '0' },
    dispatch: { accepted: '0', full: '0', closed: '0', unavailable: '0', generation_rejected: '0' },
    commands: { executed: '0', failed: '0' }, running: true, accepting: true, active_tasks: '0', dropped_events: '0', traffic: null });
const WorkerIdentity = (Id: string) => ({ Id, ProcessId: '1', GenerationId: '4' });
test('没有服务端筛选能力时只发正式支持的分页和精确ID', async () => {
    const Paths: string[] = [];
    const Source = new LiveAdminDataSource({ Fetch: async Path => {
        Paths.push(String(Path));
        return Response.json(String(Path).endsWith('Bootstrap') ? Bootstrap : { status: 'ok', value: { items: [], next_cursor: '0', has_more: false } });
    } });
    await Source.GetGroups({ Cursor: '0', Limit: 50, Query: 'name', State: 'active', Sort: 'traffic_desc' });
    const Groups = new URL(`http://localhost${Paths[1]}`);
    assert.equal(Groups.searchParams.has('q'), false); assert.equal(Groups.searchParams.has('state'), false); assert.equal(Groups.searchParams.has('sort'), false);
    await Source.GetAccounts({ Cursor: '0', Limit: 1, Id: '18446744073709551615' });
    assert.match(Paths[2] ?? '', /id=18446744073709551615/);
});
test('Drain/Revoke/Cancel/Reset所有现有命令无正文，保留完整作用域', async () => {
    const Requests: { Path: string; Init: RequestInit | undefined }[] = [];
    const Source = new LiveAdminDataSource({ Fetch: async (Path, Init) => {
        if (String(Path).endsWith('Bootstrap')) return Response.json({ ...Bootstrap, capabilities: ['workers.drain', 'accounts.revoke', 'sessions.cancel', 'streams.reset', 'tasks.cancel'] });
        if (String(Path).includes('/Workers?')) return Response.json({ status: 'ok', value: { items: [Worker('7')], next_cursor: '0', has_more: false } });
        Requests.push({ Path: String(Path), Init }); return Response.json({ status: 'accepted', operation: '10', message: 'queued' });
    } });
    await Source.DrainWorker(WorkerIdentity('7')); await Source.RevokeAccount('8', true);
    await Source.CancelSession({ Id: '9', ProcessId: '1', WorkerId: '7', AccountId: '8', GenerationId: '4' });
    await Source.ResetStream({ Id: '11', TaskId: '12', ParentTaskId: '13', ProcessId: '1', SessionId: '9', AccountId: '8', WorkerId: '7', GenerationId: '4' });
    await Source.CancelTask({ Id: '12', ProcessId: '1', WorkerId: '7', SessionId: '9', StreamId: '11', GenerationId: '4', ParentTaskId: '13' });
    assert.equal(Requests.length, 5);
    for (const Request of Requests) { assert.equal(Request.Init?.body, undefined); assert.equal(new Headers(Request.Init?.headers).get('Content-Type'), null); }
    assert.match(Requests[3]?.Path ?? '', /generation=4&worker=7&parent_task=13&task=12/);
    assert.match(Requests[4]?.Path ?? '', /Processes\/1\/Workers\/7\/Sessions\/9\/Tasks\/12\/Cancel/);
});
test('live 断线不退回演示快照', async () => {
    const Source = new LiveAdminDataSource({ Fetch: async () => { throw new Error('offline'); } });
    await assert.rejects(Source.GetOverview(), /无法连接/);
});
test('Bootstrap 并发只请求一次，领域快照与 JSON 不泄漏凭据', async () => {
    let Count = 0;
    const Source = new LiveAdminDataSource({ Fetch: async () => { ++Count; return Response.json(Bootstrap); } });
    const [First, Second] = await Promise.all([Source.GetBootstrap(), Source.GetBootstrap()]);
    assert.equal(Count, 1);
    assert.equal(First, Second);
    assert.equal(JSON.stringify(First).includes(Token), false);
    assert.equal(JSON.stringify(Source).includes(Token), false);
});
test('命令带当前实例请求头与本地尝试标识，已受理不伪装完成', async () => {
    const Calls: { Path: string; Init: RequestInit | undefined }[] = [];
    const Source = new LiveAdminDataSource({ Fetch: async (Path, Init) => {
        Calls.push({ Path: String(Path), Init });
        if (String(Path).endsWith('Bootstrap')) return Response.json(Bootstrap);
        if (String(Path).includes('/Workers?')) return Response.json({ status: 'ok', value: { items: [Worker('18446744073709551615')], next_cursor: '0', has_more: false } });
        return Response.json({ status: 'accepted', operation: '5', message: 'accepted' });
    } });
    const SourceWorkerIdentity = { Id: '18446744073709551615', ProcessId: '1', GenerationId: '4' };
    const Result = await Source.DrainWorker(SourceWorkerIdentity);
    assert.equal(Result.Status, 'accepted');
    const Action = Calls[Calls.length - 1];
    assert.match(Action?.Path ?? '', /worker=18446744073709551615/);
    const SentHeaders = new Headers(Action?.Init?.headers);
    assert.equal(SentHeaders.get('Authorization'), `Bearer ${Token}`);
    assert.equal(SentHeaders.get('X-Prism-Incarnation'), Incarnation);
    assert.ok(SentHeaders.get('Idempotency-Key'));
    assert.equal(Action?.Init?.body, undefined);
    assert.equal(SentHeaders.get('Content-Type'), null);
});
test('命令响应丢失返回未知且不自动重发', async () => {
    let Posts = 0;
    const Source = new LiveAdminDataSource({ Fetch: async (Path) => {
        if (String(Path).endsWith('Bootstrap')) return Response.json(Bootstrap);
        if (String(Path).includes('/Workers?')) return Response.json({ status: 'ok', value: { items: [Worker('8')], next_cursor: '0', has_more: false } });
        ++Posts; throw new Error('connection lost');
    } });
    const Result = await Source.DrainWorker(WorkerIdentity('8'));
    assert.equal(Result.Status, 'unknown');
    assert.match(Result.Message, /不要重复发送/);
    assert.ok(Result.LocalAttemptId);
    assert.equal(Posts, 1);
});
test('配置读取和提交不丢 uint64，并携带用户编辑时的 Generation', async () => {
    let Body = '';
    const Source = new LiveAdminDataSource({ Fetch: async (Path, Init) => {
        if (String(Path).endsWith('Bootstrap')) return Response.json(Bootstrap);
        if (String(Path).endsWith('Configuration')) return new Response('{"status":"ok","value":{"generation":"7","reloadable":true,"configuration":{"AccountGroups":[],"Accounts":[],"Huge":18446744073709551615}}}');
        Body = String(Init?.body);
        return Response.json({ status: 'completed', operation: '5', configuration_issues: [], message: 'done' });
    } });
    const Configuration = await Source.GetConfiguration();
    assert.match(Configuration.Text, /18446744073709551615/);
    await Source.ApplyConfiguration(Configuration.Text, false, Configuration.Generation);
    assert.match(Body, /"base_generation":"7"/);
    assert.match(Body, /18446744073709551615/);
});
test('组修改只影响目标并保留真实数值、未知正式字段与凭据引用', () => {
    const Source = '{"AccountGroups":[{"Id":"g","Name":"old","Policy":{"Bytes":18446744073709551615}}],"Accounts":[{"Id":"account","SecretRef":"env:REAL_SECRET","GroupId":"g"}],"Huge":18446744073709551615}';
    const Changed = ChangeConfiguration(Source, { Kind: 'rename-group', Id: 'g', Name: '新组' });
    assert.match(Changed, /"Name":"新组"/);
    assert.match(Changed, /18446744073709551615/);
    assert.match(Changed, /env:REAL_SECRET/);
    assert.throws(() => ChangeConfiguration(Source, { Kind: 'account-group', Id: 'missing', GroupId: null }), /已不存在/);
});
