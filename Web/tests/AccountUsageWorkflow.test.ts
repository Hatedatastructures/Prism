import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';

registerHooks({
    resolve(Specifier, Context, NextResolve) {
        if (Specifier.startsWith('.') && !/\.[cm]?[jt]sx?$/i.test(Specifier)) {
            try { return NextResolve(Specifier, Context); } catch { return NextResolve(`${Specifier}.ts`, Context); }
        }
        return NextResolve(Specifier, Context);
    },
});

const { DemoAdminDataSource } = await import('../src/Services/DemoAdminDataSource.ts');

test('演示额度调整后读回新余额与修订，再次使用新修订成功', async () => {
    const Source = new DemoAdminDataSource();
    const Bootstrap = await Source.GetBootstrap({ Fresh: true });
    assert.ok(Bootstrap.Capabilities.includes('accounts.usage.read'));
    assert.ok(Bootstrap.Capabilities.includes('accounts.usage.adjust'));

    const Accounts = await Source.GetAccounts({ Cursor: '0', Limit: 50 });
    const Account = Accounts.Items.find(Value => Value.GroupId !== null && Value.GroupId !== undefined);
    assert.ok(Account, '演示工作流需要一个有周期额度的分组账户');
    const AccountKey = Account.AccountKey;
    assert.equal(AccountKey, Account.Id);
    assert.ok(AccountKey);

    const Before = await Source.GetAccountUsage(AccountKey);
    if (Before.LimitBytes === null) throw new Error('分组演示账户应提供有限额度');
    const Amount = 1_048_576n;
    const First = await Source.AdjustUsage({ AccountKey, Revision: Before.Revision,
        Kind: 'add_allowance', Bytes: Amount.toString(), Reason: 'focused workflow verification' });
    assert.equal(First.Status, 'completed');

    const AfterFirst = await Source.GetAccountUsage(AccountKey);
    if (AfterFirst.LimitBytes === null) throw new Error('调整后额度仍应保持有限');
    assert.equal(AfterFirst.Revision, (BigInt(Before.Revision) + 1n).toString());
    assert.equal(BigInt(AfterFirst.LimitBytes), BigInt(Before.LimitBytes) + Amount);

    const Second = await Source.AdjustUsage({ AccountKey, Revision: AfterFirst.Revision,
        Kind: 'add_allowance', Bytes: Amount.toString(), Reason: 'second adjustment uses refreshed revision' });
    assert.equal(Second.Status, 'completed');

    const AfterSecond = await Source.GetAccountUsage(AccountKey);
    if (AfterSecond.LimitBytes === null) throw new Error('二次调整后额度仍应保持有限');
    assert.equal(AfterSecond.Revision, (BigInt(AfterFirst.Revision) + 1n).toString());
    assert.equal(BigInt(AfterSecond.LimitBytes), BigInt(AfterFirst.LimitBytes) + Amount);
});
