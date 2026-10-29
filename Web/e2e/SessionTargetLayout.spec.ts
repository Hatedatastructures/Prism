import { expect, test, type Locator, type Page } from '@playwright/test';

const TargetCases = [
    {
        Name: '未命中活动记录', Id: 'session-missing',
        Query: 'session=session-missing&process=PRISM-DEMO-01&identity_worker=worker-01&identity_account=acct-northstar&generation=42',
        Message: 'Session 已退出当前活动清单', HasIdentity: true,
    },
    {
        Name: '身份字段不足', Id: 'session-missing', Query: 'session=session-missing',
        Message: 'Session 身份字段不足', HasIdentity: false,
    },
    {
        Name: '同号记录身份不匹配', Id: 'session-1001',
        Query: 'session=session-1001&process=PRISM-DEMO-01&identity_worker=worker-01&identity_account=acct-northstar&generation=41',
        Message: '当前清单中的同 ID 记录身份不同', HasIdentity: true,
    },
] as const;

for (const Target of TargetCases) {
    test(`Session ${Target.Name}时保留详情位置与原始身份`, async ({ page }) => {
        await page.goto(`/sessions?source=demo&${Target.Query}`);
        const Inspector = page.getByRole('region', { name: `Session ${Target.Id} 详情`, exact: true });
        await expect(Inspector.getByText(Target.Message, { exact: true })).toBeVisible();
        await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr[data-state="selected"]')).toHaveCount(0);
        await expect(page.getByRole('button', { name: '取消 Session', exact: true })).toHaveCount(0);

        if (Target.HasIdentity) {
            const Identity = Inspector.locator('dl[aria-label="指定 Session 身份"]');
            await expect(Identity).toContainText(Target.Id);
            await expect(Identity).toContainText('PRISM-DEMO-01');
            await expect(Identity).toContainText('worker-01');
            await Inspector.getByRole('button', { name: '重新核对此 Session', exact: true }).click();
            await expect(Inspector.getByText(Target.Message, { exact: true })).toBeVisible();
        } else {
            await expect(Inspector.getByRole('button', { name: '重新核对此 Session', exact: true })).toHaveCount(0);
        }

        await ExpectTargetPlacement(page, Inspector);
        const Requested = new URLSearchParams(Target.Query);
        const Current = new URL(page.url()).searchParams;
        for (const [Key, Value] of Requested) expect(Current.get(Key)).toBe(Value);
    });
}

/** @brief 桌面详情与清单并排；手机返回清单保留目标并恢复焦点。 */
async function ExpectTargetPlacement(PageValue: Page, Inspector: Locator): Promise<void> {
    const Viewport = PageValue.viewportSize();
    const Directory = PageValue.getByRole('region', { name: 'Session 连接列表', exact: true });
    await expect(Inspector).toBeVisible();
    if ((Viewport?.width ?? 0) >= 1181) {
        await expect(Directory).toBeVisible();
        const DirectoryBounds = await Directory.boundingBox();
        const InspectorBounds = await Inspector.boundingBox();
        expect(DirectoryBounds).not.toBeNull();
        expect(InspectorBounds).not.toBeNull();
        expect(DirectoryBounds!.x + DirectoryBounds!.width).toBeLessThanOrEqual(InspectorBounds!.x + 1);
        expect(Math.abs(DirectoryBounds!.y - InspectorBounds!.y)).toBeLessThanOrEqual(1);
        expect(InspectorBounds!.y).toBeLessThan(Viewport!.height);
        expect(InspectorBounds!.x + InspectorBounds!.width).toBeLessThanOrEqual(Viewport!.width + 1);
    } else if ((Viewport?.width ?? 0) <= 767) {
        await expect(Directory).toBeHidden();
        await PageValue.getByRole('button', { name: '返回连接列表', exact: true }).click();
        await expect(Inspector).toBeHidden();
        await expect(Directory).toBeVisible();
        await expect(Directory).toBeFocused();
    } else {
        await expect(Directory).toBeVisible();
    }
    const HorizontalOverflow = await PageValue.evaluate(() =>
        document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(HorizontalOverflow).toBeLessThanOrEqual(1);
}
