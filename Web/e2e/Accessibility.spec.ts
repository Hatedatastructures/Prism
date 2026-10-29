import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page, type TestInfo } from '@playwright/test';

type Theme = 'light' | 'dark';
type Route = Readonly<{ Id: string; Path: string; Name: string }>;
type ThemeCase = Readonly<{ Id: Theme; Name: string }>;

const Routes: readonly Route[] = [
    { Id: 'Overview', Path: '/', Name: '运行概览' },
    { Id: 'Workers', Path: '/workers', Name: 'Worker' },
    { Id: 'Accounts', Path: '/accounts', Name: '代理账户' },
    { Id: 'UserGroups', Path: '/user-groups', Name: '用户组' },
    { Id: 'Sessions', Path: '/sessions', Name: 'Session 追踪' },
    { Id: 'Events', Path: '/events', Name: '事件流' },
    { Id: 'Ingresses', Path: '/ingresses', Name: '代理入口' },
    { Id: 'Protocols', Path: '/protocols', Name: '协议分析' },
    { Id: 'Resources', Path: '/resources', Name: '资源与数据质量' },
    { Id: 'Configuration', Path: '/configuration', Name: '配置' },
    { Id: 'Operations', Path: '/operations', Name: '操作中心' },
];

const Themes: readonly ThemeCase[] = [
    { Id: 'light', Name: '浅色' },
    { Id: 'dark', Name: '深色' },
];

const AxeTags = ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'];

test.setTimeout(30_000);

/** @brief 等待当前演示页面标题、加载状态与字体全部就绪。 */
async function WaitForPageReady(Page: Page): Promise<void> {
    await expect(Page.locator('main h1')).toBeVisible();
    await expect(Page.locator('.page-loading')).toHaveCount(0);
    await Page.evaluate(() => document.fonts.ready);
}

/** @brief 打开确定的演示路由并通过主题按钮设置扫描主题。 */
async function PrepareDemoPage(Page: Page, Path: string, Theme: Theme): Promise<void> {
    await Page.emulateMedia({ reducedMotion: 'reduce' });
    await Page.goto(`${Path}?source=demo`);
    await WaitForPageReady(Page);

    if (Theme === 'dark') {
        await Page.getByRole('button', { name: '切换深色主题', exact: true }).click();
    }
    await expect(Page.locator('html')).toHaveAttribute('data-theme', Theme);
}

/** @brief 附加完整 axe 结果并要求当前界面没有可检测违规。 */
async function AssertNoAxeViolations(Page: Page, TestInfo: TestInfo, AttachmentName: string): Promise<void> {
    const Results = await new AxeBuilder({ page: Page }).withTags(AxeTags).analyze();
    await TestInfo.attach(`${AttachmentName}.json`, {
        body: Buffer.from(JSON.stringify(Results, null, 2), 'utf8'),
        contentType: 'application/json',
    });
    expect(Results.violations).toEqual([]);
}

for (const Route of Routes) {
    for (const ThemeCase of Themes) {
        test(`无障碍 ${ThemeCase.Name}主题 ${Route.Name} ${Route.Path}`, async ({ page }, TestInfo) => {
            await PrepareDemoPage(page, Route.Path, ThemeCase.Id);
            if (Route.Id === 'Resources') {
                await expect(page.getByText('等待下一次采样，也可点击“刷新快照”。')).toBeVisible();
                await page.getByRole('button', { name: '刷新快照' }).click();
                await expect(page.getByRole('group', { name: /资源采样/ })).toBeVisible();
                await page.getByText('诊断明细', { exact: false }).click();
                await page.getByRole('button', { name: '刷新指标' }).click();
                await expect(page.getByRole('group', { name: /识别准入累计延迟分位桶下界/ })).toBeVisible();
            }
            await AssertNoAxeViolations(page, TestInfo, `axe-${Route.Id}-${ThemeCase.Id}`);
        });
    }
}

for (const ThemeCase of Themes) {
    test(`无障碍 ${ThemeCase.Name}主题交互状态`, async ({ page }, TestInfo) => {
        await PrepareDemoPage(page, '/', ThemeCase.Id);

        const SearchDialog = page.getByRole('dialog', { name: '搜索资源', exact: true });
        await page.keyboard.press('Control+k');
        await expect(SearchDialog).toBeVisible();
        await AssertNoAxeViolations(page, TestInfo, `axe-search-dialog-${ThemeCase.Id}`);
        for (const Key of ['Tab', 'Shift+Tab']) {
            for (let Step = 0; Step < 8; Step++) {
                await page.keyboard.press(Key);
                await expect.poll(() => SearchDialog.evaluate(Dialog => Dialog.contains(document.activeElement))).toBe(true);
            }
        }
        await page.keyboard.press('Escape');
        await expect(SearchDialog).toHaveCount(0);

        const MobileNavigation = page.getByRole('button', { name: '打开导航', exact: true });
        if (await MobileNavigation.isVisible()) {
            await MobileNavigation.click();
            const NavigationDrawer = page.locator('#primary-navigation');
            await expect(NavigationDrawer).toHaveAttribute('role', 'dialog');
            await expect(NavigationDrawer).toHaveAttribute('aria-modal', 'true');
            await AssertNoAxeViolations(page, TestInfo, `axe-navigation-drawer-${ThemeCase.Id}`);
            await page.keyboard.press('Escape');
            await expect(NavigationDrawer).not.toHaveAttribute('role', 'dialog');
        }

        await page.goto('/configuration?source=demo');
        await WaitForPageReady(page);
        await expect(page.locator('html')).toHaveAttribute('data-theme', ThemeCase.Id);

        const Editor = page.getByRole('textbox', { name: '配置 JSON', exact: true });
        await expect(Editor).toBeEditable();
        await Editor.fill('{');
        await expect(Editor).toHaveAttribute('aria-invalid', 'true');
        await expect(Editor).toHaveAttribute('aria-describedby', 'configuration-json-error');
        await expect(page.getByRole('alert')).toBeVisible();
        await AssertNoAxeViolations(page, TestInfo, `axe-invalid-configuration-${ThemeCase.Id}`);

        await page.goto('/accounts?source=demo');
        await WaitForPageReady(page);
        if ((page.viewportSize()?.width ?? 0) < 768) {
            const Directory = page.getByRole('list', { name: '账户列表' });
            await expect(Directory).toBeVisible();
            await Directory.getByRole('button', { name: /northstar/ }).click();
        }
        await page.getByRole('tab', { name: '周期额度', exact: true }).click();
        await page.locator('details.usage-adjustment > summary').click();
        await expect(page.getByRole('group', { name: '调整类型', exact: true })).toBeVisible();
        await page.getByRole('radio', { name: '释放异常占额', exact: true }).check();
        await AssertNoAxeViolations(page, TestInfo, `axe-account-adjustment-choice-${ThemeCase.Id}`);
    });
}
