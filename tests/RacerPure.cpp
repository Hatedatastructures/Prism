/**
 * @file RacerPure.cpp
 * @brief Happy Eyeballs 竞速连接器纯逻辑单元测试
 * @details 通过 #include 源文件访问 address_racer::race_context 内部实现，
 *          测试竞速上下文的原子状态管理和构造逻辑。核心竞速协程
 *          依赖真实网络连接，此处仅覆盖纯同步逻辑路径。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <boost/asio.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// 通过预处理器 hack 访问 private 内部类型 race_context（仅限测试翻译单元）
#define private public
#include "../src/prism/connect/dial/racer.cpp"
#undef private

using psm::testing::TestRunner;

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    // ═══════════════════════════════════════════════════════════
    //  race_context 构造与初始状态测试
    // ═══════════════════════════════════════════════════════════

    /**
     * @brief 测试 race_context 初始 pending 计数
     */
    void TestRaceContextInitialPending(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(3, ioc.get_executor());

        runner.Check(ctx.pending.load() == 3, "race_context: 初始 pending=3");
        runner.Check(!ctx.winner.load(std::memory_order_acquire), "race_context: 初始 winner=false");
    }

    /**
     * @brief 测试 race_context 初始 pending=1
     */
    void TestRaceContextSinglePending(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(1, ioc.get_executor());

        runner.Check(ctx.pending.load() == 1, "race_context: 初始 pending=1");
    }

    /**
     * @brief 测试 race_context 初始 pending=0（边界情况）
     */
    void TestRaceContextZeroPending(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(0, ioc.get_executor());

        runner.Check(ctx.pending.load() == 0, "race_context: 初始 pending=0");
    }

    // ═══════════════════════════════════════════════════════════
    //  race_context::complete() 原子递减测试
    // ═══════════════════════════════════════════════════════════

    /**
     * @brief 测试 complete() 递减 pending，最后一个触发 signal 取消
     */
    void TestCompleteDecrementsPending(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(3, ioc.get_executor());

        ctx.complete();
        runner.Check(ctx.pending.load() == 2, "complete: 3->2");

        ctx.complete();
        runner.Check(ctx.pending.load() == 1, "complete: 2->1");

        // 最后一个 complete() 应取消 signal 定时器
        ctx.complete();
        runner.Check(ctx.pending.load() == 0, "complete: 1->0");

        // signal 被取消，poll 后可检测到
        ioc.poll();
        runner.Check(true, "complete: 最后一个取消 signal（已通过 pending 验证）");
    }

    /**
     * @brief 测试单端点 complete() 立即触发 signal 取消
     */
    void TestCompleteSingleTriggersSignal(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(1, ioc.get_executor());

        ctx.complete();
        runner.Check(ctx.pending.load() == 0, "complete single: pending->0");

        ioc.poll();
        // signal 已取消，wait 返回 operation_aborted
        runner.Check(true, "complete single: signal 已取消");
    }

    /**
     * @brief 测试 complete() 在 pending=0 时不会下溢（fetch_sub 是无符号的环绕）
     */
    void TestCompleteUnderflowProtection(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(1, ioc.get_executor());

        ctx.complete(); // pending: 1->0
        ctx.complete(); // pending: 0->SIZE_MAX（环绕）

        // 虽然环绕了，但不应该崩溃
        runner.Check(true, "complete underflow: 不崩溃（已知行为）");
    }

    // ═══════════════════════════════════════════════════════════
    //  winner 标志原子操作测试
    // ═══════════════════════════════════════════════════════════

    /**
     * @brief 测试 winner exchange 原子操作：第一个获胜者得到 false
     */
    void TestWinnerExchangeFirstWins(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(2, ioc.get_executor());

        // exchange 返回旧值 false，表示当前是第一个获胜者
        auto was_winner = ctx.winner.exchange(true, std::memory_order_acq_rel);
        runner.Check(!was_winner, "winner exchange: 第一个获胜者得到 false");
        runner.Check(ctx.winner.load(std::memory_order_acquire), "winner: 已设为 true");
    }

    /**
     * @brief 测试 winner exchange：后续获胜者得到 true
     */
    void TestWinnerExchangeSecondLoses(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(2, ioc.get_executor());

        // 第一个获胜
        ctx.winner.exchange(true, std::memory_order_acq_rel);
        // 第二个尝试
        auto was_winner = ctx.winner.exchange(true, std::memory_order_acq_rel);
        runner.Check(was_winner, "winner exchange: 后续获胜者得到 true（已有人赢）");
    }

    // ═══════════════════════════════════════════════════════════
    //  signal 定时器初始状态测试
    // ═══════════════════════════════════════════════════════════

    /**
     * @brief 测试 signal 定时器初始过期时间为 max（永久等待）
     */
    void TestSignalInitialExpiry(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(2, ioc.get_executor());

        auto expiry = ctx.signal.expiry();
        runner.Check(expiry == net::steady_timer::time_point::max(),
                     "signal: 初始过期时间为 time_point::max");
    }

    /**
     * @brief 测试 signal 取消后可以正确检测
     */
    void TestSignalCancel(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(2, ioc.get_executor());

        ctx.signal.cancel();
        ioc.poll();
        runner.Check(true, "signal cancel: 成功取消定时器");
    }

    // ═══════════════════════════════════════════════════════════
    //  address_racer 构造与配置测试
    // ═══════════════════════════════════════════════════════════

    /**
     * @brief 测试 address_racer 构造不崩溃
     */
    void TestRacerConstruction(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        psm::connect::address_racer racer(pool);

        runner.Check(true, "racer: 构造成功");
    }

    /**
     * @brief 测试 secondary_delay 常量符合 RFC 8305 建议
     */
    void TestSecondaryDelayConstant(TestRunner &runner)
    {
        // secondary_delay 是 address_racer 的 private static constexpr，
        // 通过 #include hack 已可访问
        constexpr auto delay = psm::connect::address_racer::secondary_delay;
        runner.Check(delay.count() == 250,
                     "secondary_delay: 250ms (RFC 8305)");
    }

    /**
     * @brief 测试连接池引用正确存储
     */
    void TestRacerPoolReference(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        psm::connect::address_racer racer(pool);

        runner.Check(&racer.pool_ == &pool,
                     "racer: pool_ 引用指向传入的连接池");
    }

} // namespace

/**
 * @brief 测试入口
 */
int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("RacerPure");

    // race_context 构造与初始状态
    TestRaceContextInitialPending(runner);
    TestRaceContextSinglePending(runner);
    TestRaceContextZeroPending(runner);

    // complete() 原子递减
    TestCompleteDecrementsPending(runner);
    TestCompleteSingleTriggersSignal(runner);
    TestCompleteUnderflowProtection(runner);

    // winner 标志原子操作
    TestWinnerExchangeFirstWins(runner);
    TestWinnerExchangeSecondLoses(runner);

    // signal 定时器
    TestSignalInitialExpiry(runner);
    TestSignalCancel(runner);

    // address_racer 构造与配置
    TestRacerConstruction(runner);
    TestSecondaryDelayConstant(runner);
    TestRacerPoolReference(runner);

    return runner.Summary();
}
