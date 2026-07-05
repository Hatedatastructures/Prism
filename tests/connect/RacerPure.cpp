/**
 * @file RacerPure.cpp
 * @brief Happy Eyeballs 竞速连接器纯逻辑单元测试
 * @details 通过 #include 源文件访问 address_racer::race_context 内部实现，
 *          测试竞速上下文的原子状态管理和构造逻辑。核心竞速协程
 *          依赖真实网络连接，此处仅覆盖纯同步逻辑路径。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>

#include <boost/asio.hpp>


#include <gtest/gtest.h>

// 通过预处理器 hack 访问 private 内部类型 race_context（仅限测试翻译单元）
#define private public
#include "../../src/prism/net/connect/dial/racer.cpp"
#undef private

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
    TEST(RacerPure, RaceContextInitialPending)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(3, ioc.get_executor());

        EXPECT_TRUE(ctx.pending.load() == 3) << "race_context: 初始 pending=3";
        EXPECT_TRUE(!ctx.winner.load(std::memory_order_acquire)) << "race_context: 初始 winner=false";
    }

    /**
     * @brief 测试 race_context 初始 pending=1
     */
    TEST(RacerPure, RaceContextSinglePending)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(1, ioc.get_executor());

        EXPECT_TRUE(ctx.pending.load() == 1) << "race_context: 初始 pending=1";
    }

    /**
     * @brief 测试 race_context 初始 pending=0（边界情况）
     */
    TEST(RacerPure, RaceContextZeroPending)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(0, ioc.get_executor());

        EXPECT_TRUE(ctx.pending.load() == 0) << "race_context: 初始 pending=0";
    }

    // ═══════════════════════════════════════════════════════════
    //  race_context::complete() 原子递减测试
    // ═══════════════════════════════════════════════════════════

    /**
     * @brief 测试 complete() 递减 pending，最后一个触发 signal 取消
     */
    TEST(RacerPure, CompleteDecrementsPending)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(3, ioc.get_executor());

        ctx.complete();
        EXPECT_TRUE(ctx.pending.load() == 2) << "complete: 3->2";

        ctx.complete();
        EXPECT_TRUE(ctx.pending.load() == 1) << "complete: 2->1";

        // 先注册 async_wait，再让 complete() 触发 cancel
        boost::system::error_code wait_ec;
        ctx.signal.async_wait([&](const boost::system::error_code &ec)
                              { wait_ec = ec; });

        ctx.complete();
        EXPECT_TRUE(ctx.pending.load() == 0) << "complete: 1->0";

        // 驱动 io_context 使 cancel 回调执行
        ioc.poll();
        EXPECT_TRUE(wait_ec == net::error::operation_aborted)
            << "signal: async_wait 收到 operation_aborted after cancel";
    }

    /**
     * @brief 测试单端点 complete() 立即触发 signal 取消
     */
    TEST(RacerPure, CompleteSingleTriggersSignal)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(1, ioc.get_executor());

        // 先注册 async_wait，再让 complete() 触发 cancel
        boost::system::error_code wait_ec;
        ctx.signal.async_wait([&](const boost::system::error_code &ec)
                              { wait_ec = ec; });

        ctx.complete();
        EXPECT_TRUE(ctx.pending.load() == 0) << "complete single: pending->0";

        // 驱动 io_context 使 cancel 回调执行
        ioc.poll();
        EXPECT_TRUE(wait_ec == net::error::operation_aborted)
            << "complete single: async_wait 收到 operation_aborted";
    }

    /**
     * @brief 测试 complete() 在 pending=0 时不会下溢（fetch_sub 是无符号的环绕）
     */
    TEST(RacerPure, CompleteUnderflowProtection)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(1, ioc.get_executor());

        ctx.complete(); // pending: 1->0
        ctx.complete(); // pending: 0->SIZE_MAX（环绕）

        // 虽然环绕了，但不应该崩溃
        // 环绕后 pending 值应为一个非常大的数
        EXPECT_TRUE(ctx.pending.load() > 1000u) << "complete underflow: wrapped around";
    }

    // ═══════════════════════════════════════════════════════════
    //  winner 标志原子操作测试
    // ═══════════════════════════════════════════════════════════

    /**
     * @brief 测试 winner exchange 原子操作：第一个获胜者得到 false
     */
    TEST(RacerPure, WinnerExchangeFirstWins)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(2, ioc.get_executor());

        // exchange 返回旧值 false，表示当前是第一个获胜者
        auto was_winner = ctx.winner.exchange(true, std::memory_order_acq_rel);
        EXPECT_TRUE(!was_winner) << "winner exchange: 第一个获胜者得到 false";
        EXPECT_TRUE(ctx.winner.load(std::memory_order_acquire)) << "winner: 已设为 true";
    }

    /**
     * @brief 测试 winner exchange：后续获胜者得到 true
     */
    TEST(RacerPure, WinnerExchangeSecondLoses)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(2, ioc.get_executor());

        // 第一个获胜
        ctx.winner.exchange(true, std::memory_order_acq_rel);
        // 第二个尝试
        auto was_winner = ctx.winner.exchange(true, std::memory_order_acq_rel);
        EXPECT_TRUE(was_winner) << "winner exchange: 后续获胜者得到 true（已有人赢）";
    }

    // ═══════════════════════════════════════════════════════════
    //  signal 定时器初始状态测试
    // ═══════════════════════════════════════════════════════════

    /**
     * @brief 测试 signal 定时器初始过期时间为 max（永久等待）
     */
    TEST(RacerPure, SignalInitialExpiry)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(2, ioc.get_executor());

        auto expiry = ctx.signal.expiry();
        EXPECT_TRUE(expiry == net::steady_timer::time_point::max())
            << "signal: 初始过期时间为 time_point::max";
    }

    /**
     * @brief 测试 signal 取消后可以正确检测
     */
    TEST(RacerPure, SignalCancel)
    {
        net::io_context ioc;
        psm::connect::address_racer::race_context ctx(2, ioc.get_executor());

        ctx.signal.cancel();
        // cancel() 后 expiry 不再是 max（Boost.Asio 行为：cancel 不改变 expiry）
        // 但再次 async_wait + cancel 会返回 operation_aborted
        // 验证：先注册 async_wait，再 cancel，poll 后收到 aborted
        auto ec_result = boost::system::error_code{};
        ctx.signal.async_wait([&](const boost::system::error_code &ec)
                              { ec_result = ec; });
        ctx.signal.cancel();
        ioc.poll();
        EXPECT_TRUE(ec_result == net::error::operation_aborted)
            << "signal cancel: operation_aborted";
    }

    // ═══════════════════════════════════════════════════════════
    //  address_racer 构造与配置测试
    // ═══════════════════════════════════════════════════════════

    /**
     * @brief 测试 address_racer 构造不崩溃
     */
    TEST(RacerPure, RacerConstruction)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        psm::connect::address_racer racer(pool);

        EXPECT_TRUE(&racer.pool_ != nullptr)
            << "racer: 构造成功，pool_ 引用有效";
    }

    /**
     * @brief 测试 secondary_delay 常量符合 RFC 8305 建议
     */
    TEST(RacerPure, SecondaryDelayConstant)
    {
        // secondary_delay 是 address_racer 的 private static constexpr，
        // 通过 #include hack 已可访问
        constexpr auto delay = psm::connect::address_racer::secondary_delay;
        EXPECT_TRUE(delay.count() == 250)
            << "secondary_delay: 250ms (RFC 8305)";
    }

    /**
     * @brief 测试连接池引用正确存储
     */
    TEST(RacerPure, RacerPoolReference)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        psm::connect::address_racer racer(pool);

        EXPECT_TRUE(&racer.pool_ == &pool)
            << "racer: pool_ 引用指向传入的连接池";
    }

} // namespace

/**
 * @brief 测试入口
 */
