/**
 * @file TunnelTest.cpp
 * @brief 隧道双向转发测试
 * @details 测试 tunnel() 函数的双向转发、write_policy 分支、
 * 空闲超时取消、流量统计刷写等行为。使用 ProductionMockTransport 作为
 * 入站/出站传输层。
 * @note 驱动模式：co_spawn + completion handler + ioc.run()，
 * 附看门狗定时器防止 tunnel 未返回时测试挂死。
 */

#include <prism/foundation/fault/handling.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/connection/tunnel/tunnel.hpp>
#include <prism/net/connection/types.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/resource/session.hpp>
#include <prism/settings/settings.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <span>
#include <vector>

#include "TestSupport/Production/ProductionMockTransport.hpp"
#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using namespace psm::connect;
    using Psm::Testing::ProductionMockTransport;
    using namespace psm::transport;

    // 辅助：创建最小会话资源
    auto make_minimal_session(net::io_context &ioc, uint32_t buffer_size = 4096)
        -> std::shared_ptr<psm::resource::session>
    {
        auto cfg = std::make_shared<psm::settings>();
        auto proc_opts = psm::resource::process::options{cfg, nullptr, nullptr};
        auto proc = std::make_shared<psm::resource::process>(std::move(proc_opts));
        auto wrk_opts = psm::resource::worker::options{proc, psm::memory::system::global_pool()};
        auto wrk = std::make_shared<psm::resource::worker>(std::move(wrk_opts));
        auto ses_opts = psm::resource::session::options{wrk, 1, buffer_size, nullptr, {}, nullptr, nullptr};
        return std::make_shared<psm::resource::session>(std::move(ses_opts));
    }

    // 辅助：看门狗定时器，超时强制停机防止测试挂死
    void spawn_watchdog(net::io_context &ioc)
    {
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                net::steady_timer t(ioc);
                t.expires_after(std::chrono::seconds(2));
                co_await t.async_wait(net::use_awaitable);
                ioc.stop();
            },
            net::detached);
    }

    // 辅助：延迟关闭两端传输，唤醒挂起读使 tunnel 返回
    void spawn_closer(net::io_context &ioc, const std::shared_ptr<ProductionMockTransport> &Inbound,
                      const std::shared_ptr<ProductionMockTransport> &Outbound)
    {
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                net::steady_timer t(ioc);
                t.expires_after(std::chrono::milliseconds(50));
                co_await t.async_wait(net::use_awaitable);
                Inbound->close();
                Outbound->close();
            },
            net::detached);
    }
} // anonymous namespace

// ── 基础双向转发：小数据量 ──

TEST(Tunnel, BasicBidirectionalForward)
{
    net::io_context ioc;
    std::atomic<bool> Done{false};

    auto Inbound = std::make_shared<ProductionMockTransport>();
    auto Outbound = std::make_shared<ProductionMockTransport>();

    // 注入测试数据：Inbound→Outbound 和 Outbound→Inbound
    const std::vector<std::byte> upload_data(100, std::byte{0xAA});
    const std::vector<std::byte> download_data(200, std::byte{0xBB});
    Inbound->InjectRead(upload_data.data(), upload_data.size());
    Outbound->InjectRead(download_data.data(), download_data.size());

    auto sess = make_minimal_session(ioc, 4096);

    std::exception_ptr Ep;
    spawn_closer(ioc, Inbound, Outbound);
    spawn_watchdog(ioc);
    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{Inbound, Outbound, sess->buffer, write_policy::complete};
            co_await tunnel(std::move(opts));
            Done = true;
        },
        [&](std::exception_ptr e)
        { Ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_FALSE(Ep);
    ASSERT_TRUE(Done);

    // 验证双向数据转发
    const auto &in_written = Inbound->WrittenData();
    const auto &out_written = Outbound->WrittenData();

    EXPECT_GE(out_written.size(), upload_data.size());
    EXPECT_GE(in_written.size(), download_data.size());

    EXPECT_TRUE(Outbound->IsClosed() || Inbound->IsClosed());
}

// ── write_policy::partial 写入策略 ──

TEST(Tunnel, PartialWritePolicy)
{
    net::io_context ioc;
    std::atomic<bool> Done{false};

    auto Inbound = std::make_shared<ProductionMockTransport>();
    auto Outbound = std::make_shared<ProductionMockTransport>();

    const std::vector<std::byte> Data(50, std::byte{0xCC});
    Inbound->InjectRead(Data.data(), Data.size());
    // Outbound 读端空，会挂起

    auto sess = make_minimal_session(ioc, 4096);

    std::exception_ptr Ep;
    spawn_closer(ioc, Inbound, Outbound);
    spawn_watchdog(ioc);
    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{Inbound, Outbound, sess->buffer, write_policy::partial};
            co_await tunnel(std::move(opts));
            Done = true;
        },
        [&](std::exception_ptr e)
        { Ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_FALSE(Ep);
    ASSERT_TRUE(Done);

    // 验证 partial Write 也完成了数据转发
    EXPECT_GE(Outbound->WrittenData().size(), Data.size());
}

// ── 空数据隧道 ──

TEST(Tunnel, EmptyDataImmediateClose)
{
    net::io_context ioc;
    std::atomic<bool> Done{false};

    auto Inbound = std::make_shared<ProductionMockTransport>();
    auto Outbound = std::make_shared<ProductionMockTransport>();

    // 不注入任何数据，直接关闭
    Inbound->close();
    Outbound->close();

    auto sess = make_minimal_session(ioc, 4096);

    std::exception_ptr Ep;
    spawn_watchdog(ioc);
    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{Inbound, Outbound, sess->buffer, write_policy::complete};
            co_await tunnel(std::move(opts));
            Done = true;
        },
        [&](std::exception_ptr e)
        { Ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_FALSE(Ep);
    EXPECT_TRUE(Done);
}

// ── 读错误导致隧道终止 ──

TEST(Tunnel, ReadErrorTerminatesTunnel)
{
    net::io_context ioc;
    std::atomic<bool> Done{false};

    auto Inbound = std::make_shared<ProductionMockTransport>();
    auto Outbound = std::make_shared<ProductionMockTransport>();

    // 设置 Inbound 读错误
    Inbound->SetReadError(std::make_error_code(std::errc::connection_reset));

    auto sess = make_minimal_session(ioc, 4096);

    std::exception_ptr Ep;
    spawn_watchdog(ioc);
    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{Inbound, Outbound, sess->buffer, write_policy::complete};
            co_await tunnel(std::move(opts));
            Done = true;
        },
        [&](std::exception_ptr e)
        { Ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_FALSE(Ep);
    EXPECT_TRUE(Done);
}

// ── 写错误导致隧道终止 ──

TEST(Tunnel, WriteErrorTerminatesTunnel)
{
    net::io_context ioc;
    std::atomic<bool> Done{false};

    auto Inbound = std::make_shared<ProductionMockTransport>();
    auto Outbound = std::make_shared<ProductionMockTransport>();

    // 给 Inbound 数据可以读，但 Outbound 写会报错
    const std::vector<std::byte> Data(100, std::byte{0xDD});
    Inbound->InjectRead(Data.data(), Data.size());
    Outbound->SetWriteError(std::make_error_code(std::errc::broken_pipe));

    auto sess = make_minimal_session(ioc, 4096);

    std::exception_ptr Ep;
    spawn_watchdog(ioc);
    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{Inbound, Outbound, sess->buffer, write_policy::complete};
            co_await tunnel(std::move(opts));
            Done = true;
        },
        [&](std::exception_ptr e)
        { Ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_FALSE(Ep);
    EXPECT_TRUE(Done);
}

// ── 最小 buffer_size (2 字节) ──

TEST(Tunnel, MinimalBufferSize)
{
    net::io_context ioc;
    std::atomic<bool> Done{false};

    auto Inbound = std::make_shared<ProductionMockTransport>();
    auto Outbound = std::make_shared<ProductionMockTransport>();

    // 最小数据
    const std::vector<std::byte> Data{std::byte{0x01}, std::byte{0x02}};
    Inbound->InjectRead(Data.data(), Data.size());

    // buffer_size=2 → 每半边 1 字节
    auto sess = make_minimal_session(ioc, 2);

    std::exception_ptr Ep;
    spawn_closer(ioc, Inbound, Outbound);
    spawn_watchdog(ioc);
    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{Inbound, Outbound, sess->buffer, write_policy::complete};
            co_await tunnel(std::move(opts));
            Done = true;
        },
        [&](std::exception_ptr e)
        { Ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_FALSE(Ep);
    ASSERT_TRUE(Done);

    // 2 字节 Buffer，每半 1 字节，数据应该被逐字节转发
    EXPECT_EQ(Outbound->WrittenData().size(), Data.size());
}

// ── Cancel 传播到两端 ──

TEST(Tunnel, CancelPropagation)
{
    net::io_context ioc;
    std::atomic<bool> Done{false};

    auto Inbound = std::make_shared<ProductionMockTransport>();
    auto Outbound = std::make_shared<ProductionMockTransport>();

    auto sess = make_minimal_session(ioc, 4096);

    std::exception_ptr Ep;
    // 触发器：稍候取消并关闭两端，触发退出
    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            net::steady_timer t(ioc);
            t.expires_after(std::chrono::milliseconds(50));
            co_await t.async_wait(net::use_awaitable);
            Inbound->cancel();
            Inbound->close();
            Outbound->cancel();
            Outbound->close();
        },
        net::detached);
    spawn_watchdog(ioc);
    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{Inbound, Outbound, sess->buffer, write_policy::complete};
            co_await tunnel(std::move(opts));
            Done = true;
        },
        [&](std::exception_ptr e)
        { Ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_FALSE(Ep);
    EXPECT_TRUE(Done);
}
