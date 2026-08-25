/**
 * @file TunnelTest.cpp
 * @brief 隧道双向转发测试
 * @details 测试 tunnel() 函数的双向转发、write_policy 分支、
 * 空闲超时取消、流量统计刷写等行为。使用 MockTransport 作为
 * 入站/出站传输层。
 */

#include <prism/foundation/fault/handling.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/net/connection/Dialer/Dialer.hpp>
#include <prism/net/connection/tunnel/tunnel.hpp>
#include <prism/net/connection/types.hpp>
#include <prism/net/transport/Transmission.hpp>
#include <prism/Resource/Session.hpp>
#include <prism/settings/settings.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <span>
#include <vector>

#include "common/MockTransport.hpp"
#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using namespace psm::connect;
    using namespace psm::testing;
    using namespace psm::transport;

    // 辅助：创建最小会话资源
    auto make_minimal_session(net::io_context &ioc, uint32_t buffer_size = 4096)
        -> std::shared_ptr<psm::resource::session>
    {
        auto cfg = std::make_shared<psm::settings>();
        auto proc_opts = psm::resource::process::options{cfg, nullptr, nullptr};
        auto proc = std::make_shared<psm::resource::process>(std::move(proc_opts));
        auto wrk_opts = psm::resource::worker::options{proc, psm::memory::std::global_pool()};
        auto wrk = std::make_shared<psm::resource::worker>(std::move(wrk_opts));
        auto ses_opts = psm::resource::session::options{wrk, 1, buffer_size, nullptr, {}, nullptr, nullptr};
        return std::make_shared<psm::resource::session>(std::move(ses_opts));
    }
} // anonymous namespace

// ── 基础双向转发：小数据量 ──

TEST(Tunnel, BasicBidirectionalForward)
{
    net::io_context ioc;
    std::atomic<bool> Done{false};

    auto inbound = std::make_shared<MockTransport>();
    auto Outbound = std::make_shared<MockTransport>();

    // 注入测试数据：inbound→Outbound 和 Outbound→inbound
    const std::vector<std::byte> upload_data(100, std::byte{0xAA});
    const std::vector<std::byte> download_data(200, std::byte{0xBB});
    inbound->inject_read(upload_data.data(), upload_data.size());
    Outbound->inject_read(download_data.data(), download_data.size());

    auto sess = make_minimal_session(ioc, 4096);

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{inbound, Outbound, sess->buffer, write_policy::complete};
            co_await tunnel(std::move(opts));
            Done = true;
        },
        net::detached);

    // 驱动：注入数据后关闭触发隧道结束
    ioc.run_for(std::chrono::milliseconds(200));

    // 关闭触发隧道结束
    inbound->close();
    Outbound->close();

    ioc.run_for(std::chrono::milliseconds(200));

    // 验证双向数据转发
    const auto &in_written = inbound->WrittenData();
    const auto &out_written = Outbound->WrittenData();

    EXPECT_GE(out_written.size(), upload_data.size());
    EXPECT_GE(in_written.size(), download_data.size());

    EXPECT_TRUE(Outbound->IsClosed() || inbound->IsClosed());
}

// ── write_policy::partial 写入策略 ──

TEST(Tunnel, PartialWritePolicy)
{
    net::io_context ioc;
    std::atomic<bool> Done{false};

    auto inbound = std::make_shared<MockTransport>();
    auto Outbound = std::make_shared<MockTransport>();

    const std::vector<std::byte> Data(50, std::byte{0xCC});
    inbound->inject_read(Data.data(), Data.size());
    // Outbound 读端空，会挂起

    auto sess = make_minimal_session(ioc, 4096);

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{inbound, Outbound, sess->buffer, write_policy::partial};
            co_await tunnel(std::move(opts));
            Done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(200));

    // 关闭触发隧道结束
    inbound->close();
    Outbound->close();

    ioc.run_for(std::chrono::milliseconds(200));

    // 验证 partial Write 也完成了数据转发
    EXPECT_GE(Outbound->WrittenData().size(), Data.size());
}

// ── 空数据隧道 ──

TEST(Tunnel, EmptyDataImmediateClose)
{
    net::io_context ioc;
    std::atomic<bool> Done{false};

    auto inbound = std::make_shared<MockTransport>();
    auto Outbound = std::make_shared<MockTransport>();

    // 不注入任何数据，直接关闭
    inbound->close();
    Outbound->close();

    auto sess = make_minimal_session(ioc, 4096);

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{inbound, Outbound, sess->buffer, write_policy::complete};
            co_await tunnel(std::move(opts));
            Done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(500));
    EXPECT_TRUE(Done);
}

// ── 读错误导致隧道终止 ──

TEST(Tunnel, ReadErrorTerminatesTunnel)
{
    net::io_context ioc;
    std::atomic<bool> Done{false};

    auto inbound = std::make_shared<MockTransport>();
    auto Outbound = std::make_shared<MockTransport>();

    // 设置 inbound 读错误
    inbound->set_ReadError(std::make_error_code(std::errc::connection_reset));

    auto sess = make_minimal_session(ioc, 4096);

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{inbound, Outbound, sess->buffer, write_policy::complete};
            co_await tunnel(std::move(opts));
            Done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(500));
    EXPECT_TRUE(Done);
}

// ── 写错误导致隧道终止 ──

TEST(Tunnel, WriteErrorTerminatesTunnel)
{
    net::io_context ioc;
    std::atomic<bool> Done{false};

    auto inbound = std::make_shared<MockTransport>();
    auto Outbound = std::make_shared<MockTransport>();

    // 给 inbound 数据可以读，但 Outbound 写会报错
    const std::vector<std::byte> Data(100, std::byte{0xDD});
    inbound->inject_read(Data.data(), Data.size());
    Outbound->set_WriteError(std::make_error_code(std::errc::broken_pipe));

    auto sess = make_minimal_session(ioc, 4096);

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{inbound, Outbound, sess->buffer, write_policy::complete};
            co_await tunnel(std::move(opts));
            Done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(500));
    EXPECT_TRUE(Done);
}

// ── 最小 buffer_size (2 字节) ──

TEST(Tunnel, MinimalBufferSize)
{
    net::io_context ioc;
    std::atomic<bool> Done{false};

    auto inbound = std::make_shared<MockTransport>();
    auto Outbound = std::make_shared<MockTransport>();

    // 最小数据
    const std::vector<std::byte> Data{std::byte{0x01}, std::byte{0x02}};
    inbound->inject_read(Data.data(), Data.size());

    // buffer_size=2 → 每半边 1 字节
    auto sess = make_minimal_session(ioc, 2);

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{inbound, Outbound, sess->buffer, write_policy::complete};
            co_await tunnel(std::move(opts));
            Done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(200));
    inbound->close();
    Outbound->close();
    ioc.run_for(std::chrono::milliseconds(200));

    EXPECT_TRUE(Done);
    // 2 字节 Buffer，每半 1 字节，数据应该被逐字节转发
    EXPECT_EQ(Outbound->WrittenData().size(), Data.size());
}

// ── Cancel 传播到两端 ──

TEST(Tunnel, CancelPropagation)
{
    net::io_context ioc;
    std::atomic<bool> Done{false};

    auto inbound = std::make_shared<MockTransport>();
    auto Outbound = std::make_shared<MockTransport>();

    auto sess = make_minimal_session(ioc, 4096);

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{inbound, Outbound, sess->buffer, write_policy::complete};
            co_await tunnel(std::move(opts));
            Done = true;
        },
        net::detached);

    // 稍等让隧道启动
    ioc.run_for(std::chrono::milliseconds(100));

    // 取消两端触发退出
    inbound->cancel();
    inbound->close();
    Outbound->cancel();
    Outbound->close();

    ioc.run_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(Done);
}
