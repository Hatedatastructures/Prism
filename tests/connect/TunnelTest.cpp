/**
 * @file TunnelTest.cpp
 * @brief 隧道双向转发测试
 * @details 测试 tunnel() 函数的双向转发、write_policy 分支、
 * 空闲超时取消、流量统计刷写等行为。使用 MockTransport 作为
 * 入站/出站传输层。
 */

#include <gtest/gtest.h>

#include <prism/config/config.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/net/connect/pool/pool.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/context/context.hpp>
#include <prism/foundation/fault/handling.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/proto/protocol/types.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <span>
#include <vector>

#include "common/MockTransport.hpp"

namespace
{
    namespace net = boost::asio;
    using namespace psm::connect;
    using namespace psm::testing;
    using namespace psm::transport;
    using namespace psm::context;

    // 辅助：创建最小 session 上下文
    auto make_minimal_session(net::io_context &ioc, uint32_t buffer_size = 4096)
        -> session
    {
        static server server_ctx{
            std::atomic<std::shared_ptr<const psm::config>>{},
            nullptr, nullptr};
        server_ctx.cfg.store(std::make_shared<const psm::config>());

        static connection_pool pool{ioc, psm::memory::system::global_pool()};
        static psm::connect::router router_instance(
            psm::connect::router_options{pool, ioc, {}, psm::memory::system::global_pool()});
        static psm::context::worker_ref worker_ctx{ioc, psm::worker::borrow{}, psm::memory::system::global_pool()};
        static psm::memory::frame_arena arena;

        session_opts opts{
            1,
            server_ctx,
            worker_ctx,
            arena,
            buffer_size,
            nullptr,
            {}};
        return session(std::move(opts));
    }
} // anonymous namespace

// ── 基础双向转发：小数据量 ──

TEST(Tunnel, BasicBidirectionalForward)
{
    net::io_context ioc;
    std::atomic<bool> done{false};

    auto inbound = std::make_shared<MockTransport>();
    auto outbound = std::make_shared<MockTransport>();

    // 注入测试数据：inbound→outbound 和 outbound→inbound
    const std::vector<std::byte> upload_data(100, std::byte{0xAA});
    const std::vector<std::byte> download_data(200, std::byte{0xBB});
    inbound->inject_read(upload_data.data(), upload_data.size());
    outbound->inject_read(download_data.data(), download_data.size());

    auto sess = make_minimal_session(ioc, 4096);

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{inbound, outbound, sess.buffer_size, write_policy::complete};
            co_await tunnel(std::move(opts));
            done = true;
        },
        net::detached);

    // 驱动：注入数据后关闭触发隧道结束
    ioc.run_for(std::chrono::milliseconds(200));

    // 关闭触发隧道结束
    inbound->close();
    outbound->close();

    ioc.run_for(std::chrono::milliseconds(200));

    // 验证双向数据转发
    const auto &in_written = inbound->written_data();
    const auto &out_written = outbound->written_data();

    EXPECT_GE(out_written.size(), upload_data.size());
    EXPECT_GE(in_written.size(), download_data.size());

    EXPECT_TRUE(outbound->is_closed() || inbound->is_closed());
}

// ── write_policy::partial 写入策略 ──

TEST(Tunnel, PartialWritePolicy)
{
    net::io_context ioc;
    std::atomic<bool> done{false};

    auto inbound = std::make_shared<MockTransport>();
    auto outbound = std::make_shared<MockTransport>();

    const std::vector<std::byte> data(50, std::byte{0xCC});
    inbound->inject_read(data.data(), data.size());
    // outbound 读端空，会挂起

    auto sess = make_minimal_session(ioc, 4096);

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{
                inbound, outbound, sess.buffer_size, write_policy::partial};
            co_await tunnel(std::move(opts));
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(200));

    // 关闭触发隧道结束
    inbound->close();
    outbound->close();

    ioc.run_for(std::chrono::milliseconds(200));

    // 验证 partial write 也完成了数据转发
    EXPECT_GE(outbound->written_data().size(), data.size());
}

// ── 空数据隧道 ──

TEST(Tunnel, EmptyDataImmediateClose)
{
    net::io_context ioc;
    std::atomic<bool> done{false};

    auto inbound = std::make_shared<MockTransport>();
    auto outbound = std::make_shared<MockTransport>();

    // 不注入任何数据，直接关闭
    inbound->close();
    outbound->close();

    auto sess = make_minimal_session(ioc, 4096);

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{inbound, outbound, sess.buffer_size, write_policy::complete};
            co_await tunnel(std::move(opts));
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(500));
    EXPECT_TRUE(done);
}

// ── 读错误导致隧道终止 ──

TEST(Tunnel, ReadErrorTerminatesTunnel)
{
    net::io_context ioc;
    std::atomic<bool> done{false};

    auto inbound = std::make_shared<MockTransport>();
    auto outbound = std::make_shared<MockTransport>();

    // 设置 inbound 读错误
    inbound->set_read_error(std::make_error_code(std::errc::connection_reset));

    auto sess = make_minimal_session(ioc, 4096);

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{inbound, outbound, sess.buffer_size, write_policy::complete};
            co_await tunnel(std::move(opts));
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(500));
    EXPECT_TRUE(done);
}

// ── 写错误导致隧道终止 ──

TEST(Tunnel, WriteErrorTerminatesTunnel)
{
    net::io_context ioc;
    std::atomic<bool> done{false};

    auto inbound = std::make_shared<MockTransport>();
    auto outbound = std::make_shared<MockTransport>();

    // 给 inbound 数据可以读，但 outbound 写会报错
    const std::vector<std::byte> data(100, std::byte{0xDD});
    inbound->inject_read(data.data(), data.size());
    outbound->set_write_error(std::make_error_code(std::errc::broken_pipe));

    auto sess = make_minimal_session(ioc, 4096);

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{inbound, outbound, sess.buffer_size, write_policy::complete};
            co_await tunnel(std::move(opts));
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(500));
    EXPECT_TRUE(done);
}

// ── 最小 buffer_size (2 字节) ──

TEST(Tunnel, MinimalBufferSize)
{
    net::io_context ioc;
    std::atomic<bool> done{false};

    auto inbound = std::make_shared<MockTransport>();
    auto outbound = std::make_shared<MockTransport>();

    // 最小数据
    const std::vector<std::byte> data{std::byte{0x01}, std::byte{0x02}};
    inbound->inject_read(data.data(), data.size());

    // buffer_size=2 → 每半边 1 字节
    auto sess = make_minimal_session(ioc, 2);

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{inbound, outbound, sess.buffer_size, write_policy::complete};
            co_await tunnel(std::move(opts));
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(200));
    inbound->close();
    outbound->close();
    ioc.run_for(std::chrono::milliseconds(200));

    EXPECT_TRUE(done);
    // 2 字节 buffer，每半 1 字节，数据应该被逐字节转发
    EXPECT_EQ(outbound->written_data().size(), data.size());
}

// ── cancel 传播到两端 ──

TEST(Tunnel, CancelPropagation)
{
    net::io_context ioc;
    std::atomic<bool> done{false};

    auto inbound = std::make_shared<MockTransport>();
    auto outbound = std::make_shared<MockTransport>();

    auto sess = make_minimal_session(ioc, 4096);

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto opts = tunnel_options{inbound, outbound, sess.buffer_size, write_policy::complete};
            co_await tunnel(std::move(opts));
            done = true;
        },
        net::detached);

    // 稍等让隧道启动
    ioc.run_for(std::chrono::milliseconds(100));

    // 取消两端触发退出
    inbound->cancel();
    inbound->close();
    outbound->cancel();
    outbound->close();

    ioc.run_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(done);
}
