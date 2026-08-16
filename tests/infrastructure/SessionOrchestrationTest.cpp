/**
 * @file SessionOrchestrationTest.cpp
 * @brief 会话编排测试（T4-2）
 * @details 覆盖：
 *          - 识别成功 → 装配 → 管线 → 数据转发（echo 往返）
 *          - 未知协议 / 识别失败 → protocol_error
 *          - 认证中途拒绝 → auth_failed 管线终止
 *          - relay 结束 → traffic sink 收到按 identity 聚合的流量
 *          - prepare 回调装配 target → dial 拿到正确目标
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

#include <common/core/authenticator.hpp>
#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/runtime/session.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/core/transmission.hpp>

namespace
{

    namespace net = boost::asio;
    using namespace psmtest;

    auto run_coro(net::io_context &ioc, auto coro)
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    /// 测试流量统计 sink
    class test_traffic_sink final : public psmtest::middleware::context::traffic_sink
    {
    public:
        void report(std::string_view identity, std::size_t up, std::size_t down) override
        {
            last_identity = std::string(identity);
            total_up += up;
            total_down += down;
            ++calls;
        }
        std::string last_identity;
        std::size_t total_up{0};
        std::size_t total_down{0};
        int calls{0};
    };

    /// 回显上游：读到的数据原样写回（detached 运行，直至 EOF）
    auto echo_upstream(shared_transmission client_side) -> net::awaitable<void>
    {
        std::array<std::byte, 4096> buf{};
        std::error_code ec;
        while (true)
        {
            const auto n = co_await client_side->async_read_some(std::span<std::byte>(buf), ec);
            if (ec || n == 0)
            {
                break;
            }
            co_await client_side->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
            if (ec)
            {
                break;
            }
        }
        client_side->close();
    }

    /// 构造可识别的首包（socks5 greeting：0x05 0x01 0x00）
    auto socks5_greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    /// 内存流对 → shared 包装
    auto make_pair_shared(net::io_context &ioc)
        -> std::pair<std::shared_ptr<memory_stream>, std::shared_ptr<memory_stream>>
    {
        auto [a, b] = make_memory_pair(ioc.get_executor());
        return {std::make_shared<memory_stream>(std::move(a)),
                std::make_shared<memory_stream>(std::move(b))};
    }

    /// 基础会话选项：识别 socks5 + prepare 装配 + dial 注入出站
    auto base_options(std::shared_ptr<memory_stream> outbound_s,
                      std::chrono::milliseconds idle = std::chrono::seconds(60))
        -> psmtest::runtime::session_options
    {
        psmtest::runtime::session_options opts;
        opts.relay_idle_timeout = idle;
        opts.prepare = [](const psmtest::recognition::recognize_result &,
                          psmtest::middleware::context &ctx) -> net::awaitable<psmtest::fault::code>
        {
            ctx.target.positive = true;
            ctx.target.host = "upstream.test";
            ctx.target.port = "8080";
            co_return psmtest::fault::code::success;
        };
        opts.dial = [outbound_s](const psmtest::connect::target &) -> net::awaitable<
            std::pair<psmtest::fault::code, psmtest::shared_transmission>>
        {
            co_return std::pair{psmtest::fault::code::success, outbound_s};
        };
        return opts;
    }

    TEST(SessionOrchestration, RecognizeAndRelay)
    {
        net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);
        auto [outbound_s, upstream_s] = make_pair_shared(ioc);

        psmtest::runtime::session session(base_options(outbound_s));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void> { co_await session.run(inbound_s); },
                         net::detached);
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void> { co_await echo_upstream(upstream_s); },
                         net::detached);

                     // 客户端发 socks5 首包
                     std::error_code wec;
                     const auto payload = socks5_greeting();
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         wec);

                     // 上游回显 → 客户端收到
                     std::array<std::byte, 64> rbuf{};
                     std::error_code rec;
                     const auto rn = co_await client_s->async_read_some(std::span<std::byte>(rbuf), rec);
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(rbuf.data()), rn), payload);

                     client_s->close();
                 });
    }

    TEST(SessionOrchestration, UnknownProtocolRejected)
    {
        net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);

        psmtest::runtime::session_options opts;
        psmtest::runtime::session session(opts);

        psmtest::fault::code rc = psmtest::fault::code::success;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 垃圾首包（不可识别）
                     const std::string garbage = "\xff\xfe\xfd\xfc\xfb";
                     std::error_code wec;
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(garbage.data()),
                                                    garbage.size()),
                         wec);
                     rc = co_await session.run(inbound_s);
                 });
        EXPECT_EQ(rc, psmtest::fault::code::protocol_error);
    }

    TEST(SessionOrchestration, AuthRejectedMidway)
    {
        net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);

        psmtest::runtime::session_options opts;
        opts.auth = std::make_shared<psmtest::reject_authenticator>();
        opts.prepare = [](const psmtest::recognition::recognize_result &,
                          psmtest::middleware::context &ctx) -> net::awaitable<psmtest::fault::code>
        {
            ctx.raw_identity = "alice";
            ctx.raw_secret = "bad";
            co_return psmtest::fault::code::success;
        };
        psmtest::runtime::session session(opts);

        psmtest::fault::code rc = psmtest::fault::code::success;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::error_code wec;
                     const auto payload = socks5_greeting();
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         wec);
                     rc = co_await session.run(inbound_s);
                 });
        EXPECT_EQ(rc, psmtest::fault::code::auth_failed);
    }

    TEST(SessionOrchestration, TrafficReportedOnRelayEnd)
    {
        net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);
        auto [outbound_s, upstream_s] = make_pair_shared(ioc);

        test_traffic_sink sink;
        auto opts = base_options(outbound_s, std::chrono::milliseconds(50));
        opts.auth = std::make_shared<psmtest::static_authenticator>("alice", "pw");
        opts.traffic = &sink;
        opts.prepare = [](const psmtest::recognition::recognize_result &,
                          psmtest::middleware::context &ctx) -> net::awaitable<psmtest::fault::code>
        {
            ctx.target.positive = true;
            ctx.raw_identity = "alice";
            ctx.raw_secret = "pw";
            co_return psmtest::fault::code::success;
        };
        psmtest::runtime::session session(opts);

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void> { co_await session.run(inbound_s); },
                         net::detached);
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void> { co_await echo_upstream(upstream_s); },
                         net::detached);

                     std::error_code wec;
                     const auto payload = socks5_greeting();
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         wec);
                     // 等回显（relay 转发 → echo → 回显）
                     std::array<std::byte, 64> buf{};
                     std::error_code sec;
                     const auto n = co_await client_s->async_read_some(std::span<std::byte>(buf), sec);
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n), payload);

                     // 空闲 50ms → relay 超时关闭 → 会话结束 → 上报
                     net::steady_timer t(ioc);
                     t.expires_after(std::chrono::milliseconds(300));
                     co_await t.async_wait(net::use_awaitable);
                     client_s->close();
                 });
        EXPECT_GT(sink.calls, 0);
        EXPECT_GE(sink.total_up, socks5_greeting().size());
        EXPECT_EQ(sink.last_identity, "alice");
    }

    TEST(SessionOrchestration, PrepareSetsTargetForDial)
    {
        net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);
        auto [outbound_s, upstream_s] = make_pair_shared(ioc);

        std::string dialed_host;
        std::string dialed_port;
        psmtest::runtime::session_options opts;
        opts.prepare = [](const psmtest::recognition::recognize_result &,
                          psmtest::middleware::context &ctx) -> net::awaitable<psmtest::fault::code>
        {
            ctx.target.positive = true;
            ctx.target.host = "target.test";
            ctx.target.port = "443";
            co_return psmtest::fault::code::success;
        };
        opts.dial = [&](const psmtest::connect::target &t) -> net::awaitable<
            std::pair<psmtest::fault::code, psmtest::shared_transmission>>
        {
            dialed_host = t.host;
            dialed_port = t.port;
            co_return std::pair{psmtest::fault::code::success, outbound_s};
        };
        psmtest::runtime::session session(opts);

        psmtest::fault::code rc = psmtest::fault::code::success;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::error_code wec;
                     const auto payload = socks5_greeting();
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         wec);
                     client_s->close(); // EOF → relay 立即结束
                     rc = co_await session.run(inbound_s);
                 });
        EXPECT_EQ(rc, psmtest::fault::code::success);
        EXPECT_EQ(dialed_host, "target.test");
        EXPECT_EQ(dialed_port, "443");
    }

} // namespace
