/**
 * @file SessionOrchestrationTest.cpp
 * @brief 会话编排测试（T4-2）
 * @details 覆盖：
 *          - 识别成功 → 装配 → 管线 → 数据转发（echo 往返）
 *          - 未知协议 / 识别失败 → protocol_error
 *          - 认证中途拒绝 → auth_failed 管线终止
 *          - relay 结束 → traffic sink 收到按 identity 聚合的流量
 *          - Prepare 回调装配 Target → Dial 拿到正确目标
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

#include <common/Core/Authenticator.hpp>
#include <common/Core/Fault/Code.hpp>
#include <common/Core/Fault/Handling.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Runtime/Session.hpp>
#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Core/Transmission.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using namespace Preview;

    using Preview::Testing::RunCoro; // 公共样板（见 <common/RuntimeTestHelpers.hpp>）

    /// 测试流量统计 sink
    class test_traffic_sink final : public Preview::Middleware::Context::TrafficSink
    {
    public:
        void Report(std::string_view identity, std::size_t up, std::size_t down) override
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
    auto echo_upstream(SharedTransmission client_side) -> net::awaitable<void>
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
        client_side->Close();
    }

    /// 构造可识别的首包（socks5 Greeting：0x05 0x01 0x00）
    auto socks5_greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    /// 内存流对 → shared 包装
    auto make_pair_shared(net::io_context &ioc)
        -> std::pair<std::shared_ptr<MemoryStream>, std::shared_ptr<MemoryStream>>
    {
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        return {std::make_shared<MemoryStream>(std::move(a)),
                std::make_shared<MemoryStream>(std::move(b))};
    }

    /// 基础会话选项：识别 socks5 + Prepare 装配 + Dial 注入出站
    auto base_options(std::shared_ptr<MemoryStream> outbound_s,
                      std::chrono::milliseconds idle = std::chrono::seconds(60))
        -> Preview::Runtime::SessionOptions
    {
        Preview::Runtime::SessionOptions opts;
        opts.RelayIdleTimeout = idle;
        opts.Prepare = [](const Preview::Recognition::RecognizeResult &,
                          Preview::Middleware::Context &ctx) -> net::awaitable<Preview::Fault::Code>
        {
            ctx.Target.positive = true;
            ctx.Target.Host = "upstream.test";
            ctx.Target.Port = "8080";
            co_return Preview::Fault::Code::Success;
        };
        opts.Dial = [outbound_s](const Preview::Network::Target &) -> net::awaitable<
            std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            co_return std::pair{Preview::Fault::Code::Success, outbound_s};
        };
        return opts;
    }

    TEST(SessionOrchestration, RecognizeAndRelay)
    {
        net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);
        auto [outbound_s, upstream_s] = make_pair_shared(ioc);

        Preview::Runtime::Session Session(base_options(outbound_s));

        RunCoro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void> { co_await Session.Run(inbound_s); },
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

                     client_s->Close();
                 });
    }

    TEST(SessionOrchestration, UnknownProtocolRejected)
    {
        net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);

        Preview::Runtime::SessionOptions opts;
        Preview::Runtime::Session Session(opts);

        Preview::Fault::Code rc = Preview::Fault::Code::Success;
        RunCoro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 垃圾首包（不可识别）
                     const std::string garbage = "\xff\xfe\xfd\xfc\xfb";
                     std::error_code wec;
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(garbage.data()),
                                                    garbage.size()),
                         wec);
                     rc = co_await Session.Run(inbound_s);
                 });
        EXPECT_EQ(rc, Preview::Fault::Code::ProtocolError);
    }

    TEST(SessionOrchestration, AuthRejectedMidway)
    {
        net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);

        Preview::Runtime::SessionOptions opts;
        opts.Auth = std::make_shared<Preview::RejectAuthenticator>();
        opts.Prepare = [](const Preview::Recognition::RecognizeResult &,
                          Preview::Middleware::Context &ctx) -> net::awaitable<Preview::Fault::Code>
        {
            ctx.RawIdentity = "alice";
            ctx.RawSecret = "bad";
            co_return Preview::Fault::Code::Success;
        };
        Preview::Runtime::Session Session(opts);

        Preview::Fault::Code rc = Preview::Fault::Code::Success;
        RunCoro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::error_code wec;
                     const auto payload = socks5_greeting();
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         wec);
                     rc = co_await Session.Run(inbound_s);
                 });
        EXPECT_EQ(rc, Preview::Fault::Code::AuthFailed);
    }

    TEST(SessionOrchestration, TrafficReportedOnRelayEnd)
    {
        net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);
        auto [outbound_s, upstream_s] = make_pair_shared(ioc);

        test_traffic_sink sink;
        auto opts = base_options(outbound_s, std::chrono::milliseconds(50));
        opts.Auth = std::make_shared<Preview::StaticAuthenticator>("alice", "pw");
        opts.traffic = &sink;
        opts.Prepare = [](const Preview::Recognition::RecognizeResult &,
                          Preview::Middleware::Context &ctx) -> net::awaitable<Preview::Fault::Code>
        {
            ctx.Target.positive = true;
            ctx.RawIdentity = "alice";
            ctx.RawSecret = "pw";
            co_return Preview::Fault::Code::Success;
        };
        Preview::Runtime::Session Session(opts);

        RunCoro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void> { co_await Session.Run(inbound_s); },
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
                     client_s->Close();
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
        Preview::Runtime::SessionOptions opts;
        opts.Prepare = [](const Preview::Recognition::RecognizeResult &,
                          Preview::Middleware::Context &ctx) -> net::awaitable<Preview::Fault::Code>
        {
            ctx.Target.positive = true;
            ctx.Target.Host = "Target.test";
            ctx.Target.Port = "443";
            co_return Preview::Fault::Code::Success;
        };
        opts.Dial = [&](const Preview::Network::Target &t) -> net::awaitable<
            std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            dialed_host = t.Host;
            dialed_port = t.Port;
            co_return std::pair{Preview::Fault::Code::Success, outbound_s};
        };
        Preview::Runtime::Session Session(opts);

        Preview::Fault::Code rc = Preview::Fault::Code::Success;
        RunCoro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::error_code wec;
                     const auto payload = socks5_greeting();
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         wec);
                     client_s->Close(); // EOF → relay 立即结束
                     upstream_s->Close(); // 未启动上游协程，显式结束下行方向
                     rc = co_await Session.Run(inbound_s);
                 });
        EXPECT_EQ(rc, Preview::Fault::Code::Success);
        EXPECT_EQ(dialed_host, "Target.test");
        EXPECT_EQ(dialed_port, "443");
    }

} // namespace
