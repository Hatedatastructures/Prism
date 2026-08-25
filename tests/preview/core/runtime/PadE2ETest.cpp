/**
 * @file PadE2ETest.cpp
 * @brief Pad 中间件接入 Session 管线验证
 * @details PadTransport 读取方向为纯透传、写入方向在载荷后追加随机填充，
 *          因此客户端收到的前 payload.size() 字节必为原文——据此对
 *          开关 pad 两种管线都做完整数据面断言。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Net/Dialer/Dialer.hpp>
#include <common/Core/Runtime/Listener.hpp>
#include <common/Core/Runtime/Session.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using Tcp = net::ip::tcp;
    using namespace Preview;

    // 公共样板（RunCoro/echo 上游见 <common/RuntimeTestHelpers.hpp>）
    using psm::testing::AcceptEchoLoop;
    using psm::testing::RunCoro;
    using psm::testing::tcp_echo_server;

    /// 拨号上游（SessionOptions::Dial 回调实现；直连目标，不经 psm::testing::chain_state）
    auto dial_direct(net::any_io_executor ex, const Network::Target &t)
        -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
    {
        std::error_code ec;
        Network::Dialer::Dialer d(ex);
        auto up = co_await d.Connect(
            std::string(t.Host), static_cast<unsigned short>(std::stoi(std::string(t.Port))), ec);
        if (ec || !up)
        {
            co_return std::pair{Fault::Code::unreachable, SharedTransmission{}};
        }
        co_return std::pair{Fault::Code::success, std::move(up)};
    }

    /**
     * @brief 管线用例公共流程：echo 上游 + 单会话 listener + 客户端一次往返
     * @param pad pad 配置（nullptr = 不启用填充）
     * @return {是否拨号, 是否回环成功}
     */
    auto run_pipeline_case(net::io_context &ioc, const Middleware::Context::PadConfig *pad)
        -> net::awaitable<std::pair<bool, bool>>
    {
        Tcp::acceptor echo_ac(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_ac.local_endpoint().port();
        net::co_spawn(ioc.get_executor(), psm::testing::AcceptEchoLoop(echo_ac), net::detached);

        auto dialed = std::make_shared<bool>(false);
        auto make_accept_set_target =
            [echo_port](SharedTransmission &, Middleware::Context &ctx) -> net::awaitable<Fault::Code>
        {
            ctx.Target.Host = "127.0.0.1";
            ctx.Target.Port = std::to_string(echo_port);
            co_return Fault::Code::success;
        };

        Runtime::TcpListener listener(ioc.get_executor(),
            [&](SharedTransmission, std::size_t) -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = make_accept_set_target;
                opts.pad = pad;
                opts.Dial = [this_ex = ioc.get_executor(), dialed]
                    (const Network::Target &t) -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    *dialed = true;
                    co_return co_await dial_direct(this_ex, t);
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool Ok = false;
        const auto rc = co_await listener.Start(net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        EXPECT_EQ(rc, Fault::Code::success);
        const auto lp = listener.LocalEndpoint().port();
        std::error_code ec;
        Network::Dialer::Dialer d(ioc.get_executor());
        auto raw = co_await d.Connect("127.0.0.1", lp, ec);
        if (!ec && raw)
        {
            const std::string payload = "pad Pipeline case";
            co_await raw->AsyncWrite(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                           payload.size()),
                ec);
            std::array<std::byte, 64> buf{};
            std::size_t got = 0;
            while (!ec && got < payload.size())
            {
                const auto n = co_await raw->AsyncReadSome(
                    std::span<std::byte>(buf).subspan(got), ec);
                if (n == 0) break;
                got += n;
            }
            // pad 开启时下行回环含补齐填充（≥ 载荷），前缀必为原文；
            // pad 关闭时回环恰为载荷长度
            Ok = (got >= payload.size()) &&
                 std::equal(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(payload.size()),
                            reinterpret_cast<const std::byte *>(payload.data()));
            if (!Ok)
            {
                ADD_FAILURE() << "DIAG got=" << got << " first16="
                              << std::string(reinterpret_cast<const char *>(buf.data()),
                                             (std::min)(got, std::size_t{24}));
            }
            raw->Close();
        }
        listener.Stop();
        boost::system::error_code ce;
        echo_ac.close(ce);
        co_return std::pair{*dialed, Ok};
    }

    TEST(PadMiddleware, SessionWithoutPad)
    {
        net::io_context ioc;
        std::pair<bool, bool> Result;
        RunCoro(ioc, [&]() -> net::awaitable<void>
        {
            Result = co_await run_pipeline_case(ioc, nullptr);
        });
        EXPECT_TRUE(Result.first);
        EXPECT_TRUE(Result.second);
    }

    TEST(PadMiddleware, SessionWithPadWrapsAndRelays)
    {
        net::io_context ioc;
        Middleware::Context::PadConfig pad_cfg;
        pad_cfg.Enabled = true;
        pad_cfg.MinSize = 64;
        pad_cfg.MaxSize = 128;

        std::pair<bool, bool> Result;
        RunCoro(ioc, [&]() -> net::awaitable<void>
        {
            Result = co_await run_pipeline_case(ioc, &pad_cfg);
        });
        EXPECT_TRUE(Result.first);
        // 下行写入经 PadTransport 追加填充，但前缀字节仍是原文，回环必须成立
        EXPECT_TRUE(Result.second);
    }

} // namespace
