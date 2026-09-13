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

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Net/Dialer/Dialer.hpp>
#include <preview/Runtime/Listener.hpp>
#include <preview/Runtime/Session.hpp>
#include <preview/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Preview::Fault;
    namespace Middleware = Preview::Middleware;
    namespace Network = Preview::Network;
    namespace Runtime = Preview::Runtime;
    using Tcp = Net::ip::tcp;
    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::SharedTransmission;

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Preview::Testing::AcceptEchoLoop;
    using Preview::Testing::RunCoro;
    using Preview::Testing::TcpEchoServer;

    TEST(PadMiddleware, UsesContextSizeBounds)
    {
        Net::io_context Ioc;
        RunCoro(Ioc,
                [&]() -> Net::awaitable<void>
                {
                    auto [InboundValue, PeerValue] = MakeMemoryPair(Ioc.get_executor());
                    SharedTransmission Inbound = std::make_shared<MemoryStream>(std::move(InboundValue));
                    auto Peer = std::make_shared<MemoryStream>(std::move(PeerValue));
                    Middleware::Context::PadConfig Pad;
                    Pad.Enabled = true;
                    Pad.MinSize = 8;
                    Pad.MaxSize = 8;
                    Middleware::Context Context;
                    Context.pad = &Pad;
                    Middleware::Builtin::PadMiddleware Middleware;

                    EXPECT_EQ(co_await Middleware.Handle(Inbound, Context), Fault::Code::Success);
                    std::error_code WriteError;
                    const std::string_view Payload{"abc"};
                    EXPECT_EQ(co_await Inbound->AsyncWrite(
                                  AsBytes(AsU8Span(Payload.data(), Payload.size())), WriteError),
                              3U);
                    EXPECT_FALSE(WriteError);
                    std::array<std::byte, 16> Wire{};
                    std::error_code ReadError;
                    const auto Count = co_await Peer->async_read_some(Wire, ReadError);
                    EXPECT_FALSE(ReadError);
                    EXPECT_EQ(Count, 8U);
                });
    }

    /// 拨号上游（SessionOptions::Dial 回调实现；直连目标，不经 Preview::Testing::ChainState）
    auto DialDirect(Net::any_io_executor Executor, const Network::Target &Target)
        -> Net::awaitable<std::pair<Fault::Code, SharedTransmission>>
    {
        std::error_code ErrorCode;
        Network::Dialer::Dialer Dialer(Executor);
        auto Upstream = co_await Dialer.Connect(
            std::string(Target.Host), static_cast<unsigned short>(std::stoi(std::string(Target.Port))), ErrorCode);
        if (ErrorCode || !Upstream)
        {
            co_return std::pair{Fault::Code::Unreachable, SharedTransmission{}};
        }
        co_return std::pair{Fault::Code::Success, std::move(Upstream)};
    }

    /**
     * @brief 管线用例公共流程：echo 上游 + 单会话 listener + 客户端一次往返
     * @param pad pad 配置（nullptr = 不启用填充）
     * @return {是否拨号, 是否回环成功}
     */
    auto RunPipelineCase(Net::io_context &IoContext, const Middleware::Context::PadConfig *Pad)
        -> Net::awaitable<std::pair<bool, bool>>
    {
        Tcp::acceptor EchoAcceptor(IoContext, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto EchoPort = EchoAcceptor.local_endpoint().port();
        Net::co_spawn(IoContext.get_executor(), Preview::Testing::AcceptEchoLoop(EchoAcceptor), Net::detached);

        auto Dialed = std::make_shared<bool>(false);
        auto MakeAcceptSetTarget =
            [EchoPort](SharedTransmission &, Middleware::Context &Context) -> Net::awaitable<Fault::Code>
        {
            Context.Target.Host = "127.0.0.1";
            Context.Target.Port = std::to_string(EchoPort);
            co_return Fault::Code::Success;
        };

        Runtime::TcpListener Listener(IoContext.get_executor(),
            [&](SharedTransmission, std::size_t) -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions Options;
                Options.AcceptProtocol = MakeAcceptSetTarget;
                Options.pad = Pad;
                Options.Dial = [Executor = IoContext.get_executor(), Dialed]
                    (const Network::Target &t) -> Net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    *Dialed = true;
                    co_return co_await DialDirect(Executor, t);
                };
                return std::make_shared<Runtime::Session>(std::move(Options));
            });

        bool Ok = false;
        const auto ResultCode = co_await Listener.Start(Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(ResultCode, Fault::Code::Success);
        const auto ListenPort = Listener.LocalEndpoint().port();
        std::error_code ErrorCode;
        Network::Dialer::Dialer Dialer(IoContext.get_executor());
        auto Raw = co_await Dialer.Connect("127.0.0.1", ListenPort, ErrorCode);
        if (!ErrorCode && Raw)
        {
            const std::string Payload = "pad Pipeline case";
            co_await Raw->AsyncWrite(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()),
                ErrorCode);
            std::array<std::byte, 64> Buffer{};
            std::size_t Received = 0;
            while (!ErrorCode && Received < Payload.size())
            {
                const auto BytesRead = co_await Raw->async_read_some(
                    std::span<std::byte>(Buffer).subspan(Received), ErrorCode);
                if (BytesRead == 0)
                {
                    break;
                }
                Received += BytesRead;
            }
            // pad 开启时下行回环含补齐填充（≥ 载荷），前缀必为原文；
            // pad 关闭时回环恰为载荷长度
            Ok = (Received >= Payload.size()) &&
                 std::equal(Buffer.begin(), Buffer.begin() + static_cast<std::ptrdiff_t>(Payload.size()),
                            reinterpret_cast<const std::byte *>(Payload.data()));
            if (!Ok)
            {
                ADD_FAILURE() << "DIAG received=" << Received << " first16="
                              << std::string(reinterpret_cast<const char *>(Buffer.data()),
                                             (std::min)(Received, std::size_t{24}));
            }
            Raw->Close();
        }
        Listener.Stop();
        boost::system::error_code ce;
        EchoAcceptor.close(ce);
        co_return std::pair{*Dialed, Ok};
    }

    TEST(PadMiddleware, SessionWithoutPad)
    {
        Net::io_context IoContext;
        std::pair<bool, bool> Result;
        RunCoro(IoContext, [&]() -> Net::awaitable<void>
        {
            Result = co_await RunPipelineCase(IoContext, nullptr);
        });
        EXPECT_TRUE(Result.first);
        EXPECT_TRUE(Result.second);
    }

    TEST(PadMiddleware, SessionWithPadWrapsAndRelays)
    {
        Net::io_context IoContext;
        Middleware::Context::PadConfig PadConfig;
        PadConfig.Enabled = true;
        PadConfig.MinSize = 64;
        PadConfig.MaxSize = 128;

        std::pair<bool, bool> Result;
        RunCoro(IoContext, [&]() -> Net::awaitable<void>
        {
            Result = co_await RunPipelineCase(IoContext, &PadConfig);
        });
        EXPECT_TRUE(Result.first);
        // 下行写入经 PadTransport 追加填充，但前缀字节仍是原文，回环必须成立
        EXPECT_TRUE(Result.second);
    }

} // namespace
