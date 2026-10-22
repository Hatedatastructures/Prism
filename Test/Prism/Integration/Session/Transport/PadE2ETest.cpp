/**
 * @file PadE2ETest.cpp
 * @brief Pad 中间件接入 Session 管线验证
 * @details PadTransport 读取方向为纯透传、写入方向在载荷后追加随机填充，
 *          因此客户端收到的前 payload.size() 字节必为原文——据此对
 *          开关 pad 两种管线都做完整数据面断言。
 */

#include <gtest/gtest.h>
#include <Test/Prism/Runtime/Session/SessionAdmissionSupport.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <exception>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Transport/PadPolicy.hpp>
#include <Prism/Runtime/Middleware/Builtin/Pad.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Middleware = Prism::Middleware;
    namespace Network = Prism::Network;
    namespace Runtime = Prism::Runtime;
    namespace Memory = Prism::Memory;
    namespace Transport = Prism::Transport;
    using Tcp = Net::ip::tcp;
    using Prism::AsBytes;
    using Prism::AsU8Span;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::SharedTransmission;

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Prism::Testing::AcceptEchoLoop;
    using Prism::Testing::RunCoro;
    using Prism::Testing::TcpEchoServer;

    auto RunContextSizeBoundsCase(Net::io_context &Ioc) -> Net::awaitable<void>
    {
        auto [InboundValue, PeerValue] = MakeMemoryPair(Ioc.get_executor());
        SharedTransmission Inbound = std::make_shared<MemoryStream>(std::move(InboundValue));
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerValue));
        Middleware::Context::PadConfig Pad;
        Pad.Enabled = true;
        auto Policy = std::make_shared<Transport::PadConfig>();
        Policy->Targets = {{8, 8}};
        Pad.Policy = std::move(Policy);
        Middleware::Context Context;
        Context.Pad = &Pad;
        Context.Bytes = std::make_shared<Memory::BytePool>(
            Memory::BytePoolOptions{64U * 1024U, 4U});
        Middleware::Builtin::PadMiddleware PadOwner;

        const auto Handled = co_await PadOwner.Handle(Inbound, Context);
        EXPECT_FALSE(Handled.Failed());
        const std::string_view Payload{"abc"};
        const auto Write = co_await Inbound->WriteExact(
            AsBytes(AsU8Span(Payload.data(), Payload.size())));
        EXPECT_EQ(Write.Bytes, 3U);
        EXPECT_FALSE(Write.Failure.Failed());
        std::array<std::byte, 16> Wire{};
        const auto Read = co_await Peer->ReadSome(Wire);
        EXPECT_FALSE(Read.Failure.Failed());
        EXPECT_EQ(Read.Bytes, 8U);
    }

    TEST(PadMiddleware, UsesContextSizeBounds)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunContextSizeBoundsCase(Ioc));
    }

    /// 拨号上游（SessionOptions::Dial 回调实现；直连目标，不经 Prism::Testing::ChainState）
    auto DialDirect(Net::any_io_executor Executor, const Network::Target &Target)
        -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
    {
        Network::Dialer::Dialer Dialer(Executor);
        co_return co_await Dialer.Connect(Target);
    }

    struct EchoTaskState final
    {
        using CompletionChannel =
            Net::experimental::channel<void(boost::system::error_code)>;

        std::shared_ptr<CompletionChannel> Done;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    auto StartEchoTask(Net::any_io_executor Executor, Tcp::acceptor &Acceptor)
        -> EchoTaskState
    {
        EchoTaskState State{
            std::make_shared<EchoTaskState::CompletionChannel>(Executor, 1),
            std::make_shared<std::exception_ptr>()};
        Net::co_spawn(
            Executor,
            AcceptEchoLoop(Acceptor),
            [State](std::exception_ptr ErrorValue)
            {
                if (ErrorValue && !*State.Failure)
                {
                    *State.Failure = ErrorValue;
                }
                (void)State.Done->try_send(boost::system::error_code{});
            });
        return State;
    }

    auto WaitEchoTask(EchoTaskState State) -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        (void)co_await State.Done->async_receive(
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (ErrorCode)
        {
            throw std::system_error(ErrorCode);
        }
        if (*State.Failure)
        {
            std::rethrow_exception(*State.Failure);
        }
    }

    struct PadSessionFactoryRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Prism::Testing::StreamFactory> AcceptProtocol;
        std::shared_ptr<Middleware::Context::PadConfig> Pad;
        std::shared_ptr<Memory::BytePool> Bytes;
        std::shared_ptr<bool> Dialed;
    };

    struct PadConnectionRequest final
    {
        SharedTransmission Inbound;
        Prism::WorkerId Worker;
        std::string SourceIp;
    };

    auto MakePadSession(PadSessionFactoryRequest Request,
                        PadConnectionRequest Connection)
        -> std::shared_ptr<Runtime::Session>
    {
        Runtime::SessionOptions Options;
        Options.Services->AcceptProtocol = std::move(Request.AcceptProtocol);
        Options.Services->Bytes = std::move(Request.Bytes);
        if (Request.Pad)
        {
            Options.Services->Pad = std::make_shared<Middleware::Context::PadConfig>(
                *Request.Pad);
        }
        Options.Services->Dial =
            [Executor = Request.Executor, Dialed = std::move(Request.Dialed)]
            (const Network::Target &Target) -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
            {
                *Dialed = true;
                co_return co_await DialDirect(Executor, Target);
            };
        (void)Connection.Worker;
        (void)Connection.SourceIp;
        return std::make_shared<Runtime::Session>(std::move(Options));
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
        auto EchoTask = StartEchoTask(IoContext.get_executor(), EchoAcceptor);

        auto Dialed = std::make_shared<bool>(false);
        auto Bytes = std::make_shared<Memory::BytePool>(
            Memory::BytePoolOptions{64U * 1024U, 8U});
        auto MakeAcceptSetTarget =
            [EchoPort](Prism::Contract::StreamAcceptInput Input)
                -> Net::awaitable<Prism::Contract::AcceptOutcome>
        {
            Prism::Contract::ProtocolDataPlane Plane;
            Plane.Root = Prism::Contract::StreamDataPlane{std::move(Input.Inbound)};
            Plane.Target.Host = *Prism::Network::ParseHost("127.0.0.1");
            Plane.Target.Port = EchoPort;
            co_return Prism::Contract::AcceptOutcome{std::move(Plane)};
        };

        auto AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(MakeAcceptSetTarget);
        std::shared_ptr<Middleware::Context::PadConfig> PadCopy;
        if (Pad)
        {
            PadCopy = std::make_shared<Middleware::Context::PadConfig>(*Pad);
        }
        const PadSessionFactoryRequest FactoryRequest{
            IoContext.get_executor(), std::move(AcceptProtocol), std::move(PadCopy),
            std::move(Bytes), Dialed};
        Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor=IoContext.get_executor();
        ListenerOptions.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
            Prism::GenerationId{1});
        ListenerOptions.Factory=
            [FactoryRequest](Prism::Runtime::SessionAdmission Admission)
                -> std::shared_ptr<Runtime::Session>
            {
                return MakePadSession(FactoryRequest,
                                      PadConnectionRequest{std::move(Admission.Inbound), Admission.Worker,
                                          std::move(Admission.SourceIp)});
            };
        Runtime::TcpListener Listener(std::move(ListenerOptions));

        bool Ok = false;
        const auto ResultCode = co_await Listener.Start(Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(ResultCode, Fault::Code::Success);
        const auto ListenPort = Listener.LocalEndpoint().port();
        std::error_code ErrorCode;
        Network::Dialer::Dialer Dialer(IoContext.get_executor());
        auto RawResult = co_await Dialer.Connect(
            {*Prism::Network::ParseHost("127.0.0.1"), ListenPort});
        if (RawResult && *RawResult)
        {
            auto Raw = std::move(*RawResult);
            const std::string Payload = "pad Pipeline case";
            const auto PayloadBytes = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
            const auto Write = co_await Raw->WriteExact(PayloadBytes);
            ErrorCode = Fault::ToNative(Write.Failure);
            std::array<std::byte, 64> Buffer{};
            std::size_t Received = 0;
            while (!ErrorCode && Received < Payload.size())
            {
                const auto Read = co_await Raw->ReadSome(
                    std::span<std::byte>(Buffer).subspan(Received));
                ErrorCode = Fault::ToNative(Read.Failure);
                const auto BytesRead = Read.Bytes;
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
            (void)Raw->Close();
        }
        else if (!RawResult)
        {
            ErrorCode = Fault::ToNative(RawResult.error());
        }
        Listener.Stop();
        boost::system::error_code CloseError;
        EchoAcceptor.close(CloseError);
        co_await WaitEchoTask(std::move(EchoTask));
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
        auto Policy = std::make_shared<Transport::PadConfig>();
        Policy->Targets = {{64, 128}};
        PadConfig.Policy = std::move(Policy);

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
