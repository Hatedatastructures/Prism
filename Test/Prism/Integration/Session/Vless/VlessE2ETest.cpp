/**
 * @file VlessE2ETest.cpp
 * @brief VLESS 第二条纵向链路测试（阶段 4：抽象复用验证）
 * @details 与 SOCKS5 共用同一套 runtime Session 编排：
 *          listener → recognition → AcceptProtocol(vless) →
 *          Dial Middleware → relay Middleware → echo 上游。
 *          验证点：runtime 零协议特判（不复制 SOCKS5 的
 *          Accept/PostDial 编排），VLESS 仅提供握手与数据面。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <string_view>

#include "VlessTestSupport.hpp"

namespace
{

    namespace Net = boost::asio;
    namespace Runtime = Prism::Runtime;
    namespace Vless = Prism::Vless;
    namespace Fault = Prism::Fault;
    namespace VlessTest = Prism::Testing::VlessE2E;
    using Prism::Error;
    using Prism::SharedTransmission;
    using VlessTest::VlessTcpEchoOwner;
    using VlessTest::VlessSessionFactory;
    using VlessTest::ConnectVlessWithTestUuid;
    using VlessTest::CloseVlessTransmission;
    using VlessTest::DialVlessListener;
    using VlessTest::FinishVlessTcpFlow;
    using VlessTest::FinishVlessListener;
    using VlessTest::StartVlessListener;
    using VlessTest::StartVlessTcpEcho;
    using VlessTest::TestUuid;
    using VlessTest::TrafficRecorder;
    using VlessTest::VlessChainState;

    using ConnectResult = Prism::Testing::ConnectResult;
    using Prism::Testing::RunCoro;

    struct VlessConnectFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VlessTcpEchoOwner &Echo;
        const Vless::Address &Target;
        const Vless::ClientConfig &ClientConfig;
        std::shared_ptr<VlessChainState> Chain;
        ConnectResult &Result;
    };

    /** @brief 驱动一次 VLESS TCP listener→admission→dial→echo 纵向链路。 */
    auto RunVlessConnectFlow(VlessConnectFlow Flow) -> Net::awaitable<void>
    {
        auto &Result = Flow.Result;
        std::exception_ptr FirstFailure;
        SharedTransmission Proxy;
        try
        {
            if (!co_await StartVlessListener(Flow.Listener))
            {
                Result.Failure = Prism::Testing::FailureFromProtocolError(
                    Prism::Error::IoError);
            }
            else
            {
                auto Raw = co_await DialVlessListener(Flow.Ioc, Flow.Listener);
                if (!Raw)
                {
                    Result.Failure = Raw.error();
                }
                else
                {
                    auto ProtocolConnect = co_await Vless::Connect(
                        Vless::ConnectParameters{
                            std::move(*Raw), Flow.ClientConfig, Flow.Target});
                    if (!ProtocolConnect)
                    {
                        Result.Failure = ProtocolConnect.error();
                    }
                    else if (!*ProtocolConnect)
                    {
                        Result.Failure = {Fault::Code::InvalidArgument, {}};
                    }
                    else
                    {
                        Proxy = std::move(*ProtocolConnect);
                    }
                    if (Proxy)
                    {
                        const std::string Payload = "chain payload";
                        const auto Write = co_await Proxy->WriteExact(
                            std::span<const std::byte>(
                                reinterpret_cast<const std::byte *>(Payload.data()),
                                Payload.size()));
                        auto IoFailure = Write.Failure;
                        if (!IoFailure.Failed() && Write.Bytes != Payload.size())
                        {
                            IoFailure = {Fault::Code::IoError};
                        }
                        std::array<std::byte, 64> Buffer{};
                        std::size_t Received = 0;
                        while (!IoFailure.Failed() && Received < Payload.size())
                        {
                            const auto Read = co_await Proxy->ReadSome(
                                std::span<std::byte>(Buffer).subspan(Received));
                            const auto Remaining = Payload.size() - Received;
                            if (Read.Bytes > Remaining)
                            {
                                IoFailure = {Fault::Code::InvalidArgument, Read.Failure.Native};
                                break;
                            }
                            Received += Read.Bytes;
                            if (Read.Failure.Failed())
                            {
                                IoFailure = Read.Failure;
                                break;
                            }
                            if (Read.Bytes == 0U)
                            {
                                IoFailure = {Fault::Code::Eof};
                                break;
                            }
                        }
                        if (IoFailure.Failed()) Result.Failure = IoFailure;
                        Result.Echo.assign(reinterpret_cast<const char *>(Buffer.data()), Received);
                        Result.Host = Flow.Chain->RequestedHost;
                        Result.Port = Flow.Chain->RequestedPort;
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        CloseVlessTransmission(Proxy, FirstFailure);
        co_await FinishVlessTcpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    /** @brief 运行通用 VLESS TCP 真实链路（自建 IO context）。 */
    auto RunVlessConnect(const Vless::Address &Target,
                         Vless::ClientConfig ClientConfiguration = {},
                         Vless::ServerConfig ServerConfiguration = {})
        -> ConnectResult
    {
        ConnectResult Result;
        Net::io_context Io;
        auto Echo = StartVlessTcpEcho(Io);
        const auto EchoPort = Echo.Acceptor->local_endpoint().port();
        auto ChainState = std::make_shared<VlessChainState>(
            VlessChainState{Io.get_executor(), EchoPort});

        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = Io.get_executor(),
            .Factory = VlessSessionFactory{ChainState, ServerConfiguration},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{1})});

        RunCoro(Io, RunVlessConnectFlow(VlessConnectFlow{
            Io, Listener, Echo, Target, ClientConfiguration, ChainState, Result}));
        EXPECT_FALSE(*Echo.Failure);
        return Result;
    }

    struct VlessFullChainFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VlessTcpEchoOwner &Echo;
        bool &HandshakeOk;
        std::string &EchoBack;
    };

    /** @brief 驱动 VLESS full-chain TCP payload 与 recognition/admission 回环。 */
    auto RunVlessFullChainFlow(VlessFullChainFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        SharedTransmission Proxy;
        try
        {
            if (co_await StartVlessListener(Flow.Listener))
            {
                auto Raw = co_await DialVlessListener(Flow.Ioc, Flow.Listener);
                if (Raw)
                {
                    auto ProtocolConnect = co_await ConnectVlessWithTestUuid(
                        std::move(*Raw),
                        Vless::Address{Vless::AddressType::Domain, "example.com", 443});
                    Flow.HandshakeOk = static_cast<bool>(ProtocolConnect) && static_cast<bool>(*ProtocolConnect);
                    if (!ProtocolConnect)
                    {
                        ADD_FAILURE() << "VLESS full-chain handshake failed: "
                            << Prism::Fault::Describe(ProtocolConnect.error().Code)
                            << " Native=" << ProtocolConnect.error().Native.category().name()
                            << ":" << ProtocolConnect.error().Native.value();
                    }
                    else if (!*ProtocolConnect)
                    {
                        ADD_FAILURE() << "Protocol Connect succeeded without a connection owner";
                    }
                    else
                    {
                        Proxy = std::move(*ProtocolConnect);
                    }
                    if (Proxy)
                    {
                        const std::string Payload = "vless runtime payload";
                        const auto Write = co_await Proxy->WriteExact(
                            std::span<const std::byte>(
                                reinterpret_cast<const std::byte *>(Payload.data()),
                                Payload.size()));
                        auto IoFailure = Write.Failure;
                        if (!IoFailure.Failed() && Write.Bytes != Payload.size())
                        {
                            IoFailure = {Fault::Code::IoError};
                        }
                        std::array<std::byte, 128> Buffer{};
                        std::size_t Received = 0;
                        while (!IoFailure.Failed() && Received < Payload.size())
                        {
                            const auto Read = co_await Proxy->ReadSome(
                                std::span<std::byte>(Buffer).subspan(Received));
                            const auto Remaining = Payload.size() - Received;
                            if (Read.Bytes > Remaining)
                            {
                                IoFailure = {Fault::Code::InvalidArgument, Read.Failure.Native};
                                break;
                            }
                            Received += Read.Bytes;
                            if (Read.Failure.Failed())
                            {
                                IoFailure = Read.Failure;
                                break;
                            }
                            if (Read.Bytes == 0U)
                            {
                                IoFailure = {Fault::Code::Eof};
                                break;
                            }
                        }
                        if (IoFailure.Failed())
                        {
                            ADD_FAILURE() << "VLESS echo transfer failed: "
                                << Fault::Describe(IoFailure.Code)
                                << " Native=" << IoFailure.Native.category().name()
                                << ':' << IoFailure.Native.value();
                        }
                        Flow.EchoBack.assign(
                            reinterpret_cast<const char *>(Buffer.data()), Received);
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        CloseVlessTransmission(Proxy, FirstFailure);
        co_await FinishVlessTcpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    TEST(TcpListener, VlessTcpConnectFullChain)
    {
        Net::io_context Io;
        auto Echo = StartVlessTcpEcho(Io);
        const auto EchoPort = Echo.Acceptor->local_endpoint().port();
        auto ChainState = std::make_shared<VlessChainState>(
            VlessChainState{Io.get_executor(), EchoPort});

        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = Io.get_executor(),
            .Factory = VlessSessionFactory{
                ChainState, Vless::ServerConfig{TestUuid()}, std::chrono::seconds(2)},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{2})});

        bool HandshakeOk = false;
        std::string EchoBack;
        RunCoro(Io, RunVlessFullChainFlow(
            VlessFullChainFlow{Io, Listener, Echo, HandshakeOk, EchoBack}));

        EXPECT_TRUE(HandshakeOk);
        EXPECT_EQ(ChainState->RequestedHost, "example.com");
        EXPECT_EQ(ChainState->RequestedPort, "443");
        EXPECT_EQ(EchoBack, "vless runtime payload");
        EXPECT_FALSE(*Echo.Failure);
    }

    TEST(TcpListener, VlessTcpConnectBadUuid)
    {
        // 服务端期望 TestUuid，客户端使用全零 → 握手被拒。
        // Xray 语义：UUID 不匹配时服务端静默断开（不发响应），
        // 客户端读响应遇 EOF → 传输错误（非 bad_auth 码）。
        Vless::ServerConfig ServerConfiguration;
        ServerConfiguration.uuid = TestUuid();
        const auto Result = RunVlessConnect(
            Vless::Address{Vless::AddressType::Domain, "example.net", 22},
            Vless::ClientConfig{}, ServerConfiguration);
        EXPECT_TRUE(Result.Failure.Failed());
        EXPECT_TRUE(Result.Echo.empty());
    }

    struct VlessDialRefusedFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        bool &SawClose;
    };

    /** @brief 驱动 VLESS 拨号拒绝后的真实 EOF 收口。 */
    auto RunVlessDialRefusedFlow(VlessDialRefusedFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        SharedTransmission Proxy;
        try
        {
            if (co_await StartVlessListener(Flow.Listener))
            {
                auto Raw = co_await DialVlessListener(Flow.Ioc, Flow.Listener);
                if (Raw)
                {
                    auto ProtocolConnect = co_await ConnectVlessWithTestUuid(
                        std::move(*Raw),
                        Vless::Address{Vless::AddressType::Domain, "example.com", 80});
                    if (!ProtocolConnect)
                    {
                        ADD_FAILURE() << "Unexpected protocol handshake failure: "
                            << Prism::Fault::Describe(ProtocolConnect.error().Code)
                            << " Native=" << ProtocolConnect.error().Native.category().name()
                            << ":" << ProtocolConnect.error().Native.value();
                    }
                    else if (!*ProtocolConnect)
                    {
                        ADD_FAILURE() << "Protocol Connect succeeded without a connection owner";
                    }
                    else
                    {
                        Proxy = std::move(*ProtocolConnect);
                    }
                    if (Proxy)
                    {
                        std::array<std::byte, 8> Buffer{};
                        const auto Read = co_await Proxy->ReadSome(Buffer);
                        Flow.SawClose = Read.Bytes == 0U || Read.Failure.Failed();
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        CloseVlessTransmission(Proxy, FirstFailure);
        co_await FinishVlessListener(Flow.Listener, FirstFailure);
    }

    TEST(TcpListener, VlessTcpConnectDialRefused)
    {
        Net::io_context Io;
        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = Io.get_executor(),
            .Factory = VlessSessionFactory{
                {}, Vless::ServerConfig{TestUuid()}, {}, {}, true},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{3})});

        bool SawClose = false;
        RunCoro(Io, RunVlessDialRefusedFlow(
            VlessDialRefusedFlow{Io, Listener, SawClose}));
        EXPECT_TRUE(SawClose);
    }

    TEST(TcpListener, VlessTcpConnectIpv4)
    {
        const auto Result = RunVlessConnect(
            Vless::Address{Vless::AddressType::Ipv4, "93.184.216.34", 80});
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_EQ(Result.Failure.Code, Fault::Code::Success);
        EXPECT_EQ(Result.Echo, "chain payload");
        EXPECT_EQ(Result.Host, "93.184.216.34");
        EXPECT_EQ(Result.Port, "80");
    }

    TEST(TcpListener, VlessTcpConnectIpv6)
    {
        // VLESS wire 与 Network::Host 使用 16 字节；链路结果 Host 是 ToText 的显示文本。
        const std::array<std::uint8_t, 16> Bytes = {
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
            0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46};
        const std::string V6Host(reinterpret_cast<const char *>(Bytes.data()),
                                 Bytes.size());
        const auto ExpectedHost = Prism::Network::ToText(
            Prism::Network::Host(Prism::Network::Ipv6Bytes{Bytes}));
        const auto Result = RunVlessConnect(
            Vless::Address{Vless::AddressType::Ipv6, V6Host, 443});
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_EQ(Result.Failure.Code, Fault::Code::Success);
        EXPECT_EQ(Result.Echo, "chain payload");
        EXPECT_EQ(Result.Host, ExpectedHost.View());
        EXPECT_EQ(Result.Port, "443");
    }

    struct VlessHalfCloseFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VlessTcpEchoOwner &Echo;
        std::string &EchoBack;
    };

    /** @brief 驱动 VLESS 写半关闭后仍读取 echo 的 TCP 场景。 */
    auto RunVlessHalfCloseFlow(VlessHalfCloseFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        SharedTransmission Proxy;
        try
        {
            if (co_await StartVlessListener(Flow.Listener))
            {
                auto Raw = co_await DialVlessListener(Flow.Ioc, Flow.Listener);
                if (Raw)
                {
                    auto ProtocolConnect = co_await ConnectVlessWithTestUuid(
                        std::move(*Raw),
                        Vless::Address{Vless::AddressType::Domain, "example.com", 80});
                    if (!ProtocolConnect)
                    {
                        ADD_FAILURE() << "Unexpected protocol handshake failure: "
                            << Prism::Fault::Describe(ProtocolConnect.error().Code)
                            << " Native=" << ProtocolConnect.error().Native.category().name()
                            << ":" << ProtocolConnect.error().Native.value();
                    }
                    else if (!*ProtocolConnect)
                    {
                        ADD_FAILURE() << "Protocol Connect succeeded without a connection owner";
                    }
                    else
                    {
                        Proxy = std::move(*ProtocolConnect);
                    }
                    if (Proxy)
                    {
                        const std::string Payload = "half Close payload";
                        const auto Write = co_await Proxy->WriteExact(std::span<const std::byte>(
                            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
                        auto IoFailure = Write.Failure;
                        if (!IoFailure.Failed() && Write.Bytes != Payload.size())
                        {
                            IoFailure = {Fault::Code::IoError};
                        }
                        co_await Net::post(Flow.Ioc, Net::use_awaitable);
                        const auto Shutdown = co_await Proxy->WriteShutdown();
                        if (!Shutdown && !IoFailure.Failed())
                        {
                            IoFailure = Shutdown.error();
                        }
                        std::array<std::byte, 64> Buffer{};
                        std::size_t Received = 0;
                        while (!IoFailure.Failed() && Received < Payload.size())
                        {
                            const auto Read = co_await Proxy->ReadSome(
                                std::span<std::byte>(Buffer).subspan(Received));
                            const auto Remaining = Payload.size() - Received;
                            if (Read.Bytes > Remaining)
                            {
                                IoFailure = {Fault::Code::InvalidArgument, Read.Failure.Native};
                                break;
                            }
                            Received += Read.Bytes;
                            if (Read.Failure.Failed())
                            {
                                IoFailure = Read.Failure;
                                break;
                            }
                            if (Read.Bytes == 0U)
                            {
                                IoFailure = {Fault::Code::Eof};
                                break;
                            }
                        }
                        if (IoFailure.Failed())
                        {
                            ADD_FAILURE() << "VLESS half-close transfer failed: "
                                << Fault::Describe(IoFailure.Code)
                                << " Native=" << IoFailure.Native.category().name()
                                << ':' << IoFailure.Native.value();
                        }
                        Flow.EchoBack.assign(
                            reinterpret_cast<const char *>(Buffer.data()), Received);
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        CloseVlessTransmission(Proxy, FirstFailure);
        co_await FinishVlessTcpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    TEST(TcpListener, VlessTcpConnectHalfCloseClient)
    {
        Net::io_context Io;
        auto Echo = StartVlessTcpEcho(Io);
        const auto EchoPort = Echo.Acceptor->local_endpoint().port();
        auto ChainState = std::make_shared<VlessChainState>(
            VlessChainState{Io.get_executor(), EchoPort});
        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = Io.get_executor(),
            .Factory = VlessSessionFactory{
                ChainState, Vless::ServerConfig{TestUuid()}},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{4})});

        std::string EchoBack;
        RunCoro(Io, RunVlessHalfCloseFlow(
            VlessHalfCloseFlow{Io, Listener, Echo, EchoBack}));
        EXPECT_EQ(EchoBack, "half Close payload");
        EXPECT_FALSE(*Echo.Failure);
    }

    struct VlessIdleFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VlessTcpEchoOwner &Echo;
        bool &Closed;
    };

    /** @brief 驱动 VLESS relay idle timeout 后的真实关闭观察。 */
    auto RunVlessIdleFlow(VlessIdleFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        SharedTransmission Proxy;
        try
        {
            if (co_await StartVlessListener(Flow.Listener))
            {
                auto Raw = co_await DialVlessListener(Flow.Ioc, Flow.Listener);
                if (Raw)
                {
                    auto ProtocolConnect = co_await ConnectVlessWithTestUuid(
                        std::move(*Raw),
                        Vless::Address{Vless::AddressType::Domain, "example.com", 80});
                    if (!ProtocolConnect)
                    {
                        ADD_FAILURE() << "Unexpected protocol handshake failure: "
                            << Prism::Fault::Describe(ProtocolConnect.error().Code)
                            << " Native=" << ProtocolConnect.error().Native.category().name()
                            << ":" << ProtocolConnect.error().Native.value();
                    }
                    else if (!*ProtocolConnect)
                    {
                        ADD_FAILURE() << "Protocol Connect succeeded without a connection owner";
                    }
                    else
                    {
                        Proxy = std::move(*ProtocolConnect);
                    }
                    if (Proxy)
                    {
                        std::array<std::byte, 8> Buffer{};
                        const auto Read = co_await Proxy->ReadSome(Buffer);
                        Flow.Closed = Read.Bytes == 0U || Read.Failure.Failed();
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        CloseVlessTransmission(Proxy, FirstFailure);
        co_await FinishVlessTcpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    TEST(TcpListener, VlessTcpConnectIdleTimeout)
    {
        Net::io_context Io;
        auto Echo = StartVlessTcpEcho(Io);
        const auto EchoPort = Echo.Acceptor->local_endpoint().port();
        auto ChainState = std::make_shared<VlessChainState>(
            VlessChainState{Io.get_executor(), EchoPort});
        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = Io.get_executor(),
            .Factory = VlessSessionFactory{
                ChainState, Vless::ServerConfig{TestUuid()}, std::chrono::milliseconds(100)},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{5})});

        bool Closed = false;
        RunCoro(Io, RunVlessIdleFlow(
            VlessIdleFlow{Io, Listener, Echo, Closed}));
        EXPECT_TRUE(Closed);
        EXPECT_FALSE(*Echo.Failure);
    }

    struct VlessTrafficFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VlessTcpEchoOwner &Echo;
        TrafficRecorder &Recorder;
    };

    /** @brief 驱动 VLESS payload 与流量观测器收尾。 */
    auto RunVlessTrafficFlow(VlessTrafficFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        SharedTransmission Proxy;
        try
        {
            if (co_await StartVlessListener(Flow.Listener))
            {
                auto Raw = co_await DialVlessListener(Flow.Ioc, Flow.Listener);
                if (Raw)
                {
                    auto ProtocolConnect = co_await ConnectVlessWithTestUuid(
                        std::move(*Raw),
                        Vless::Address{Vless::AddressType::Domain, "example.com", 80});
                    if (!ProtocolConnect)
                    {
                        ADD_FAILURE() << "Unexpected protocol handshake failure: "
                            << Prism::Fault::Describe(ProtocolConnect.error().Code)
                            << " Native=" << ProtocolConnect.error().Native.category().name()
                            << ":" << ProtocolConnect.error().Native.value();
                    }
                    else if (!*ProtocolConnect)
                    {
                        ADD_FAILURE() << "Protocol Connect succeeded without a connection owner";
                    }
                    else
                    {
                        Proxy = std::move(*ProtocolConnect);
                    }
                    if (Proxy)
                    {
                        const std::string Payload = "traffic payload";
                        const auto Write = co_await Proxy->WriteExact(std::span<const std::byte>(
                            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
                        EXPECT_FALSE(Write.Failure.Failed());
                        EXPECT_EQ(Write.Bytes, Payload.size());
                        std::array<std::byte, 64> Buffer{};
                        const auto Read = co_await Proxy->ReadExact(
                            std::span<std::byte>(Buffer).first(Payload.size()));
                        EXPECT_FALSE(Read.Failure.Failed());
                        EXPECT_EQ(Read.Bytes, Payload.size());
                        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), Read.Bytes),
                                  Payload);
                        Net::steady_timer Timer(Flow.Ioc);
                        for (int Index = 0; Index < 300 && Flow.Recorder.Calls == 0; ++Index)
                        {
                            Timer.expires_after(std::chrono::milliseconds(10));
                            co_await Timer.async_wait(Net::use_awaitable);
                        }
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        CloseVlessTransmission(Proxy, FirstFailure);
        co_await FinishVlessTcpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    TEST(TcpListener, VlessTrafficReport)
    {
        Net::io_context Io;
        auto Echo = StartVlessTcpEcho(Io);
        const auto EchoPort = Echo.Acceptor->local_endpoint().port();
        auto ChainState = std::make_shared<VlessChainState>(
            VlessChainState{Io.get_executor(), EchoPort});
        auto RecorderOwner = std::make_shared<TrafficRecorder>();
        auto &Traffic = *RecorderOwner;
        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = Io.get_executor(),
            .Factory = VlessSessionFactory{
                ChainState, Vless::ServerConfig{TestUuid()}, {}, RecorderOwner},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{6})});

        RunCoro(Io, RunVlessTrafficFlow(
            VlessTrafficFlow{Io, Listener, Echo, Traffic}));
        EXPECT_EQ(Traffic.Calls, 1);
        EXPECT_GE(Traffic.Up, std::string("traffic payload").size());
        EXPECT_GE(Traffic.Down, std::string("traffic payload").size());
        // 此 ingress fixture 将该 UUID 明确注册为 AccountId{1}。
        EXPECT_EQ(Traffic.LastEvent.Account, Prism::AccountId{1});
        EXPECT_FALSE(*Echo.Failure);
    }

} // namespace
