/**
 * @file TrojanE2ETest.cpp
 * @brief Trojan 纵向链路测试（链 P：代理协议 L3 经 adapter 接入缝）
 * @details 与 SOCKS5/VLESS 共用同一套 runtime Session 编排：
 *          listener → recognition → adapter::MakeAcceptTrojan →
 *          Dial Middleware → relay Middleware → echo 上游。
 *          验证点：runtime 零协议特判；Trojan 仅经 adapter 提供握手与数据面。
 */

#include <gtest/gtest.h>
#include "TrojanRuntimeTestSupport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Anytls/IngressFactory.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Protocols/Trojan/IngressFactory.hpp>
#include <Prism/Protocols/Vmess/IngressFactory.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include "TrojanRuntimeTestSupport.hpp"

namespace
{

    namespace Net = boost::asio;
    namespace Runtime = Prism::Runtime;
    namespace Network = Prism::Network;
    namespace Trojan = Prism::Trojan;
    namespace Fault = Prism::Fault;
    using Prism::Error;
    using Prism::SharedTransmission;
    using Tcp = Net::ip::tcp;

    namespace TrojanE2E = Prism::Testing::TrojanE2E;
    using TrojanE2E::CloseAndDrain;
    using TrojanE2E::ConnectResult;
    using TrojanE2E::DialTrojanUpstream;
    using TrojanE2E::FinishTrojanListener;
    using TrojanE2E::FinishTrojanTcpFlow;
    using TrojanE2E::MakeTrojanListenerAccounts;
    using TrojanE2E::RunCoro;
    using TrojanE2E::StartTrojanTcpEcho;
    using TrojanE2E::TailReadGuarded;
    using TrojanE2E::TrojanChainState;
    using TrojanE2E::TrojanSessionFactory;
    using TrojanE2E::TrojanTcpEchoOwner;

    struct TrojanConnectFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        TrojanTcpEchoOwner &Echo;
        const Trojan::Address &Target;
        const Trojan::ClientConfig &ClientConfig;
        std::shared_ptr<TrojanChainState> Chain;
        ConnectResult &Result;
    };

    /** @brief 驱动 Trojan TCP listener→admission→dial→echo 纵向链路。 */
    auto RunTrojanConnectFlow(TrojanConnectFlow Flow) -> Net::awaitable<void>
    {
        auto &Result = Flow.Result;
        std::exception_ptr FirstFailure;
        SharedTransmission Proxy;
        try
        {
            const auto StartResult = co_await Flow.Listener.Start(
                Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
            if (StartResult != Fault::Code::Success)
            {
                Result.Failure = {StartResult, {}};
            }
            else
            {
                const auto ListenPort = Flow.Listener.LocalEndpoint().port();
                Network::Dialer::Dialer Dialer(Flow.Ioc.get_executor());
                auto Raw = co_await Dialer.Connect(Network::Target{
                    *Prism::Network::ParseHost("127.0.0.1"), ListenPort});
                if (!Raw)
                {
                    Result.Failure = Raw.error();
                }
                else
                {
                    auto ProtocolConnect = co_await Trojan::Connect(
                        Trojan::ConnectParameters{
                            std::move(*Raw), Flow.ClientConfig, Flow.Target, Trojan::Command::Connect});
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
                        const std::string Payload = "trojan runtime payload";
                        const auto Written = co_await Proxy->WriteExact(std::span<const std::byte>(
                            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
                        EXPECT_FALSE(Written.Failure.Failed())
                            << "FaultCode=" << Fault::Describe(Written.Failure.Code)
                            << " NativeCategory=" << Written.Failure.Native.category().name()
                            << " NativeValue=" << Written.Failure.Native.value();
                        EXPECT_EQ(Written.Bytes, Payload.size());
                        std::array<std::byte, 64> Buffer{};
                        std::size_t Received = 0;
                        while (Received < Payload.size())
                        {
                            const auto Read = co_await Proxy->ReadSome(
                                std::span<std::byte>(Buffer).subspan(Received));
                            if (Read.Failure.Failed() || Read.Bytes == 0) break;
                            Received += Read.Bytes;
                        }
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
        try
        {
            if (Proxy)
            {
                co_await CloseAndDrain(Proxy);
            }
        }
        catch (...)
        {
            if (!FirstFailure)
            {
                FirstFailure = std::current_exception();
            }
        }
        co_await FinishTrojanTcpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    /// 通用 Trojan TCP 真实链路运行器（自建 ioc）
    auto RunTrojanConnect(const Trojan::Address &Target,
                            Trojan::ClientConfig ClientConfig = {},
                            Trojan::ServerConfig ServerConfig = {})
        -> ConnectResult
    {
        ConnectResult Output;
        Net::io_context IoContext;
        auto Echo = StartTrojanTcpEcho(IoContext);
        const auto EchoPort = Echo.Acceptor->local_endpoint().port();
        auto StateObj = std::make_shared<TrojanChainState>(
            TrojanChainState{IoContext.get_executor(), EchoPort});
        auto Accounts = MakeTrojanListenerAccounts(ServerConfig, Prism::GenerationId{1});

        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = IoContext.get_executor(),
            .Factory = TrojanSessionFactory{
                .Chain = StateObj, .Configuration = ServerConfig, .Accounts = Accounts},
            .Publication = Accounts->Publication});

        RunCoro(IoContext, RunTrojanConnectFlow(TrojanConnectFlow{
            IoContext, Listener, Echo, Target, ClientConfig, StateObj, Output}));
        EXPECT_FALSE(*Echo.Failure);
        return Output;
    }

    TEST(TcpListener, TrojanTcpConnectFullChain)
    {
        const auto Result = RunTrojanConnect(
            Trojan::Address{Trojan::AddressType::Domain, "example.com", 443},
            Trojan::ClientConfig{"Secret"},
            Trojan::ServerConfig{"Secret"});
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_EQ(Result.Failure.Code, Fault::Code::Success);
        EXPECT_EQ(Result.Echo, "trojan runtime payload");
        EXPECT_EQ(Result.Host, "example.com");
        EXPECT_EQ(Result.Port, "443");
    }

    TEST(TcpListener, TrojanTcpConnectIpv4)
    {
        const auto Result = RunTrojanConnect(
            Trojan::Address{Trojan::AddressType::Ipv4, "1.2.3.4", 80},
            Trojan::ClientConfig{"Secret"},
            Trojan::ServerConfig{"Secret"});
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_EQ(Result.Failure.Code, Fault::Code::Success);
        EXPECT_EQ(Result.Echo, "trojan runtime payload");
        EXPECT_EQ(Result.Host, "1.2.3.4");
        EXPECT_EQ(Result.Port, "80");
    }

    TEST(TcpListener, TrojanTcpConnectIpv6)
    {
        std::string WireHost(16, '\0');
        WireHost.back() = '\x01';
        const auto Result = RunTrojanConnect(
            Trojan::Address{Trojan::AddressType::Ipv6, std::move(WireHost), 80},
            Trojan::ClientConfig{"Secret"},
            Trojan::ServerConfig{"Secret"});
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_EQ(Result.Failure.Code, Fault::Code::Success);
        EXPECT_EQ(Result.Echo, "trojan runtime payload");
        // 原目标仍为 ::1；wire 保有16字节，正式网络目标在观察边界呈现数值文本。
        const auto Host = Network::ParseHost(Result.Host);
        ASSERT_TRUE(Host);
        const auto Address = Network::IpAddress(*Host);
        ASSERT_TRUE(Address);
        ASSERT_TRUE(Address->is_v6());
        const auto Bytes = Address->to_v6().to_bytes();
        EXPECT_EQ(Bytes.size(), 16u);
        EXPECT_EQ(Bytes, Net::ip::address_v6::loopback().to_bytes());
        EXPECT_EQ(Result.Port, "80");
    }

    TEST(TcpListener, TrojanTcpConnectBadPassword)
    {
        // 服务端密码 "right"，客户端 "wrong" → 认证失败静默断（Xray 语义）
        const auto Result = RunTrojanConnect(
            Trojan::Address{Trojan::AddressType::Domain, "example.net", 22},
            Trojan::ClientConfig{"wrong"},
            Trojan::ServerConfig{"right"});
        // Trojan 客户端不读服务端应答，Connect 恒 success；bad Auth 表现为
        // 服务端静默断（Xray 语义）→ 数据面空（无 relay）。
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_EQ(Result.Failure.Code, Fault::Code::Success);
        EXPECT_TRUE(Result.Echo.empty());
    }

    struct TrojanDialRefusedFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        bool &SawClose;
    };

    /** @brief 驱动 Trojan 拨号拒绝后的真实 EOF/错误收口。 */
    auto RunTrojanDialRefusedFlow(TrojanDialRefusedFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        SharedTransmission Proxy;
        try
        {
            const auto StartResult = co_await Flow.Listener.Start(
                Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
            EXPECT_EQ(StartResult, Fault::Code::Success);
            if (StartResult == Fault::Code::Success)
            {
                const auto ListenPort = Flow.Listener.LocalEndpoint().port();
                Network::Dialer::Dialer Dialer(Flow.Ioc.get_executor());
                auto Raw = co_await Dialer.Connect(Network::Target{
                    *Prism::Network::ParseHost("127.0.0.1"), ListenPort});
                if (Raw)
                {
                    const Trojan::ClientConfig Config{"Secret"};
                    const Trojan::Address Target{Trojan::AddressType::Domain, "example.com", 80};
                    auto ProtocolConnect = co_await Trojan::Connect(
                        Trojan::ConnectParameters{
                            std::move(*Raw), Config, Target, Trojan::Command::Connect});
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
                        Flow.SawClose = Read.Bytes == 0 || Read.Failure.Failed();
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        try
        {
            if (Proxy)
            {
                co_await CloseAndDrain(Proxy);
            }
        }
        catch (...)
        {
            if (!FirstFailure)
            {
                FirstFailure = std::current_exception();
            }
        }
        co_await FinishTrojanListener(Flow.Listener, FirstFailure);
    }

    TEST(TcpListener, TrojanTcpConnectDialRefused)
    {
        Net::io_context IoContext;
        const Trojan::ServerConfig Configuration{"Secret"};
        auto Accounts = MakeTrojanListenerAccounts(Configuration, Prism::GenerationId{2});
        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = IoContext.get_executor(),
            .Factory = TrojanSessionFactory{
                .Configuration = Configuration, .Accounts = Accounts, .RejectDial = true},
            .Publication = Accounts->Publication});

        bool SawClose = false;
        RunCoro(IoContext, RunTrojanDialRefusedFlow(
            TrojanDialRefusedFlow{IoContext, Listener, SawClose}));
        EXPECT_TRUE(SawClose);
    }

    struct TrojanHalfCloseFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        TrojanTcpEchoOwner &Echo;
        bool &CleanEof;
    };

    /** @brief 驱动 Trojan 写半关闭后的真实 EOF 收口。 */
    auto RunTrojanHalfCloseFlow(TrojanHalfCloseFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        SharedTransmission Proxy;
        try
        {
            const auto StartResult = co_await Flow.Listener.Start(
                Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
            EXPECT_EQ(StartResult, Fault::Code::Success);
            if (StartResult == Fault::Code::Success)
            {
                const auto ListenPort = Flow.Listener.LocalEndpoint().port();
                Network::Dialer::Dialer Dialer(Flow.Ioc.get_executor());
                auto Raw = co_await Dialer.Connect(Network::Target{
                    *Prism::Network::ParseHost("127.0.0.1"), ListenPort});
                if (Raw)
                {
                    const Trojan::ClientConfig Config{"Secret"};
                    const Trojan::Address Target{Trojan::AddressType::Domain, "example.com", 80};
                    auto ProtocolConnect = co_await Trojan::Connect(
                        Trojan::ConnectParameters{
                            std::move(*Raw), Config, Target, Trojan::Command::Connect});
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
                        const std::string Payload = "half-Close Probe";
                        const auto Written = co_await Proxy->WriteExact(std::span<const std::byte>(
                            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
                        EXPECT_FALSE(Written.Failure.Failed())
                            << "FaultCode=" << Fault::Describe(Written.Failure.Code)
                            << " NativeCategory=" << Written.Failure.Native.category().name()
                            << " NativeValue=" << Written.Failure.Native.value();
                        EXPECT_EQ(Written.Bytes, Payload.size());
                        std::array<std::byte, 64> Buffer{};
                        std::size_t Received = 0;
                        while (Received < Payload.size())
                        {
                            const auto Read = co_await Proxy->ReadSome(
                                std::span<std::byte>(Buffer).subspan(Received));
                            if (Read.Failure.Failed() || Read.Bytes == 0) break;
                            Received += Read.Bytes;
                        }
                        EXPECT_EQ(Received, Payload.size());
                        const auto Shutdown = co_await Proxy->WriteShutdown();
                        EXPECT_TRUE(Shutdown);
                        std::array<std::byte, 8> Tail{};
                        std::error_code TailError;
                        const auto Count = co_await Prism::Testing::TailReadGuarded(
                            Proxy, Tail, TailError);
                        Flow.CleanEof = Count == 0 && Prism::Fault::ToCode(TailError) == Prism::Fault::Code::Eof;
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        try
        {
            if (Proxy)
            {
                co_await CloseAndDrain(Proxy);
            }
        }
        catch (...)
        {
            if (!FirstFailure)
            {
                FirstFailure = std::current_exception();
            }
        }
        co_await FinishTrojanTcpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    TEST(TcpListener, TrojanTcpConnectHalfCloseClient)
    {
        // 发送数据收到 echo 后，客户端半关闭（Shutdown 写），读侧应干净 EOF
        Net::io_context IoContext;
        auto Echo = StartTrojanTcpEcho(IoContext);
        const auto EchoPort = Echo.Acceptor->local_endpoint().port();
        auto StateObj = std::make_shared<TrojanChainState>(
            TrojanChainState{IoContext.get_executor(), EchoPort});
        const Trojan::ServerConfig Configuration{"Secret"};
        auto Accounts = MakeTrojanListenerAccounts(Configuration, Prism::GenerationId{3});

        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = IoContext.get_executor(),
            .Factory = TrojanSessionFactory{
                .Chain = StateObj, .Configuration = Configuration, .Accounts = Accounts},
            .Publication = Accounts->Publication});

        bool CleanEof = false;
        RunCoro(IoContext, RunTrojanHalfCloseFlow(
            TrojanHalfCloseFlow{IoContext, Listener, Echo, CleanEof}));
        EXPECT_TRUE(CleanEof);
        EXPECT_FALSE(*Echo.Failure);
    }

    struct TrojanIdleFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        TrojanTcpEchoOwner &Echo;
        bool &Closed;
    };

    /** @brief 驱动 Trojan relay idle timeout 关闭观察。 */
    auto RunTrojanIdleFlow(TrojanIdleFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        SharedTransmission Proxy;
        try
        {
            const auto StartResult = co_await Flow.Listener.Start(
                Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
            EXPECT_EQ(StartResult, Fault::Code::Success);
            if (StartResult == Fault::Code::Success)
            {
                const auto ListenPort = Flow.Listener.LocalEndpoint().port();
                Network::Dialer::Dialer Dialer(Flow.Ioc.get_executor());
                auto Raw = co_await Dialer.Connect(Network::Target{
                    *Prism::Network::ParseHost("127.0.0.1"), ListenPort});
                if (Raw)
                {
                    const Trojan::ClientConfig Config{"Secret"};
                    const Trojan::Address Target{Trojan::AddressType::Domain, "example.com", 80};
                    auto ProtocolConnect = co_await Trojan::Connect(
                        Trojan::ConnectParameters{
                            std::move(*Raw), Config, Target, Trojan::Command::Connect});
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
                        Net::steady_timer Timer(
                            Flow.Ioc.get_executor(), std::chrono::milliseconds(400));
                        co_await Timer.async_wait(Net::use_awaitable);
                        std::array<std::byte, 8> Buffer{};
                        const auto Read = co_await Proxy->ReadSome(Buffer);
                        Flow.Closed = Read.Bytes == 0 || Read.Failure.Failed();
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        try
        {
            if (Proxy)
            {
                co_await CloseAndDrain(Proxy);
            }
        }
        catch (...)
        {
            if (!FirstFailure)
            {
                FirstFailure = std::current_exception();
            }
        }
        co_await FinishTrojanTcpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    TEST(TcpListener, TrojanTcpConnectIdleTimeout)
    {
        // 不发送任何数据，relay 空闲超时后会话应关闭
        Net::io_context IoContext;
        auto Echo = StartTrojanTcpEcho(IoContext);
        const auto EchoPort = Echo.Acceptor->local_endpoint().port();
        auto StateObj = std::make_shared<TrojanChainState>(
            TrojanChainState{IoContext.get_executor(), EchoPort});
        const Trojan::ServerConfig Configuration{"Secret"};
        auto Accounts = MakeTrojanListenerAccounts(Configuration, Prism::GenerationId{4});

        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = IoContext.get_executor(),
            .Factory = TrojanSessionFactory{
                .Chain = StateObj, .Configuration = Configuration, .Accounts = Accounts,
                .RelayIdleTimeout = std::chrono::milliseconds(150)},
            .Publication = Accounts->Publication});

        bool Closed = false;
        RunCoro(IoContext, RunTrojanIdleFlow(
            TrojanIdleFlow{IoContext, Listener, Echo, Closed}));
        EXPECT_TRUE(Closed);
        EXPECT_FALSE(*Echo.Failure);
    }

} // namespace
