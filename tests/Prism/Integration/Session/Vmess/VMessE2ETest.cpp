/**
 * @file VMessE2ETest.cpp
 * @brief VMess 纵向链路测试（链 P：代理协议 L3 经 adapter 接入缝）
 * @details 与 SOCKS5/VLESS/Trojan 共用同一套 runtime Session 编排：
 *          listen → recognition → adapter::MakeAcceptVmess →
 *          Dial Middleware → relay Middleware → echo 上游。
 */

#include <gtest/gtest.h>
#include <Prism/Runtime/SessionAdmissionTestSupport.hpp>

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
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Anytls/IngressFactory.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Protocols/Trojan/IngressFactory.hpp>
#include <Prism/Protocols/Vmess/IngressFactory.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Vmess/Vmess.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Prism/ProtocolIngressBindings.hpp>
#include "VMessTcpE2ETestSupport.hpp"

namespace
{

    namespace Net = boost::asio;
    namespace Runtime = Prism::Runtime;
    namespace Network = Prism::Network;
    namespace Vmess = Prism::Vmess;
    namespace Fault = Prism::Fault;
    using Prism::Error;
    using Prism::SharedTransmission;
    using Tcp = Net::ip::tcp;

    namespace VmessSupport = Prism::Testing::VmessTcpE2E;
    using VmessSupport::CloseVmessConnection;
    using VmessSupport::ConnectResult;
    using VmessSupport::DialVmessListener;
    using VmessSupport::FinishVmessListener;
    using VmessSupport::FinishVmessTcpFlow;
    using VmessSupport::StartVmessListener;
    using VmessSupport::StartVmessTcpEcho;
    using VmessSupport::TestUuid;
    using VmessSupport::VmessSessionFactory;
    using VmessSupport::VmessTcpEchoOwner;
    using VmessSupport::vmess_chain_state;

    // 公共样板（RunCoro/echo 上游/TailReadGuarded 等见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Prism::Testing::RunCoro;
    using Prism::Testing::TailReadGuarded;

    struct VmessConnectFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VmessTcpEchoOwner &Echo;
        const Vmess::Address &Target;
        const Vmess::ClientConfig &ClientConfig;
        std::shared_ptr<vmess_chain_state> Chain;
        ConnectResult &Result;
    };

    /** @brief 驱动 VMess TCP listener→admission→dial→echo 纵向链路。 */
    auto RunVmessConnectFlow(VmessConnectFlow Flow) -> Net::awaitable<void>
    {
        auto &Result = Flow.Result;
        std::exception_ptr FirstFailure;
        std::shared_ptr<Vmess::Conn<>> Proxy;
        try
        {
            if (!co_await StartVmessListener(Flow.Listener))
            {
                Result.Failure = Prism::Testing::FailureFromProtocolError(
                    Prism::Error::IoError);
            }
            else
            {
                auto Raw = co_await DialVmessListener(Flow.Ioc, Flow.Listener);
                if (!Raw)
                {
                    Result.Failure = Raw.error();
                }
                else
                {
                    auto ProtocolConnect = co_await Vmess::Connect(
                        Vmess::ConnectParameters{
                            std::move(*Raw), Flow.ClientConfig, Flow.Target,
                            Vmess::Command::Tcp});
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
                        const std::string Payload = "vmess runtime payload";
                        const auto Write = co_await Proxy->WriteExact(std::span<const std::byte>(
                            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
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
                        if (IoFailure.Failed())
                        {
                            Result.Failure = IoFailure;
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
        CloseVmessConnection(Proxy, FirstFailure);
        co_await FinishVmessTcpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    struct VmessDialRefusedFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        bool &SawClose;
    };

    /** @brief 驱动 VMess 拨号拒绝后的真实 EOF/错误收口。 */
    auto RunVmessDialRefusedFlow(VmessDialRefusedFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        std::shared_ptr<Vmess::Conn<>> Proxy;
        try
        {
            if (co_await StartVmessListener(Flow.Listener))
            {
                auto Raw = co_await DialVmessListener(Flow.Ioc, Flow.Listener);
                if (Raw)
                {
                    const auto ClientConfig = Vmess::ClientConfig{TestUuid()};
                    const auto Target = Vmess::Address{
                        Vmess::AddressType::Domain, "example.com", 80};
                    auto ProtocolConnect = co_await Vmess::Connect(
                        Vmess::ConnectParameters{
                            std::move(*Raw), ClientConfig, Target, Vmess::Command::Tcp});
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
        CloseVmessConnection(Proxy, FirstFailure);
        co_await FinishVmessListener(Flow.Listener, FirstFailure);
    }

    struct VmessHalfCloseFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VmessTcpEchoOwner &Echo;
        bool &CleanEof;
    };

    /** @brief 驱动 VMess 半关闭后的回显与 UnexpectedEof 收口。 */
    auto RunVmessHalfCloseFlow(VmessHalfCloseFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        std::shared_ptr<Vmess::Conn<>> Proxy;
        try
        {
            if (co_await StartVmessListener(Flow.Listener))
            {
                auto Raw = co_await DialVmessListener(Flow.Ioc, Flow.Listener);
                if (Raw)
                {
                    const auto ClientConfig = Vmess::ClientConfig{TestUuid()};
                    const auto Target = Vmess::Address{
                        Vmess::AddressType::Domain, "example.com", 80};
                    auto ProtocolConnect = co_await Vmess::Connect(
                        Vmess::ConnectParameters{
                            std::move(*Raw), ClientConfig, Target, Vmess::Command::Tcp});
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
                        const auto Write = co_await Proxy->WriteExact(std::span<const std::byte>(
                            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
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
                        EXPECT_EQ(Received, Payload.size());
                        EXPECT_FALSE(IoFailure.Failed());
                        const auto Shutdown = co_await Proxy->WriteShutdown();
                        EXPECT_TRUE(Shutdown);
                        std::array<std::byte, 8> Tail{};
                        std::error_code TailError;
                        const auto TailCount = co_await Prism::Testing::TailReadGuarded(
                            Proxy, Tail, TailError);
                        Flow.CleanEof = TailCount == 0 &&
                                        Prism::Fault::ToCode(TailError) ==
                                            Prism::Fault::Code::Eof;
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        CloseVmessConnection(Proxy, FirstFailure);
        co_await FinishVmessTcpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    struct VmessIdleFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VmessTcpEchoOwner &Echo;
        bool &Closed;
    };

    /** @brief 驱动 VMess 空闲超时并验证连接关闭。 */
    auto RunVmessIdleFlow(VmessIdleFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        std::shared_ptr<Vmess::Conn<>> Proxy;
        try
        {
            if (co_await StartVmessListener(Flow.Listener))
            {
                auto Raw = co_await DialVmessListener(Flow.Ioc, Flow.Listener);
                if (Raw)
                {
                    const auto ClientConfig = Vmess::ClientConfig{TestUuid()};
                    const auto Target = Vmess::Address{
                        Vmess::AddressType::Domain, "example.com", 80};
                    auto ProtocolConnect = co_await Vmess::Connect(
                        Vmess::ConnectParameters{
                            std::move(*Raw), ClientConfig, Target, Vmess::Command::Tcp});
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
                        Flow.Closed = Read.Bytes == 0U || Read.Failure.Failed();
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        CloseVmessConnection(Proxy, FirstFailure);
        co_await FinishVmessTcpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    /// 通用 VMess TCP 真实链路运行器
    auto run_vmess_connect(const Vmess::Address &Target,
                           Vmess::ClientConfig ccfg = {},
                           Vmess::ServerConfig scfg = {})
        -> ConnectResult
    {
        ConnectResult out;
        Net::io_context ioc;
        auto Echo = StartVmessTcpEcho(ioc);
        const auto echo_port = Echo.Acceptor->local_endpoint().port();
        auto StateObj = std::make_shared<vmess_chain_state>(
            vmess_chain_state{ioc.get_executor(), echo_port});

        Runtime::TcpListener listen(
            Runtime::TcpListener::Options{
            .Executor = ioc.get_executor(),
            .Factory = VmessSessionFactory{StateObj, scfg},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{1})});

        RunCoro(ioc, RunVmessConnectFlow(VmessConnectFlow{
            ioc, listen, Echo, Target, ccfg, StateObj, out}));
        EXPECT_FALSE(*Echo.Failure);
        return out;
    }

    TEST(TcpListener, VmessTcpConnectFullChain)
    {
        const auto r = run_vmess_connect(
            Vmess::Address{Vmess::AddressType::Domain, "example.com", 443},
            Vmess::ClientConfig{TestUuid()},
            Vmess::ServerConfig{TestUuid()});
        EXPECT_TRUE(r.Failure.Succeeded());
        EXPECT_EQ(r.Failure.Code, Fault::Code::Success);
        EXPECT_EQ(r.Echo, "vmess runtime payload");
        EXPECT_EQ(r.Host, "example.com");
        EXPECT_EQ(r.Port, "443");
    }

    TEST(TcpListener, VmessTcpConnectIpv4)
    {
        const auto r = run_vmess_connect(
            Vmess::Address{Vmess::AddressType::Ipv4, "1.2.3.4", 80},
            Vmess::ClientConfig{TestUuid()},
            Vmess::ServerConfig{TestUuid()});
        EXPECT_TRUE(r.Failure.Succeeded());
        EXPECT_EQ(r.Failure.Code, Fault::Code::Success);
        EXPECT_EQ(r.Echo, "vmess runtime payload");
        EXPECT_EQ(r.Host, "1.2.3.4");
        EXPECT_EQ(r.Port, "80");
    }

    TEST(TcpListener, VmessTcpConnectIpv6)
    {
        std::string WireHost(16, '\0');
        WireHost.back() = '\x01';
        const auto r = run_vmess_connect(
            Vmess::Address{Vmess::AddressType::Ipv6, std::move(WireHost), 80},
            Vmess::ClientConfig{TestUuid()},
            Vmess::ServerConfig{TestUuid()});
        EXPECT_TRUE(r.Failure.Succeeded());
        EXPECT_EQ(r.Failure.Code, Fault::Code::Success);
        EXPECT_EQ(r.Echo, "vmess runtime payload");
        // 正式网络目标将 16 字节 loopback 呈现为数值文本。
        const auto Host = Network::ParseHost(r.Host);
        ASSERT_TRUE(Host);
        const auto Address = Network::IpAddress(*Host);
        ASSERT_TRUE(Address);
        ASSERT_TRUE(Address->is_v6());
        EXPECT_EQ(Address->to_v6().to_bytes(),
            Net::ip::address_v6::loopback().to_bytes());
        EXPECT_EQ(r.Port, "80");
    }

    TEST(TcpListener, VmessTcpConnectBadUuid)
    {
        // 服务端期望 TestUuid，客户端全零 → AEAD 解密失败（bad_auth/io_error）
        const auto r = run_vmess_connect(
            Vmess::Address{Vmess::AddressType::Domain, "example.net", 22},
            Vmess::ClientConfig{},
            Vmess::ServerConfig{TestUuid()});
        EXPECT_TRUE(r.Failure.Failed());
        EXPECT_TRUE(r.Echo.empty());
    }

    TEST(TcpListener, VmessTcpConnectDialRefused)
    {
        Net::io_context ioc;
        Runtime::TcpListener listen(
            Runtime::TcpListener::Options{
            .Executor = ioc.get_executor(),
            .Factory = VmessSessionFactory{
                {}, Vmess::ServerConfig{TestUuid()}, {}, {}, true},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{2})});

        bool saw_close = false;
        RunCoro(ioc, RunVmessDialRefusedFlow(
            VmessDialRefusedFlow{ioc, listen, saw_close}));
        EXPECT_TRUE(saw_close);
    }

    TEST(TcpListener, VmessTcpConnectHalfCloseClient)
    {
        Net::io_context ioc;
        auto Echo = StartVmessTcpEcho(ioc);
        const auto echo_port = Echo.Acceptor->local_endpoint().port();
        auto StateObj = std::make_shared<vmess_chain_state>(
            vmess_chain_state{ioc.get_executor(), echo_port});

        Runtime::TcpListener listen(
            Runtime::TcpListener::Options{
            .Executor = ioc.get_executor(),
            .Factory = VmessSessionFactory{
                StateObj, Vmess::ServerConfig{TestUuid()}},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{3})});

        bool clean_eof = false;
        RunCoro(ioc, RunVmessHalfCloseFlow(
            VmessHalfCloseFlow{ioc, listen, Echo, clean_eof}));
        EXPECT_TRUE(clean_eof);
        EXPECT_FALSE(*Echo.Failure);
    }

    TEST(TcpListener, VmessTcpConnectIdleTimeout)
    {
        Net::io_context ioc;
        auto Echo = StartVmessTcpEcho(ioc);
        const auto echo_port = Echo.Acceptor->local_endpoint().port();
        auto StateObj = std::make_shared<vmess_chain_state>(
            vmess_chain_state{ioc.get_executor(), echo_port});

        Runtime::TcpListener listen(
            Runtime::TcpListener::Options{
            .Executor = ioc.get_executor(),
            .Factory = VmessSessionFactory{
                StateObj, Vmess::ServerConfig{TestUuid()}, std::chrono::milliseconds(150)},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{4})});

        bool closed = false;
        RunCoro(ioc, RunVmessIdleFlow(
            VmessIdleFlow{ioc, listen, Echo, closed}));
        EXPECT_TRUE(closed);
        EXPECT_FALSE(*Echo.Failure);
    }

} // namespace
