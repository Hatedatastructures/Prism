/**
 * @file VMessE2ETest.cpp
 * @brief VMess 纵向链路测试（链 P：代理协议 L3 经 adapter 接入缝）
 * @details 与 SOCKS5/VLESS/Trojan 共用同一套 runtime Session 编排：
 *          listen → recognition → adapter::MakeAcceptVmess →
 *          Dial Middleware → relay Middleware → echo 上游。
 */

#include <gtest/gtest.h>
#include <Preview/Runtime/SessionAdmissionTestSupport.hpp>

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

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Protocols/Anytls/IngressFactory.hpp>
#include <Preview/Protocols/Vless/IngressFactory.hpp>
#include <Preview/Protocols/Trojan/IngressFactory.hpp>
#include <Preview/Protocols/Vmess/IngressFactory.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Vmess/Vmess.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Preview/ProtocolIngressBindings.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Runtime = Preview::Runtime;
    namespace Network = Preview::Network;
    namespace Vmess = Preview::Vmess;
    namespace Fault = Preview::Fault;
    using Preview::Error;
    using Preview::SharedTransmission;
    using Tcp = Net::ip::tcp;

    using TcpEchoDone = Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct VmessTcpEchoOwner final
    {
        std::shared_ptr<Tcp::acceptor> Acceptor;
        std::shared_ptr<TcpEchoDone> Done;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    auto StartVmessTcpEcho(Net::io_context &Io) -> VmessTcpEchoOwner
    {
        VmessTcpEchoOwner Owner;
        Owner.Acceptor = std::make_shared<Tcp::acceptor>(
            Io, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        Owner.Done = std::make_shared<TcpEchoDone>(Io.get_executor(), 1);
        Owner.Failure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(
            Io.get_executor(), Preview::Testing::AcceptEchoLoop(*Owner.Acceptor),
            [Owner](const std::exception_ptr &ErrorValue)
            {
                if (ErrorValue && !*Owner.Failure)
                {
                    *Owner.Failure = ErrorValue;
                }
                (void)Owner.Done->try_send(
                    boost::system::error_code{}, true);
            });
        return Owner;
    }

    auto StopVmessTcpEcho(VmessTcpEchoOwner &Owner) -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        Owner.Acceptor->close(ErrorCode);
        (void)co_await Owner.Done->async_receive(Net::use_awaitable);
        if (*Owner.Failure)
        {
            std::rethrow_exception(*Owner.Failure);
        }
    }

    /** @brief 等待 VMess TCP echo 和 listener 的真实关闭完成。 */
    auto FinishVmessTcpFlow(
        VmessTcpEchoOwner &Echo, Runtime::TcpListener &Listener,
        std::exception_ptr &FirstFailure) -> Net::awaitable<void>
    {
        try
        {
            co_await StopVmessTcpEcho(Echo);
        }
        catch (...)
        {
            if (!FirstFailure)
            {
                FirstFailure = std::current_exception();
            }
        }
        try
        {
            co_await Listener.Shutdown();
        }
        catch (...)
        {
            if (!FirstFailure)
            {
                FirstFailure = std::current_exception();
            }
        }
        if (FirstFailure)
        {
            std::rethrow_exception(FirstFailure);
        }
    }

    /** @brief 等待没有 echo owner 的 VMess listener 真实关闭。 */
    auto FinishVmessListener(
        Runtime::TcpListener &Listener,
        std::exception_ptr &FirstFailure) -> Net::awaitable<void>
    {
        try
        {
            co_await Listener.Shutdown();
        }
        catch (...)
        {
            if (!FirstFailure)
            {
                FirstFailure = std::current_exception();
            }
        }
        if (FirstFailure)
        {
            std::rethrow_exception(FirstFailure);
        }
    }

    /** @brief 启动 VMess 测试 listener，并统一处理启动结果。 */
    auto StartVmessListener(Runtime::TcpListener &Listener) -> Net::awaitable<bool>
    {
        const auto Result = co_await Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(Result, Fault::Code::Success);
        co_return Result == Fault::Code::Success;
    }

    /**
     * @brief 通过 VMess listener 建立测试 client 的 TCP 连接。
     * @param Ioc 拨号 executor 所属的 io_context。
     * @param Listener 同步借用其本地 endpoint；协程返回前不保存引用。
     * @return 连接所有者或保留分类与原生原因的失败值；调用者拥有返回的 transmission。
     */
    auto DialVmessListener(
        Net::io_context &Ioc, Runtime::TcpListener &Listener)
        -> Net::awaitable<std::expected<SharedTransmission, Preview::Fault::Failure>>
    {
        Network::Dialer::Dialer Dialer(Ioc.get_executor());
        co_return co_await Dialer.Connect(
            {*Preview::Network::ParseHost("127.0.0.1"), Listener.LocalEndpoint().port()});
    }

    /** @brief 关闭 VMess client connection，并保存首个关闭异常。 */
    auto CloseVmessConnection(
        std::shared_ptr<Vmess::Conn<>> &Proxy,
        std::exception_ptr &FirstFailure) -> void
    {
        try
        {
            if (Proxy)
            {
                Proxy->Close();
            }
        }
        catch (...)
        {
            if (!FirstFailure)
            {
                FirstFailure = std::current_exception();
            }
        }
    }

    // 公共样板（RunCoro/echo 上游/TailReadGuarded 等见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Preview::Testing::AcceptEchoLoop;
    using Preview::Testing::ChainState;
    using ConnectResult = Preview::Testing::ConnectResult;
    using Preview::Testing::MakeUuid;
    using Preview::Testing::RunCoro;
    using Preview::Testing::TailReadGuarded;
    using Preview::Testing::TcpEchoServer;
    using Preview::Testing::ToHex;
    using TrafficRecorder = Preview::Testing::TrafficRecorder;

    using boost::asio::experimental::awaitable_operators::operator||;

    /// VMess 纵向测试共享状态（复用公共 Preview::Testing::ChainState）
    using vmess_chain_state = Preview::Testing::ChainState;

    /// 测试 UUID 兼容别名
    inline auto test_uuid() -> std::array<std::uint8_t, 16>
    {
        return MakeUuid();
    }

    /// 连接 VMess 纵向测试的回环上游（复用公共 DialUpstream）
    auto dial_vmess_upstream(
        const std::shared_ptr<vmess_chain_state> &State,
        const Network::Target &Target)
        -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
    {
        co_return co_await Preview::Testing::DialUpstream(State, Target);
    }

    struct VmessSessionFactory final
    {
        std::shared_ptr<vmess_chain_state> Chain;
        Vmess::ServerConfig Configuration;
        std::chrono::milliseconds RelayIdleTimeout{0};
        std::shared_ptr<TrafficRecorder> Traffic;
        bool RejectDial{false};

        auto operator()(Preview::Runtime::SessionAdmission Admission) const
            -> std::shared_ptr<Runtime::Session>
        {
            Runtime::SessionOptions Options;
            auto UseState = Preview::Testing::MakeProtocolIngressUseState();
            Options.Services->GenerationUseState = UseState;
            Options.Services->AcceptProtocol = Preview::Testing::MakeVmessIngress(
                Configuration, Preview::Testing::VmessIngressResources{
                    {}, {}, {}, UseState, Admission.Inbound->Executor()}, Preview::Vmess::IngressRoute{});
            if (RejectDial)
            {
                Options.Services->Dial = [](const Network::Target &)
                    -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
                { co_return std::unexpected(Fault::Failure{Fault::Code::ConnectionRefused}); };
            }
            else
            {
                const auto ChainValue = Chain;
                Options.Services->Dial = [ChainValue](const Network::Target &Target)
                    -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
                { co_return co_await dial_vmess_upstream(ChainValue, Target); };
            }
            if (RelayIdleTimeout.count() != 0) Options.Services->RelayIdleTimeout = RelayIdleTimeout;
            Options.Services->Traffic = Traffic;
            return std::make_shared<Runtime::Session>(std::move(Options));
        }
    };

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
                Result.Failure = Preview::Testing::FailureFromProtocolError(
                    Preview::Error::IoError);
            }
            else
            {
                std::error_code ErrorCode;
                auto Raw = co_await DialVmessListener(Flow.Ioc, Flow.Listener);
                if (!Raw)
                {
                    Result.Failure = Raw.error();
                }
                else
                {
                    auto ProtocolConnect = co_await Vmess::Connect({
                        std::move(*Raw), Flow.ClientConfig, Flow.Target,
                        static_cast<std::uint8_t>(Vmess::Command::Tcp)});
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
                        co_await Proxy->AsyncWrite(std::span<const std::byte>(
                            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()),
                            ErrorCode);
                        std::array<std::byte, 64> Buffer{};
                        std::size_t Received = 0;
                        while (!ErrorCode && Received < Payload.size())
                        {
                            const auto Count = co_await Proxy->async_read_some(
                                std::span<std::byte>(Buffer).subspan(Received), ErrorCode);
                            if (Count == 0) break;
                            Received += Count;
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
                std::error_code ErrorCode;
                auto Raw = co_await DialVmessListener(Flow.Ioc, Flow.Listener);
                if (Raw)
                {
                    auto ProtocolConnect = co_await Vmess::Connect({
                        std::move(*Raw), Vmess::ClientConfig{test_uuid()},
                        Vmess::Address{Vmess::AddressType::Domain, "example.com", 80},
                        static_cast<std::uint8_t>(Vmess::Command::Tcp)});
                    if (!ProtocolConnect)
                    {
                        ADD_FAILURE() << "Unexpected protocol handshake failure: "
                            << Preview::Fault::Describe(ProtocolConnect.error().Code)
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
                        const auto Count = co_await Proxy->async_read_some(Buffer, ErrorCode);
                        Flow.SawClose = Count == 0 || ErrorCode;
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
                std::error_code ErrorCode;
                auto Raw = co_await DialVmessListener(Flow.Ioc, Flow.Listener);
                if (Raw)
                {
                    auto ProtocolConnect = co_await Vmess::Connect({
                        std::move(*Raw), Vmess::ClientConfig{test_uuid()},
                        Vmess::Address{Vmess::AddressType::Domain, "example.com", 80},
                        static_cast<std::uint8_t>(Vmess::Command::Tcp)});
                    if (!ProtocolConnect)
                    {
                        ADD_FAILURE() << "Unexpected protocol handshake failure: "
                            << Preview::Fault::Describe(ProtocolConnect.error().Code)
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
                        co_await Proxy->AsyncWrite(std::span<const std::byte>(
                            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()),
                            ErrorCode);
                        std::array<std::byte, 64> Buffer{};
                        std::size_t Received = 0;
                        while (!ErrorCode && Received < Payload.size())
                        {
                            const auto Count = co_await Proxy->async_read_some(
                                std::span<std::byte>(Buffer).subspan(Received), ErrorCode);
                            if (Count == 0) break;
                            Received += Count;
                        }
                        EXPECT_EQ(Received, Payload.size());
                        Proxy->Shutdown();
                        std::array<std::byte, 8> Tail{};
                        std::error_code TailError;
                        const auto TailCount = co_await Preview::Testing::TailReadGuarded(
                            Proxy, Tail, TailError);
                        Flow.CleanEof = TailCount == 0 &&
                                        TailError == ::Preview::make_error_code(
                                            ::Preview::Error::UnexpectedEof);
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
                std::error_code ErrorCode;
                auto Raw = co_await DialVmessListener(Flow.Ioc, Flow.Listener);
                if (Raw)
                {
                    auto ProtocolConnect = co_await Vmess::Connect({
                        std::move(*Raw), Vmess::ClientConfig{test_uuid()},
                        Vmess::Address{Vmess::AddressType::Domain, "example.com", 80},
                        static_cast<std::uint8_t>(Vmess::Command::Tcp)});
                    if (!ProtocolConnect)
                    {
                        ADD_FAILURE() << "Unexpected protocol handshake failure: "
                            << Preview::Fault::Describe(ProtocolConnect.error().Code)
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
                        const auto Count = co_await Proxy->async_read_some(Buffer, ErrorCode);
                        Flow.Closed = Count == 0 || ErrorCode;
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

    struct VmessTrafficFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VmessTcpEchoOwner &Echo;
    };

    /** @brief 驱动 VMess 业务字节并等待 listener registry 的真实终结。 */
    auto RunVmessTrafficFlow(VmessTrafficFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        std::shared_ptr<Vmess::Conn<>> Proxy;
        try
        {
            if (co_await StartVmessListener(Flow.Listener))
            {
                std::error_code ErrorCode;
                auto Raw = co_await DialVmessListener(Flow.Ioc, Flow.Listener);
                if (Raw)
                {
                    auto ProtocolConnect = co_await Vmess::Connect({
                        std::move(*Raw), Vmess::ClientConfig{test_uuid()},
                        Vmess::Address{Vmess::AddressType::Domain, "example.com", 80},
                        static_cast<std::uint8_t>(Vmess::Command::Tcp)});
                    if (!ProtocolConnect)
                    {
                        ADD_FAILURE() << "Unexpected protocol handshake failure: "
                            << Preview::Fault::Describe(ProtocolConnect.error().Code)
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
                        const std::string Payload = "traffic identity Probe";
                        co_await Proxy->AsyncWrite(std::span<const std::byte>(
                            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()),
                            ErrorCode);
                        std::array<std::byte, 64> Buffer{};
                        std::size_t Received = 0;
                        while (!ErrorCode && Received < Payload.size())
                        {
                            const auto Count = co_await Proxy->async_read_some(
                                std::span<std::byte>(Buffer).subspan(Received), ErrorCode);
                            if (Count == 0) break;
                            Received += Count;
                        }
                        EXPECT_FALSE(ErrorCode);
                        EXPECT_EQ(Received, Payload.size());
                        EXPECT_EQ(std::string(
                                      reinterpret_cast<const char *>(Buffer.data()), Received),
                                  Payload);
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
            .Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
                Preview::GenerationId{1}),
            .Factory = VmessSessionFactory{StateObj, scfg}});

        RunCoro(ioc, RunVmessConnectFlow(VmessConnectFlow{
            ioc, listen, Echo, Target, ccfg, StateObj, out}));
        EXPECT_FALSE(*Echo.Failure);
        return out;
    }

    TEST(TcpListener, VmessTcpConnectFullChain)
    {
        const auto r = run_vmess_connect(
            Vmess::Address{Vmess::AddressType::Domain, "example.com", 443},
            Vmess::ClientConfig{test_uuid()},
            Vmess::ServerConfig{test_uuid()});
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
            Vmess::ClientConfig{test_uuid()},
            Vmess::ServerConfig{test_uuid()});
        EXPECT_TRUE(r.Failure.Succeeded());
        EXPECT_EQ(r.Failure.Code, Fault::Code::Success);
        EXPECT_EQ(r.Echo, "vmess runtime payload");
        EXPECT_EQ(r.Host, "1.2.3.4");
        EXPECT_EQ(r.Port, "80");
    }

    TEST(TcpListener, VmessTcpConnectIpv6)
    {
        const auto r = run_vmess_connect(
            Vmess::Address{Vmess::AddressType::Ipv6, "::1", 80},
            Vmess::ClientConfig{test_uuid()},
            Vmess::ServerConfig{test_uuid()});
        EXPECT_TRUE(r.Failure.Succeeded());
        EXPECT_EQ(r.Failure.Code, Fault::Code::Success);
        EXPECT_EQ(r.Echo, "vmess runtime payload");
        // VMess ipv6 线缆为 16 字节二进制
        EXPECT_EQ(r.Host.size(), 16u);
        EXPECT_EQ(r.Port, "80");
    }

    TEST(TcpListener, VmessTcpConnectBadUuid)
    {
        // 服务端期望 test_uuid，客户端全零 → AEAD 解密失败（bad_auth/io_error）
        const auto r = run_vmess_connect(
            Vmess::Address{Vmess::AddressType::Domain, "example.net", 22},
            Vmess::ClientConfig{},
            Vmess::ServerConfig{test_uuid()});
        EXPECT_TRUE(r.Failure.Failed());
        EXPECT_TRUE(r.Echo.empty());
    }

    TEST(TcpListener, VmessTcpConnectDialRefused)
    {
        Net::io_context ioc;
        Runtime::TcpListener listen(
            Runtime::TcpListener::Options{
            .Executor = ioc.get_executor(),
            .Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
                Preview::GenerationId{2}),
            .Factory = VmessSessionFactory{
                {}, Vmess::ServerConfig{test_uuid()}, {}, {}, true}});

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
            .Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
                Preview::GenerationId{3}),
            .Factory = VmessSessionFactory{
                StateObj, Vmess::ServerConfig{test_uuid()}}});

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
            .Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
                Preview::GenerationId{4}),
            .Factory = VmessSessionFactory{
                StateObj, Vmess::ServerConfig{test_uuid()}, std::chrono::milliseconds(150)}});

        bool closed = false;
        RunCoro(ioc, RunVmessIdleFlow(
            VmessIdleFlow{ioc, listen, Echo, closed}));
        EXPECT_TRUE(closed);
        EXPECT_FALSE(*Echo.Failure);
    }

    TEST(TcpListener, VmessTrafficIdentity)
    {
        Net::io_context ioc;
        auto Echo = StartVmessTcpEcho(ioc);
        const auto echo_port = Echo.Acceptor->local_endpoint().port();
        auto StateObj = std::make_shared<vmess_chain_state>(
            vmess_chain_state{ioc.get_executor(), echo_port});

        auto recorder = std::make_shared<Preview::Testing::TrafficRecorder>();


        Runtime::TcpListener listen(
            Runtime::TcpListener::Options{
            .Executor = ioc.get_executor(),
            .Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
                Preview::GenerationId{5}),
            .Factory = VmessSessionFactory{
                StateObj, Vmess::ServerConfig{test_uuid()}, {}, recorder}});

        RunCoro(ioc, RunVmessTrafficFlow(
            VmessTrafficFlow{ioc, listen, Echo}));
        EXPECT_EQ(recorder->LastEvent.Kind, Preview::Foundation::TrafficEventKind::Completed);
        EXPECT_FALSE(static_cast<bool>(recorder->LastEvent.Account));
        EXPECT_EQ(recorder->Calls, 1);
        EXPECT_GT(recorder->Up, 0u);
        EXPECT_GT(recorder->Down, 0u);
        EXPECT_FALSE(*Echo.Failure);
    }

} // namespace
