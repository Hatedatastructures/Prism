/**
 * @file VMessUdpE2ETest.cpp
 * @brief VMess UDP 纵向测试（链 P：数据面经 adapter 接入缝）
 * @details VMess UDP 命令经 adapter::MakeAcceptVmess 置 is_dgram 并包装
 *          Dgram 数据面；udp_service 在 Dgram（AEAD 承载）与真实 UDP 间中继。
 */

#include <gtest/gtest.h>
#include <Prism/Contract/Services/Datagram.hpp>
#include <TestSupport/Prism/ProtocolIngressBindings.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

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
#include <Prism/Protocols/Vmess/Dgram.hpp>
#include <Prism/Protocols/Vmess/Vmess.hpp>
#include <Test/Prism/Runtime/Session/SessionAdmissionSupport.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Runtime = Prism::Runtime;
    namespace Network = Prism::Network;
    namespace Vmess = Prism::Vmess;
    namespace Fault = Prism::Fault;
    using Prism::Error;
    using Prism::SharedTransmission;
    using Udp = Net::ip::udp;
    using udp = Udp;
    using Tcp = Net::ip::tcp;

    using UdpEchoDone = Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct VmessUdpEchoOwner final
    {
        std::shared_ptr<Udp::socket> Socket;
        std::shared_ptr<UdpEchoDone> Done;
        std::shared_ptr<std::exception_ptr> Failure;
        boost::system::error_code OpenError;
    };

    auto RunVmessUdpEchoServer(const VmessUdpEchoOwner &Owner)
        -> Net::awaitable<void>
    {
        std::array<std::byte, 65535> Buffer{};
        while (true)
        {
            Udp::endpoint Source;
            boost::system::error_code ErrorCode;
            const auto Size = co_await Owner.Socket->async_receive_from(
                Net::buffer(Buffer), Source,
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                co_return;
            }
            co_await Owner.Socket->async_send_to(
                Net::buffer(Buffer.data(), Size), Source,
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                co_return;
            }
        }
    }

    auto StartVmessUdpEcho(Net::io_context &Io) -> VmessUdpEchoOwner
    {
        VmessUdpEchoOwner Owner;
        Owner.Socket = std::make_shared<Udp::socket>(Io.get_executor());
        Owner.Socket->open(Udp::v4(), Owner.OpenError);
        Owner.Socket->bind(
            Udp::endpoint(Net::ip::make_address("127.0.0.1"), 0),
            Owner.OpenError);
        Owner.Done = std::make_shared<UdpEchoDone>(Io.get_executor(), 1);
        Owner.Failure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(
            Io.get_executor(), RunVmessUdpEchoServer(Owner),
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

    auto StopVmessUdpEcho(VmessUdpEchoOwner &Owner) -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        Owner.Socket->close(ErrorCode);
        (void)co_await Owner.Done->async_receive(Net::use_awaitable);
        if (*Owner.Failure)
        {
            std::rethrow_exception(*Owner.Failure);
        }
    }

    /** @brief 等待 VMess UDP echo 和 listener 的真实关闭完成。 */
    auto FinishVmessUdpFlow(
        VmessUdpEchoOwner &Echo, Runtime::TcpListener &Listener,
        std::exception_ptr &FirstFailure) -> Net::awaitable<void>
    {
        try
        {
            co_await StopVmessUdpEcho(Echo);
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

    /** @brief 启动 VMess UDP 测试 listener，并统一处理启动结果。 */
    auto StartVmessUdpListener(Runtime::TcpListener &Listener) -> Net::awaitable<bool>
    {
        const auto Result = co_await Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(Result, Fault::Code::Success);
        co_return Result == Fault::Code::Success;
    }

    /** @brief 通过 VMess UDP listener 建立承载连接。 */
    auto DialVmessUdpListener(
        Net::io_context &Ioc, Runtime::TcpListener &Listener)
        -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
    {
        Network::Dialer::Dialer Dialer(Ioc.get_executor());
        co_return co_await Dialer.Connect(
            {*Prism::Network::ParseHost("127.0.0.1"), Listener.LocalEndpoint().port()});
    }

    /** @brief 关闭 VMess UDP datagram，并保存首个关闭异常。 */
    auto CloseVmessDatagram(
        Vmess::SharedDgram &Dgram, std::exception_ptr &FirstFailure) -> void
    {
        try
        {
            if (Dgram)
            {
                Dgram->Close();
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

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Prism::Testing::MakeUuid;
    using Prism::Testing::RunCoro;

    /// 测试 UUID 兼容别名
    inline auto test_uuid() -> std::array<std::uint8_t, 16>
    {
        return MakeUuid();
    }

    /// VMess UDP 纵向测试共享状态
    struct vmess_udp_state
    {
        Net::any_io_executor Executor;
        std::uint16_t echo_port{0};
        std::array<std::uint8_t, 16> Uuid{};
        /// 服务端数据面退出次数（TCP 关闭/空闲超时终止的证据）
        std::shared_ptr<std::atomic<int>> relay_exits{std::make_shared<std::atomic<int>>(0)};
    };

    class ExitObserver final : public Prism::Foundation::TrafficSink
    {
    public:
        explicit ExitObserver(std::shared_ptr<std::atomic<int>> Exits) : Exits_(std::move(Exits)) {}
        auto Report(Prism::Foundation::TrafficEvent) noexcept -> void override { ++*Exits_; }
        auto Retire(Prism::Foundation::TrafficRetirement Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Prism::Fault::Failure>{}; }
    private:
        std::shared_ptr<std::atomic<int>> Exits_;
    };

    auto MakeDatagramServices(const std::shared_ptr<vmess_udp_state>& State,
                              std::chrono::milliseconds IdleTimeout)
        -> Prism::Contract::DatagramServices
    {
        Prism::Contract::DatagramServices Services;
        Services.IdleTimeout = IdleTimeout;
        Services.Traffic = std::make_shared<ExitObserver>(State->relay_exits);
        Services.Resolve = [Port = State->echo_port](Prism::Network::Target)
            -> Net::awaitable<std::expected<Udp::endpoint, Prism::Fault::Failure>>
        { co_return Udp::endpoint(Net::ip::address_v4::loopback(), Port); };
        return Services;
    }

    struct VmessUdpSessionFactory final
    {
        std::shared_ptr<vmess_udp_state> State;
        std::chrono::milliseconds IdleTimeout;

        auto operator()(Runtime::SessionAdmission Admission) const
            -> Runtime::SessionAdmissionResult
        {
            Runtime::SessionOptions Options;
            Options.Services->Bytes = std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{.BlockCount = 8});
            auto Datagrams = MakeDatagramServices(State, IdleTimeout);
            auto UseState = Prism::Testing::MakeProtocolIngressUseState();
            Options.Services->GenerationUseState = UseState;
            Options.Services->AcceptProtocol = Prism::Testing::MakeVmessIngress(
                Vmess::ServerConfig{State->Uuid}, Prism::Testing::VmessIngressResources{
                    {}, {}, std::move(Datagrams), UseState, Admission.Inbound->Executor()},
                Prism::Vmess::IngressRoute{});
            return Runtime::SessionAdmissionResult{
                std::make_shared<Runtime::Session>(std::move(Options))};
        }
    };

    struct VmessUdpEchoFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VmessUdpEchoOwner &Echo;
        std::array<std::uint8_t, 16> Uuid;
        bool &Ok;
    };

    /** @brief 驱动 VMess UDP 包往返并等待真实数据面收口。 */
    auto RunVmessUdpEchoFlow(VmessUdpEchoFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        Vmess::SharedDgram Dgram;
        try
        {
            if (co_await StartVmessUdpListener(Flow.Listener))
            {
                auto Raw = co_await DialVmessUdpListener(Flow.Ioc, Flow.Listener);
                if (Raw && *Raw)
                {
                    auto ConnectResult = co_await Vmess::ConnectPacket(
                        std::move(*Raw), Vmess::ClientConfig{Flow.Uuid},
                        Vmess::Address{Vmess::AddressType::Domain, "example.com", 443});
                    if (ConnectResult) EXPECT_TRUE(*ConnectResult);
                    if (ConnectResult)
                    {
                        if (*ConnectResult)
                        {
                            Dgram = std::move(*ConnectResult);
                        }
                        else
                        {
                            ADD_FAILURE() << "VMess factory returned an empty successful owner";
                        }
                    }
                    else
                    {
                        ADD_FAILURE() << "VMess UDP handshake failed: "
                                      << static_cast<int>(ConnectResult.error().Code);
                    }
                    if (Dgram)
                    {
                        const std::string Payload = "vmess udp payload";
                        const auto SendResult = co_await Dgram->AsyncSendDatagram(
                            std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t *>(Payload.data()),
                            Payload.size()));
                        EXPECT_TRUE(SendResult.Failure.Succeeded());
                        std::vector<std::uint8_t> Received;
                        Net::steady_timer Watchdog(Dgram->Executor());
                        Watchdog.expires_after(std::chrono::seconds(2));
                        using Net::experimental::awaitable_operators::operator||;
                        auto Result = co_await (Dgram->AsyncReceiveDatagram(Received) ||
                                                Watchdog.async_wait(Net::use_awaitable));
                        bool ReceiveSucceeded = false;
                        if (Result.index() != 1)
                        {
                            ReceiveSucceeded =
                                std::get<0>(std::move(Result)).Failure.Succeeded();
                        }
                        if (ReceiveSucceeded)
                        {
                            const std::string Echo(
                                reinterpret_cast<const char *>(Received.data()), Received.size());
                            Flow.Ok = Echo == Payload;
                        }
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        CloseVmessDatagram(Dgram, FirstFailure);
        co_await FinishVmessUdpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    struct VmessUdpIdleFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VmessUdpEchoOwner &Echo;
        std::array<std::uint8_t, 16> Uuid;
        bool &Closed;
    };

    /** @brief 驱动 VMess UDP 空闲超时并验证错误收口。 */
    auto RunVmessUdpIdleFlow(VmessUdpIdleFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        Vmess::SharedDgram Dgram;
        try
        {
            if (co_await StartVmessUdpListener(Flow.Listener))
            {
                auto Raw = co_await DialVmessUdpListener(Flow.Ioc, Flow.Listener);
                if (Raw && *Raw)
                {
                    auto ConnectResult = co_await Vmess::ConnectPacket(
                        std::move(*Raw), Vmess::ClientConfig{Flow.Uuid},
                        Vmess::Address{Vmess::AddressType::Domain, "example.com", 443});
                    if (ConnectResult) EXPECT_TRUE(*ConnectResult);
                    if (ConnectResult)
                    {
                        if (*ConnectResult)
                        {
                            Dgram = std::move(*ConnectResult);
                        }
                        else
                        {
                            ADD_FAILURE() << "VMess factory returned an empty successful owner";
                        }
                    }
                    else
                    {
                        ADD_FAILURE() << "VMess UDP handshake failed: "
                                      << static_cast<int>(ConnectResult.error().Code);
                    }
                    if (Dgram)
                    {
                        Net::steady_timer Timer(
                            Flow.Ioc.get_executor(), std::chrono::milliseconds(400));
                        co_await Timer.async_wait(Net::use_awaitable);
                        std::vector<std::uint8_t> Received;
                        const auto ReceiveError = co_await Dgram->AsyncReceiveDatagram(Received);
                        Flow.Closed = ReceiveError.Failure.Failed();
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        CloseVmessDatagram(Dgram, FirstFailure);
        co_await FinishVmessUdpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    struct VmessUdpTcpCloseFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VmessUdpEchoOwner &Echo;
        const std::shared_ptr<vmess_udp_state> &State;
        bool &Closed;
    };

    /** @brief 驱动 VMess UDP 控制连接关闭后的真实中继退出。 */
    auto RunVmessUdpTcpCloseFlow(VmessUdpTcpCloseFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        Vmess::SharedDgram Dgram;
        try
        {
            if (co_await StartVmessUdpListener(Flow.Listener))
            {
                auto Raw = co_await DialVmessUdpListener(Flow.Ioc, Flow.Listener);
                if (Raw && *Raw)
                {
                    auto ConnectResult = co_await Vmess::ConnectPacket(
                        std::move(*Raw), Vmess::ClientConfig{Flow.State->Uuid},
                        Vmess::Address{Vmess::AddressType::Domain, "example.com", 443});
                    if (ConnectResult) EXPECT_TRUE(*ConnectResult);
                    if (ConnectResult)
                    {
                        if (*ConnectResult)
                        {
                            Dgram = std::move(*ConnectResult);
                        }
                        else
                        {
                            ADD_FAILURE() << "VMess factory returned an empty successful owner";
                        }
                    }
                    else
                    {
                        ADD_FAILURE() << "VMess UDP handshake failed: "
                                      << static_cast<int>(ConnectResult.error().Code);
                    }
                    if (Dgram)
                    {
                        const std::string Probe = "Tcp-Close Probe";
                        const auto SendResult = co_await Dgram->AsyncSendDatagram(
                            std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t *>(Probe.data()), Probe.size()));
                        EXPECT_TRUE(SendResult.Failure.Succeeded());
                        std::vector<std::uint8_t> Received;
                        const auto ProbeError = co_await Dgram->AsyncReceiveDatagram(Received);
                        if (ProbeError.Failure.Failed())
                        {
                            ADD_FAILURE() << "Probe roundtrip Failed: "
                                          << static_cast<int>(ProbeError.Failure.Code);
                        }
                        else
                        {
                            Dgram->Close();
                            Net::steady_timer Watchdog(Flow.Ioc.get_executor());
                            const auto Deadline = std::chrono::steady_clock::now() +
                                                  std::chrono::seconds(2);
                            while (Flow.State->relay_exits->load(std::memory_order_acquire) == 0)
                            {
                                if (std::chrono::steady_clock::now() > Deadline)
                                {
                                    throw std::runtime_error(
                                        "udp Data plane not terminated after Tcp Close");
                                }
                                Watchdog.expires_after(std::chrono::milliseconds(5));
                                co_await Watchdog.async_wait(Net::use_awaitable);
                            }
                            Flow.Closed = true;
                        }
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        CloseVmessDatagram(Dgram, FirstFailure);
        co_await FinishVmessUdpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    TEST(TcpListener, VmessUdpConnectEcho)
    {
        Net::io_context ioc;
        auto Echo = StartVmessUdpEcho(ioc);
        ASSERT_FALSE(Echo.OpenError);
        const auto echo_port = Echo.Socket->local_endpoint().port();
        auto echo_ep_ptr = Echo.Failure;
        const auto Uuid = test_uuid();

        auto State = std::make_shared<vmess_udp_state>(
            vmess_udp_state{ioc.get_executor(), echo_port, Uuid});

        Runtime::TcpListener listener(
            Runtime::TcpListener::Options{
            .Executor = ioc.get_executor(),
            .Factory = VmessUdpSessionFactory{State, std::chrono::seconds(5)},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{11})});

        bool Ok = false;
        RunCoro(ioc, RunVmessUdpEchoFlow(
            VmessUdpEchoFlow{ioc, listener, Echo, Uuid, Ok}));
        EXPECT_TRUE(Ok);
        EXPECT_FALSE(*echo_ep_ptr);
    }

    TEST(TcpListener, VmessUdpConnectIdleTimeout)
    {
        Net::io_context ioc;
        auto Echo = StartVmessUdpEcho(ioc);
        ASSERT_FALSE(Echo.OpenError);
        const auto echo_port = Echo.Socket->local_endpoint().port();
        const auto Uuid = test_uuid();

        auto State = std::make_shared<vmess_udp_state>(
            vmess_udp_state{ioc.get_executor(), echo_port, Uuid});

        Runtime::TcpListener listener(
            Runtime::TcpListener::Options{
            .Executor = ioc.get_executor(),
            .Factory = VmessUdpSessionFactory{State, std::chrono::milliseconds(150)},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{12})});

        bool closed = false;
        RunCoro(ioc, RunVmessUdpIdleFlow(
            VmessUdpIdleFlow{ioc, listener, Echo, Uuid, closed}));
        EXPECT_TRUE(closed);
        EXPECT_FALSE(*Echo.Failure);
    }

    TEST(TcpListener, VmessUdpConnectTcpCloseTerminates)
    {
        Net::io_context ioc;
        auto Echo = StartVmessUdpEcho(ioc);
        ASSERT_FALSE(Echo.OpenError);
        const auto echo_port = Echo.Socket->local_endpoint().port();
        const auto Uuid = test_uuid();

        auto State = std::make_shared<vmess_udp_state>(
            vmess_udp_state{ioc.get_executor(), echo_port, Uuid});

        Runtime::TcpListener listener(
            Runtime::TcpListener::Options{
            .Executor = ioc.get_executor(),
            .Factory = VmessUdpSessionFactory{State, std::chrono::seconds(30)},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{13})});

        bool closed = false;
        RunCoro(ioc, RunVmessUdpTcpCloseFlow(
            VmessUdpTcpCloseFlow{ioc, listener, Echo, State, closed}));
        EXPECT_TRUE(closed);
        EXPECT_FALSE(*Echo.Failure);
    }

} // namespace
