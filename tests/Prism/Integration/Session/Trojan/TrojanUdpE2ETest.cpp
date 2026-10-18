/**
 * @file TrojanUdpE2ETest.cpp
 * @brief Trojan UDP_ASSOCIATE 纵向测试（链 P：数据面经 adapter 接入缝）
 * @details Trojan UDP 命令经 adapter::MakeAcceptTrojan 置 is_dgram 并包装
 *          Dgram 数据面；udp_service 在 Dgram（TCP 承载）与真实 UDP 间中继。
 *          复用 Runtime::Session 的协议无关 Dgram 分支。
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
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Anytls/IngressFactory.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Protocols/Trojan/IngressFactory.hpp>
#include <Prism/Protocols/Vmess/IngressFactory.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Trojan/Dgram.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Runtime = Prism::Runtime;
    namespace Network = Prism::Network;
    namespace Fault = Prism::Fault;
    using Prism::Error;
    using Prism::SharedTransmission;
    using Udp = Net::ip::udp;
    using udp = Udp;
    using Tcp = Net::ip::tcp;

    using UdpEchoDone = Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct TrojanUdpEchoOwner final
    {
        std::shared_ptr<Udp::socket> Socket;
        std::shared_ptr<UdpEchoDone> Done;
        std::shared_ptr<std::exception_ptr> Failure;
        boost::system::error_code OpenError;
    };

    auto RunTrojanUdpEchoServer(const TrojanUdpEchoOwner &Owner)
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

    auto StartTrojanUdpEcho(Net::io_context &Io) -> TrojanUdpEchoOwner
    {
        TrojanUdpEchoOwner Owner;
        Owner.Socket = std::make_shared<Udp::socket>(Io.get_executor());
        Owner.Socket->open(Udp::v4(), Owner.OpenError);
        Owner.Socket->bind(
            Udp::endpoint(Net::ip::make_address("127.0.0.1"), 0),
            Owner.OpenError);
        Owner.Done = std::make_shared<UdpEchoDone>(Io.get_executor(), 1);
        Owner.Failure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(
            Io.get_executor(), RunTrojanUdpEchoServer(Owner),
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

    auto StopTrojanUdpEcho(TrojanUdpEchoOwner &Owner) -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        Owner.Socket->close(ErrorCode);
        (void)co_await Owner.Done->async_receive(Net::use_awaitable);
        if (*Owner.Failure)
        {
            std::rethrow_exception(*Owner.Failure);
        }
    }

    /** @brief 等待 Trojan UDP echo 和 listener 的真实关闭完成。 */
    auto FinishTrojanUdpFlow(
        TrojanUdpEchoOwner &Echo, Runtime::TcpListener &Listener,
        std::exception_ptr &FirstFailure) -> Net::awaitable<void>
    {
        try
        {
            co_await StopTrojanUdpEcho(Echo);
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

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Prism::Testing::RunCoro;

    /// Trojan 纵向测试共享状态
    struct trojan_udp_state
    {
        Net::any_io_executor Executor;
        std::uint16_t EchoPort{0};
        /// 服务端数据面退出次数（TCP 关闭/空闲超时终止的证据）
        std::shared_ptr<std::atomic<int>> RelayExits{std::make_shared<std::atomic<int>>(0)};
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

    auto MakeDatagramServices(const std::shared_ptr<trojan_udp_state>& State,
                              std::chrono::milliseconds IdleTimeout)
        -> Prism::Contract::DatagramServices
    {
        Prism::Contract::DatagramServices Services;
        Services.IdleTimeout = IdleTimeout;
        Services.Traffic = std::make_shared<ExitObserver>(State->RelayExits);
        Services.Resolve = [Port = State->EchoPort](Prism::Network::Target)
            -> Net::awaitable<std::expected<Udp::endpoint, Prism::Fault::Failure>>
        { co_return Udp::endpoint(Net::ip::address_v4::loopback(), Port); };
        return Services;
    }

    struct TrojanUdpSessionFactory final
    {
        std::shared_ptr<trojan_udp_state> State;
        std::chrono::milliseconds IdleTimeout;

        auto operator()(SharedTransmission Inbound, std::size_t, std::string_view) const
            -> std::shared_ptr<Runtime::Session>
        {
            Runtime::SessionOptions Options;
            Prism::Trojan::ServerConfig Configuration;
            Configuration.Password = "Secret";
            Configuration.EnableUdp = true;
            auto Datagrams = MakeDatagramServices(State, IdleTimeout);
            auto UseState = Prism::Testing::MakeProtocolIngressUseState();
            Options.Services->GenerationUseState = UseState;
            Options.Services->AcceptProtocol = Prism::Testing::MakeTrojanIngress(
                std::move(Configuration), Prism::Testing::ProtocolIngressResources{
                    std::move(Datagrams), UseState, Inbound->Executor()}, Prism::Trojan::IngressRoute{});
            return std::make_shared<Runtime::Session>(std::move(Options));
        }
    };

    struct TrojanUdpEchoFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        TrojanUdpEchoOwner &EchoOwner;
        bool &Ok;
        std::string &Echo;
    };

    /** @brief 驱动 Trojan UDP 包往返并等待真实数据面收口。 */
    auto RunTrojanUdpEchoFlow(TrojanUdpEchoFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        Prism::Trojan::SharedDgram Dgram;
        try
        {
            const auto StartResult = co_await Flow.Listener.Start(
                Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
            EXPECT_EQ(StartResult, Fault::Code::Success);
            if (StartResult == Fault::Code::Success)
            {
                const auto ListenPort = Flow.Listener.LocalEndpoint().port();
                Network::Dialer::Dialer Dialer(Flow.Ioc.get_executor());
                auto Raw = co_await Dialer.Connect(
                    {*Prism::Network::ParseHost("127.0.0.1"), ListenPort});
                if (Raw && *Raw)
                {
                    auto ConnectResult = co_await Prism::Trojan::ConnectPacket(
                        std::move(*Raw), Prism::Trojan::ClientConfig{"Secret"},
                        Prism::Trojan::Address{Prism::Trojan::AddressType::Domain,
                                                 "example.com", 443});
                    if (ConnectResult) EXPECT_TRUE(*ConnectResult);
                    if (ConnectResult)
                    {
                        if (*ConnectResult)
                        {
                            Dgram = std::move(*ConnectResult);
                        }
                        else
                        {
                            ADD_FAILURE() << "Trojan factory returned an empty successful owner";
                        }
                    }
                    else
                    {
                        ADD_FAILURE() << "Trojan UDP handshake failed: "
                                      << static_cast<int>(ConnectResult.error().Code);
                    }
                    if (Dgram)
                    {
                        const std::string Payload = "trojan udp payload";
                        const auto SendResult = co_await Dgram->AsyncSendTo(
                            Prism::Trojan::Address{Prism::Trojan::AddressType::Domain,
                                                     "example.com", 443},
                            std::span<const std::uint8_t>(
                                reinterpret_cast<const std::uint8_t *>(Payload.data()),
                                Payload.size()));
                        EXPECT_TRUE(SendResult.Failure.Succeeded());
                        Prism::Trojan::Address Source;
                        std::vector<std::uint8_t> Received;
                        Net::steady_timer Watchdog(Dgram->Executor());
                        Watchdog.expires_after(std::chrono::seconds(2));
                        using Net::experimental::awaitable_operators::operator||;
                        auto Result = co_await (Dgram->AsyncReceiveFrom(Source, Received) ||
                                                Watchdog.async_wait(Net::use_awaitable));
                        bool ReceiveSucceeded = false;
                        if (Result.index() != 1)
                        {
                            ReceiveSucceeded =
                                std::get<0>(std::move(Result)).Failure.Succeeded();
                        }
                        if (ReceiveSucceeded)
                        {
                            Flow.Echo.assign(
                                reinterpret_cast<const char *>(Received.data()), Received.size());
                            Flow.Ok = Flow.Echo == Payload;
                        }
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
        co_await FinishTrojanUdpFlow(Flow.EchoOwner, Flow.Listener, FirstFailure);
    }

    struct TrojanUdpIdleFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        TrojanUdpEchoOwner &Echo;
        bool &Closed;
    };

    /** @brief 驱动 Trojan UDP 空闲超时并验证错误收口。 */
    auto RunTrojanUdpIdleFlow(TrojanUdpIdleFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        Prism::Trojan::SharedDgram Dgram;
        try
        {
            const auto StartResult = co_await Flow.Listener.Start(
                Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
            EXPECT_EQ(StartResult, Fault::Code::Success);
            if (StartResult == Fault::Code::Success)
            {
                const auto ListenPort = Flow.Listener.LocalEndpoint().port();
                Network::Dialer::Dialer Dialer(Flow.Ioc.get_executor());
                auto Raw = co_await Dialer.Connect(
                    {*Prism::Network::ParseHost("127.0.0.1"), ListenPort});
                if (Raw && *Raw)
                {
                    auto ConnectResult = co_await Prism::Trojan::ConnectPacket(
                        std::move(*Raw), Prism::Trojan::ClientConfig{"Secret"},
                        Prism::Trojan::Address{Prism::Trojan::AddressType::Domain,
                                                 "example.com", 443});
                    if (ConnectResult) EXPECT_TRUE(*ConnectResult);
                    if (ConnectResult)
                    {
                        if (*ConnectResult)
                        {
                            Dgram = std::move(*ConnectResult);
                        }
                        else
                        {
                            ADD_FAILURE() << "Trojan factory returned an empty successful owner";
                        }
                    }
                    else
                    {
                        ADD_FAILURE() << "Trojan UDP handshake failed: "
                                      << static_cast<int>(ConnectResult.error().Code);
                    }
                    if (Dgram)
                    {
                        Net::steady_timer Timer(
                            Flow.Ioc.get_executor(), std::chrono::milliseconds(400));
                        co_await Timer.async_wait(Net::use_awaitable);
                        Prism::Trojan::Address Source;
                        std::vector<std::uint8_t> Received;
                        const auto ReceiveError = co_await Dgram->AsyncReceiveFrom(Source, Received);
                        Flow.Closed = ReceiveError.Failure.Failed();
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
        co_await FinishTrojanUdpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    struct TrojanUdpTcpCloseFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        TrojanUdpEchoOwner &Echo;
        const std::shared_ptr<trojan_udp_state> &State;
        bool &Closed;
    };

    /** @brief 驱动 Trojan UDP 控制连接关闭后的真实中继退出。 */
    auto RunTrojanUdpTcpCloseFlow(TrojanUdpTcpCloseFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        Prism::Trojan::SharedDgram Dgram;
        try
        {
            const auto StartResult = co_await Flow.Listener.Start(
                Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
            EXPECT_EQ(StartResult, Fault::Code::Success);
            if (StartResult == Fault::Code::Success)
            {
                const auto ListenPort = Flow.Listener.LocalEndpoint().port();
                Network::Dialer::Dialer Dialer(Flow.Ioc.get_executor());
                auto Raw = co_await Dialer.Connect(
                    {*Prism::Network::ParseHost("127.0.0.1"), ListenPort});
                if (Raw && *Raw)
                {
                    auto ConnectResult = co_await Prism::Trojan::ConnectPacket(
                        std::move(*Raw), Prism::Trojan::ClientConfig{"Secret"},
                        Prism::Trojan::Address{Prism::Trojan::AddressType::Domain,
                                                 "example.com", 443});
                    if (ConnectResult) EXPECT_TRUE(*ConnectResult);
                    if (ConnectResult)
                    {
                        if (*ConnectResult)
                        {
                            Dgram = std::move(*ConnectResult);
                        }
                        else
                        {
                            ADD_FAILURE() << "Trojan factory returned an empty successful owner";
                        }
                    }
                    else
                    {
                        ADD_FAILURE() << "Trojan UDP handshake failed: "
                                      << static_cast<int>(ConnectResult.error().Code);
                    }
                    if (Dgram)
                    {
                        const std::string Probe = "Tcp-Close Probe";
                        const auto SendResult = co_await Dgram->AsyncSendTo(
                            Prism::Trojan::Address{Prism::Trojan::AddressType::Domain,
                                                     "example.com", 443},
                            std::span<const std::uint8_t>(
                                reinterpret_cast<const std::uint8_t *>(Probe.data()),
                                Probe.size()));
                        EXPECT_TRUE(SendResult.Failure.Succeeded());
                        Prism::Trojan::Address Source;
                        std::vector<std::uint8_t> Received;
                        const auto ProbeError = co_await Dgram->AsyncReceiveFrom(Source, Received);
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
                            while (Flow.State->RelayExits->load(std::memory_order_acquire) == 0)
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
        co_await FinishTrojanUdpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    TEST(TcpListener, TrojanUdpAssociateEcho)
    {
        Net::io_context IoContext;
        auto Echo = StartTrojanUdpEcho(IoContext);
        ASSERT_FALSE(Echo.OpenError);
        const auto EchoPort = Echo.Socket->local_endpoint().port();
        auto EchoEndpointPointer = Echo.Failure;

        auto State = std::make_shared<trojan_udp_state>(
            trojan_udp_state{IoContext.get_executor(), EchoPort});

        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = IoContext.get_executor(),
            .Factory = TrojanUdpSessionFactory{State, std::chrono::seconds(5)}});

        bool Ok = false;
        std::string Echo;
        RunCoro(IoContext, RunTrojanUdpEchoFlow(
            TrojanUdpEchoFlow{IoContext, Listener, Echo, Ok, Echo}));
        EXPECT_TRUE(Ok);
        EXPECT_EQ(Echo, "trojan udp payload");
        EXPECT_FALSE(*EchoEndpointPointer);
    }

    TEST(TcpListener, TrojanUdpAssociateIdleTimeout)
    {
        Net::io_context IoContext;
        auto Echo = StartTrojanUdpEcho(IoContext);
        ASSERT_FALSE(Echo.OpenError);
        const auto EchoPort = Echo.Socket->local_endpoint().port();

        auto State = std::make_shared<trojan_udp_state>(
            trojan_udp_state{IoContext.get_executor(), EchoPort});

        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = IoContext.get_executor(),
            .Factory = TrojanUdpSessionFactory{State, std::chrono::milliseconds(150)}});

        bool Closed = false;
        RunCoro(IoContext, RunTrojanUdpIdleFlow(
            TrojanUdpIdleFlow{IoContext, Listener, Echo, Closed}));
        EXPECT_TRUE(Closed);
        EXPECT_FALSE(*Echo.Failure);
    }

    TEST(TcpListener, TrojanUdpAssociateTcpCloseTerminates)
    {
        Net::io_context IoContext;
        auto Echo = StartTrojanUdpEcho(IoContext);
        ASSERT_FALSE(Echo.OpenError);
        const auto EchoPort = Echo.Socket->local_endpoint().port();

        auto State = std::make_shared<trojan_udp_state>(
            trojan_udp_state{IoContext.get_executor(), EchoPort});

        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = IoContext.get_executor(),
            .Factory = TrojanUdpSessionFactory{State, std::chrono::seconds(30)}});

        bool Closed = false;
        RunCoro(IoContext, RunTrojanUdpTcpCloseFlow(
            TrojanUdpTcpCloseFlow{IoContext, Listener, Echo, State, Closed}));
        EXPECT_TRUE(Closed);
        EXPECT_FALSE(*Echo.Failure);
    }

} // namespace
