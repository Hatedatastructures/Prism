/**
 * @file DatagramProtocolServiceTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "../../../Boundary/DatagramServiceTestSupport.hpp"
#include <Preview/Runtime/SessionAdmissionTestSupport.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <Preview/Transport/Reliable.hpp>
#include <Preview/Protocols/Socks5/Socks5.hpp>
#include <Preview/Protocols/Shadowsocks2022/Ss2022Gateway.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <TestSupport/Preview/ProtocolIngressBindings.hpp>
#include <type_traits>

namespace
{
    /** @brief 编译期锁定已退役裸 carrier selector 不可进入当前 typed datagram owner。 */
    static_assert(!std::is_invocable_v<
        decltype(&Socks5::MakeDatagramSession),
        SharedTransmission, Preview::Protocols::DatagramBinding>);
    static_assert(!std::is_invocable_v<
        decltype(&Vless::MakeDatagramSession),
        SharedTransmission, Preview::Protocols::DatagramBinding>);
    static_assert(!std::is_constructible_v<
        Vmess::DatagramSession, SharedTransmission,
        Vmess::DatagramSession::Relay::Options>);
    static_assert(!std::is_invocable_v<
        decltype(&Preview::Shadowsocks2022::Ss2022Gateway::Consume),
        Preview::Shadowsocks2022::Ss2022Gateway *, SharedTransmission>);

    /** @brief 自然排空当前数据报用例的异步任务并传回首个操作异常。 */
    template <typename Operation>
    auto RunDatagramCase(Net::io_context &Io, Operation Body) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Body),
            [&Failure](std::exception_ptr ErrorValue) { Failure = std::move(ErrorValue); });
        Io.run();
        if (Failure) std::rethrow_exception(Failure);
    }

    /** @brief 正式 SOCKS5 会话观察到的 resolver 与 owner 完成事件。 */
    enum class Socks5ServerEventKind
    {
        ResolveObserved,
        Finished
    };

    /** @brief 单个 SOCKS5 UDP_ASSOCIATE 服务的握手、resolver 与结束事实。 */
    struct Socks5ServerCompletion final
    {
        explicit Socks5ServerCompletion(Net::any_io_executor Executor) : Events(Executor, 2) {}
        Net::experimental::channel<void(boost::system::error_code, Socks5ServerEventKind)> Events;
        Error Handshake{Error::IoError};
        Error ClientHandshake{Error::IoError};
        Socks5::Command Command{Socks5::Command::Connect};
        std::expected<void, Fault::Failure> Result{
            std::unexpected(Fault::Failure{Fault::Code::GenericError})};
        std::size_t ResolveCalls{0};
        bool Sent{false};
        bool ResolveObserved{false};
        bool Finished{false};
        std::exception_ptr Failure;
        Preview::SharedTransmission Carrier;
    };

    /** @brief 在测试 executor 上异步建立回环 TCP 控制通道。 */
    auto MakeTcpPair(Net::io_context &Io)
        -> Net::awaitable<std::pair<Tcp::socket, Tcp::socket>>
    {
        Tcp::acceptor Acceptor(Io, Tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        Tcp::socket Client(Io.get_executor());
        co_await Client.async_connect(Acceptor.local_endpoint(), Net::use_awaitable);
        auto Server = co_await Acceptor.async_accept(Net::use_awaitable);
        co_return std::pair{std::move(Client), std::move(Server)};
    }

    /** @brief 接管 TCP peer 上的完整 SOCKS5 UDP_ASSOCIATE 并运行唯一数据报 owner。 */
    auto RunSocks5Server(std::shared_ptr<Socks5ServerCompletion> Completion,
                         Preview::Contract::DatagramServices Services)
        -> Net::awaitable<void>
    {
        auto Config = Socks5::ServerConfig{};
        Config.DeferConnectReply = true;
        auto [Handshake, Request, Owner] = co_await Socks5::Accept(
            Completion->Carrier, Config);
        Completion->Handshake = Handshake;
        Completion->Command = Request.Cmd;
        if (Handshake != Error::None || !Owner)
        {
            co_return;
        }
        auto Service = Socks5::MakeDatagramSession(
            Owner, {std::move(Services), {}});
        Completion->Result = co_await Service->Run();
    }

    /** @brief 启动服务器 owner，并把异常或真实完成发布给测试协程。 */
    auto StartSocks5Server(std::shared_ptr<Socks5ServerCompletion> Completion,
                           Preview::Contract::DatagramServices Services) -> void
    {
        Net::co_spawn(
            Completion->Carrier->Executor(),
            RunSocks5Server(Completion, std::move(Services)),
            [Completion](std::exception_ptr Failure)
            {
                Completion->Failure = std::move(Failure);
                (void)Completion->Events.try_send(
                    boost::system::error_code{}, Socks5ServerEventKind::Finished);
            });
    }

    /** @brief 逐一消费 resolver 与 server finish 事实，直至正式 owner 退栈。 */
    auto WaitForSocks5Server(std::shared_ptr<Socks5ServerCompletion> Completion)
        -> Net::awaitable<void>
    {
        while (!Completion->Finished)
        {
            const auto Event = co_await Completion->Events.async_receive(Net::use_awaitable);
            if (Event == Socks5ServerEventKind::ResolveObserved)
            {
                Completion->ResolveObserved = true;
                continue;
            }
            Completion->Finished = true;
        }
        if (Completion->Failure)
        {
            std::rethrow_exception(Completion->Failure);
        }
    }

    /** @brief 完成正式 SOCKS5 UDP_ASSOCIATE 后关闭控制通道并等待 owner 退栈。 */
    auto RunSocks5ControlClose(Net::io_context &Io,
                               std::shared_ptr<Socks5ServerCompletion> Completion)
        -> Net::awaitable<void>
    {
        auto [ClientSocket, ServerSocket] = co_await MakeTcpPair(Io);
        Completion->Carrier = std::make_shared<Preview::Transport::Reliable>(
            std::move(ServerSocket));
        auto Client = std::make_shared<Preview::Transport::Reliable>(
            std::move(ClientSocket));
        StartSocks5Server(Completion, {});

        const auto ClientConfig = Socks5::ClientConfig{};
        const Socks5::Address Target{Socks5::AddressType::Ipv4, "0.0.0.0", 0};
        auto [Handshake, Owner] = co_await Socks5::Connect(
            Socks5::ConnectParameters{
                std::move(Client), ClientConfig, Target, Socks5::Command::UdpAssociate});
        Completion->ClientHandshake = Handshake;
        if (Handshake == Error::None && Owner)
        {
            (void)Owner->Close();
        }
        else
        {
            (void)Completion->Carrier->Close();
        }
        co_await WaitForSocks5Server(Completion);
    }

    /** @brief 发送原 UDP_ASSOCIATE 帧并等 resolver 或 20 ms idle owner 完成。 */
    auto RunSocks5ResolveFailure(Net::io_context &Io,
                                 std::shared_ptr<Socks5ServerCompletion> Completion)
        -> Net::awaitable<void>
    {
        auto [ClientSocket, ServerSocket] = co_await MakeTcpPair(Io);
        Completion->Carrier = std::make_shared<Preview::Transport::Reliable>(
            std::move(ServerSocket));
        auto ClientCarrier = std::make_shared<Preview::Transport::Reliable>(
            std::move(ClientSocket));
        Preview::Contract::DatagramServices Services;
        Services.IdleTimeout = std::chrono::milliseconds(20);
        Services.Resolve = [Completion](Preview::Network::Target)
            -> Net::awaitable<std::expected<Udp::endpoint, Preview::Fault::Failure>>
        {
            ++Completion->ResolveCalls;
            (void)Completion->Events.try_send(
                boost::system::error_code{}, Socks5ServerEventKind::ResolveObserved);
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::UnsupportedAddress});
        };
        StartSocks5Server(Completion, std::move(Services));

        const auto ClientConfig = Socks5::ClientConfig{};
        const Socks5::Address ControlTarget{Socks5::AddressType::Ipv4, "0.0.0.0", 0};
        auto [Handshake, Owner] = co_await Socks5::Connect(
            Socks5::ConnectParameters{
                std::move(ClientCarrier), ClientConfig, ControlTarget,
                Socks5::Command::UdpAssociate});
        Completion->ClientHandshake = Handshake;
        if (Handshake == Error::None && Owner)
        {
            const auto Bind = Owner->BindEndpoint();
            Net::ip::udp::socket Client(Io.get_executor());
            boost::system::error_code ErrorCode;
            Client.open(Net::ip::udp::v4(), ErrorCode);
            if (!ErrorCode)
            {
                Client.bind(Net::ip::udp::endpoint(
                    Net::ip::make_address("127.0.0.1"), 0), ErrorCode);
            }
            if (!ErrorCode)
            {
                const auto Frame = Socks5::BuildUdpDatagram(
                    Socks5::Address{Socks5::AddressType::Domain,
                                    "resolve-failure.test", 53},
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>("x"), 1));
                co_await Client.async_send_to(
                    Net::buffer(Frame),
                    Udp::endpoint(Net::ip::make_address(Bind.Host), Bind.Port),
                    Net::redirect_error(Net::use_awaitable, ErrorCode));
                Completion->Sent = !ErrorCode;
            }
            boost::system::error_code CloseError;
            Client.close(CloseError);
        }
        else
        {
            (void)Completion->Carrier->Close();
        }

        while (!Completion->Finished)
        {
            const auto Event = co_await Completion->Events.async_receive(Net::use_awaitable);
            if (Event == Socks5ServerEventKind::ResolveObserved)
            {
                Completion->ResolveObserved = true;
            }
            else
            {
                Completion->Finished = true;
            }
        }
        if (Owner)
        {
            (void)Owner->Close();
        }
        if (Completion->Failure)
        {
            std::rethrow_exception(Completion->Failure);
        }
    }

    /**
     * @brief 保存 Trojan UDP resolver 的请求观察值和真实 echo endpoint。
     */
    struct TrojanResolveState final
    {
        std::size_t &ResolveCalls;
        std::string &ResolvedHost;
        std::uint16_t &ResolvedPort;
        std::uint16_t EchoPort;

        auto operator()(Preview::Network::Target Request) const
            -> Net::awaitable<std::expected<Udp::endpoint, Preview::Fault::Failure>>
        {
            ++ResolveCalls;
            const auto Text = Preview::Network::ToText(Request.Host);
            ResolvedHost = Text.View();
            ResolvedPort = Request.Port;
            co_return Udp::endpoint(Net::ip::address_v4::loopback(), EchoPort);
        }
    };

    /** @brief 单包 UDP echo 协程的真实完成事实。 */
    struct UdpEchoCompletion final
    {
        explicit UdpEchoCompletion(Net::any_io_executor Executor) : Done(Executor, 1) {}
        Net::experimental::channel<void(boost::system::error_code)> Done;
        std::exception_ptr Failure;
    };

    /** @brief 为 VMess listener 创建携带当前 UUID 的 datagram session。 */
    struct VmessDatagramSessionFactory final
    {
        decltype(MakeUuid()) Uuid;
        /** @brief listener 级共享测试池，随接受的 SessionServices 保活。 */
        std::shared_ptr<Preview::Memory::BytePool> Bytes;

        auto operator()(Preview::Runtime::SessionAdmission) const
            -> std::shared_ptr<Runtime::Session>
        {
            Runtime::SessionOptions Options;
            Options.Services->Bytes = Bytes;
            Preview::Contract::DatagramServices UdpOptions;
            UdpOptions.IdleTimeout = std::chrono::seconds(3);
            auto UseState = Preview::Testing::MakeProtocolIngressUseState();
            Options.Services->GenerationUseState = UseState;
            Options.Services->AcceptProtocol = Preview::Testing::MakeVmessIngress(
                Vmess::ServerConfig{Uuid}, Preview::Testing::VmessIngressResources{
                    {}, {}, std::move(UdpOptions), UseState, Inbound->Executor()},
                Preview::Vmess::IngressRoute{});
            return std::make_shared<Runtime::Session>(std::move(Options));
        }
    };

    /** @brief 驱动 VMess UDP echo 并完整等待 echo 协程退栈。 */
    struct VmessUdpEchoRequest final
    {
        Net::io_context &Io;
        Runtime::TcpListener &Listener;
        decltype(MakeUuid()) Uuid;
        std::uint16_t EchoPort;
        bool &Echoed;
        std::shared_ptr<Udp::socket> EchoSocket;
        std::shared_ptr<UdpEchoCompletion> EchoCompletion;
    };

    auto RunVmessUdpEchoScenario(VmessUdpEchoRequest Request) -> Net::awaitable<void>
    {
        const auto StartResult = co_await Request.Listener.Start(
            Tcp::endpoint(Tcp::v4(), 0));
        if (StartResult == Fault::Code::Success)
        {
            Network::Dialer::Dialer Dialer(Request.Io.get_executor());
            const auto Host = Preview::Network::ParseHost("127.0.0.1");
            if (Host)
            {
                auto Dialed = co_await Dialer.Connect(
                    {*Host, Request.Listener.LocalEndpoint().port()});
                if (Dialed)
                {
                    auto ConnectResult = co_await Vmess::ConnectPacket(
                        std::move(*Dialed), Vmess::ClientConfig{Request.Uuid},
                        Vmess::Address{Vmess::AddressType::Ipv4,
                                       "127.0.0.1", Request.EchoPort});
                    if (ConnectResult && *ConnectResult)
                    {
                        auto Datagram = std::move(*ConnectResult);
                        const std::string Payload = "vmess packet";
                        const auto SendError = co_await Datagram->AsyncSendTo(
                            std::span<const std::uint8_t>(
                                reinterpret_cast<const std::uint8_t *>(Payload.data()),
                                Payload.size()));
                        if (SendError.has_value())
                        {
                            std::vector<std::uint8_t> Received;
                            Net::steady_timer Watchdog(Datagram->Executor());
                            Watchdog.expires_after(std::chrono::seconds(2));
                            using Net::experimental::awaitable_operators::operator||;
                            auto Race = co_await (
                                Datagram->AsyncReceiveFrom(Received) ||
                                Watchdog.async_wait(Net::use_awaitable));
                            if (Race.index() == 0 && std::get<0>(Race).has_value())
                            {
                                Request.Echoed =
                                    std::string(Received.begin(), Received.end()) == Payload;
                            }
                        }
                        Datagram->Close();
                    }
                }
            }
        }
        Request.Listener.Stop();
        if (Request.EchoSocket->is_open())
        {
            boost::system::error_code Ignore;
            Request.EchoSocket->cancel(Ignore);
            Request.EchoSocket->close(Ignore);
        }
        co_await Request.EchoCompletion->Done.async_receive(Net::use_awaitable);
        if (Request.EchoCompletion->Failure)
        {
            std::rethrow_exception(Request.EchoCompletion->Failure);
        }
    }
}

TEST(ProtocolDatagramSession, ClosesSocks5OwnerWhenControlCarrierEnds)
    {
        Net::io_context Io;
        auto Completion = std::make_shared<Socks5ServerCompletion>(Io.get_executor());

        RunDatagramCase(
            Io,
            [&]() -> Net::awaitable<void>
            {
                co_await RunSocks5ControlClose(Io, Completion);
                co_return;
            });

        EXPECT_EQ(Completion->ClientHandshake, Error::None);
        EXPECT_EQ(Completion->Handshake, Error::None);
        EXPECT_EQ(Completion->Command, Socks5::Command::UdpAssociate);
        EXPECT_TRUE(Completion->Result.has_value());
        ASSERT_TRUE(Completion->Carrier);
        EXPECT_FALSE(Completion->Carrier->IsOpen());
    }

TEST(ProtocolDatagramSession, ClosesVlessOwnerOnIdle)
    {
        Net::io_context Io;
        auto Carrier = std::make_shared<PreviewMockTransport>(Io.get_executor());
        Carrier->TransportKind = Preview::Transmission::Type::Udp;
        auto Owner = std::make_shared<Vless::Conn<>>(Carrier, Preview::Testing::MakeUuid());
        Preview::Protocols::DatagramObservation Observation;
        Preview::Contract::DatagramServices Options;
        Options.IdleTimeout = std::chrono::milliseconds(20);
        auto Service = Vless::MakeDatagramSession(Owner,
            Vless::Address{Vless::AddressType::Ipv4, "127.0.0.1", 53},
            {std::move(Options), std::move(Observation)});
        std::expected<void, Fault::Failure> Result{
            std::unexpected(Fault::Failure{Fault::Code::GenericError})};

        RunDatagramCase(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Service->Run();
                co_return;
            });

        EXPECT_TRUE(Result.has_value());
        EXPECT_TRUE(Carrier->IsClosed());
    }

TEST(ProtocolDatagramSession, ClosesSocks5OwnerAfterResolveFailure)
    {
        Net::io_context Io;
        auto Completion = std::make_shared<Socks5ServerCompletion>(Io.get_executor());
        RunDatagramCase(
            Io,
            [&]() -> Net::awaitable<void>
            {
                co_await RunSocks5ResolveFailure(Io, Completion);
                co_return;
            });

        EXPECT_EQ(Completion->ClientHandshake, Error::None);
        EXPECT_EQ(Completion->Handshake, Error::None);
        EXPECT_EQ(Completion->Command, Socks5::Command::UdpAssociate);
        ASSERT_FALSE(Completion->Result);
        EXPECT_EQ(Completion->Result.error().Code, Fault::Code::UnsupportedAddress);
        EXPECT_EQ(Completion->ResolveCalls, 1u);
        EXPECT_TRUE(Completion->ResolveObserved);
        EXPECT_TRUE(Completion->Sent);
        ASSERT_TRUE(Completion->Carrier);
        EXPECT_FALSE(Completion->Carrier->IsOpen());
    }

TEST(ProtocolDatagramSession, ClosesVlessOwnerAfterResolveFailure)
    {
        Net::io_context Io;
        auto Carrier = std::make_shared<PreviewMockTransport>(Io.get_executor());
        Carrier->TransportKind = Preview::Transmission::Type::Udp;
        std::vector<std::uint8_t> Packet;
        const auto Payload = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>("x"), 1);
        ASSERT_TRUE(Vless::BuildUdpPkt(Payload, Packet));
        Carrier->ToRead = Packet;
        auto Owner = std::make_shared<Vless::Conn<>>(Carrier, Preview::Testing::MakeUuid());
        Preview::Protocols::DatagramObservation Observation;
        auto ResolveCalls = std::make_shared<std::size_t>(0);
        auto Traffic = std::make_shared<TrafficRecorder>();
        Preview::Contract::DatagramServices Options;
        Options.IdleTimeout = std::chrono::milliseconds(20);
        Options.Traffic = Traffic;
        Options.Resolve = [ResolveCalls](Preview::Network::Target Target)
            -> Net::awaitable<std::expected<Net::ip::udp::endpoint,
                Preview::Fault::Failure>>
        {
            ++*ResolveCalls;
            EXPECT_EQ(Target.Host, *Preview::Network::ParseHost("resolve-failure.test"));
            EXPECT_EQ(Target.Port, 53U);
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::UnsupportedAddress});
        };
        auto Service = Vless::MakeDatagramSession(Owner,
            Vless::Address{Vless::AddressType::Domain, "resolve-failure.test", 53},
            {std::move(Options), std::move(Observation)});
        std::expected<void, Fault::Failure> Result{
            std::unexpected(Fault::Failure{Fault::Code::GenericError})};

        RunDatagramCase(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Service->Run();
                co_return;
            });

        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error().Code, Fault::Code::UnsupportedAddress);
        EXPECT_EQ(*ResolveCalls, 1u);
        EXPECT_TRUE(Carrier->IsClosed());
        EXPECT_TRUE(Carrier->Written.empty());
        EXPECT_EQ(Traffic->Calls, 1);
        EXPECT_EQ(Traffic->Up, 0U);
        EXPECT_EQ(Traffic->Down, 0U);
        Service->Close();
        Service->Close();
        EXPECT_EQ(Traffic->Calls, 1);
    }

TEST(ProtocolDatagramSession, TrojanRelaysOneDatagramAndReportsPayloadTraffic)
    {
        Net::io_context Io;
        auto Echo = std::make_shared<Udp::socket>(
            Io.get_executor(), Udp::endpoint(Udp::v4(), 0));
        const auto EchoPort = Echo->local_endpoint().port();
        Net::co_spawn(Io, UdpEchoOnce(Echo), Net::detached);

        auto Carrier = std::make_shared<PreviewMockTransport>(Io.get_executor());
        const std::string Payload = "trojan packet";
        const std::string TargetHost = "udp-echo.test";
        Carrier->ToRead = {
            static_cast<std::uint8_t>(Trojan::AddressType::Domain),
            static_cast<std::uint8_t>(TargetHost.size())};
        Carrier->ToRead.insert(Carrier->ToRead.end(), TargetHost.begin(), TargetHost.end());
        Carrier->ToRead.insert(
            Carrier->ToRead.end(),
            {static_cast<std::uint8_t>(EchoPort >> 8),
             static_cast<std::uint8_t>(EchoPort),
             0, static_cast<std::uint8_t>(Payload.size()), '\r', '\n'});
        Carrier->ToRead.insert(Carrier->ToRead.end(), Payload.begin(), Payload.end());
        auto Owner = std::make_shared<Trojan::Dgram<>>(Carrier);
        Preview::Protocols::DatagramObservation Observation;
        auto Traffic = std::make_shared<TrafficRecorder>();
        Observation.Identity = "trojan-udp-user";
        Observation.AccountId = Preview::AccountId{7};
        Preview::Contract::DatagramServices Options;
        Options.Traffic = Traffic;
        Options.IdleTimeout = std::chrono::milliseconds(20);
        std::size_t ResolveCalls = 0;
        std::string ResolvedHost;
        std::uint16_t ResolvedPort = 0;
        Options.Resolve = TrojanResolveState{
            ResolveCalls, ResolvedHost, ResolvedPort, EchoPort};
        auto Service = std::make_shared<Trojan::DatagramSession>(Trojan::DatagramWire{Owner},
            Trojan::DatagramSession::Relay::Options{std::move(Options), std::move(Observation)});
        std::expected<void, Fault::Failure> Result{
            std::unexpected(Fault::Failure{Fault::Code::GenericError})};

        RunDatagramCase(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Service->Run();
                co_return;
            });

        EXPECT_TRUE(Result.has_value());
        EXPECT_TRUE(Carrier->IsClosed());
        EXPECT_EQ(ResolveCalls, 1U);
        EXPECT_EQ(ResolvedHost, TargetHost);
        EXPECT_EQ(ResolvedPort, EchoPort);
        ASSERT_EQ(Carrier->Written.size(), Payload.size() + 11U);
        EXPECT_EQ(Carrier->Written[0], static_cast<std::uint8_t>(Trojan::AddressType::Ipv4));
        EXPECT_EQ(Carrier->Written[1], 127);
        EXPECT_EQ(Carrier->Written[2], 0);
        EXPECT_EQ(Carrier->Written[3], 0);
        EXPECT_EQ(Carrier->Written[4], 1);
        EXPECT_EQ(Carrier->Written[5], static_cast<std::uint8_t>(EchoPort >> 8));
        EXPECT_EQ(Carrier->Written[6], static_cast<std::uint8_t>(EchoPort));
        EXPECT_EQ(std::string(Carrier->Written.begin() + 11, Carrier->Written.end()), Payload);
        EXPECT_EQ(Traffic->Calls, 1);
        EXPECT_EQ(Traffic->LastEvent.Account, Preview::AccountId{7});
        EXPECT_EQ(Traffic->Up, Payload.size());
        EXPECT_EQ(Traffic->Down, Payload.size());
    }

TEST(ProtocolDatagramSession, RejectsZeroPortBeforeTrojanResolverAndClosesLifetime)
    {
        Net::io_context Io;
        auto Carrier = std::make_shared<PreviewMockTransport>(Io.get_executor());
        const std::string TargetHost = "invalid-port.test";
        const std::string Payload = "invalid-port";
        Carrier->ToRead = {
            static_cast<std::uint8_t>(Trojan::AddressType::Domain),
            static_cast<std::uint8_t>(TargetHost.size())};
        Carrier->ToRead.insert(Carrier->ToRead.end(), TargetHost.begin(), TargetHost.end());
        Carrier->ToRead.insert(Carrier->ToRead.end(),
                               {0, 0, 0, static_cast<std::uint8_t>(Payload.size()), '\r', '\n'});
        Carrier->ToRead.insert(Carrier->ToRead.end(), Payload.begin(), Payload.end());
        auto Owner = std::make_shared<Trojan::Dgram<>>(Carrier);
        Preview::Protocols::DatagramObservation Observation;
        auto Traffic = std::make_shared<TrafficRecorder>();
        Observation.Identity = "trojan-invalid-port";
        Observation.AccountId = Preview::AccountId{9};
        std::size_t ResolveCalls = 0;
        Preview::Contract::DatagramServices Options;
        Options.Traffic = Traffic;
        Options.IdleTimeout = std::chrono::milliseconds(20);
        Options.Resolve = [&ResolveCalls](Preview::Network::Target)
            -> Net::awaitable<std::expected<Udp::endpoint, Preview::Fault::Failure>>
        {
            ++ResolveCalls;
            co_return Udp::endpoint(Net::ip::address_v4::loopback(), 53);
        };
        auto Service = std::make_shared<Trojan::DatagramSession>(Trojan::DatagramWire{Owner},
            Trojan::DatagramSession::Relay::Options{std::move(Options), std::move(Observation)});
        std::expected<void, Fault::Failure> Result{
            std::unexpected(Fault::Failure{Fault::Code::GenericError})};

        RunDatagramCase(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Service->Run();
                co_return;
            });

        EXPECT_TRUE(Result.has_value());
        EXPECT_EQ(ResolveCalls, 0U);
        EXPECT_TRUE(Carrier->IsClosed());
        EXPECT_EQ(Traffic->Calls, 1U);
        EXPECT_EQ(Traffic->LastEvent.Account, Preview::AccountId{9});
        EXPECT_EQ(Traffic->Up, 0U);
        EXPECT_EQ(Traffic->Down, 0U);
    }

TEST(ProtocolDatagramSession, RejectsVmessTargetPortZero)
    {
        Net::io_context Io;
        auto Carrier = std::make_shared<PreviewMockTransport>(Io.get_executor());
        auto Datagram = std::make_shared<Vmess::Dgram<>>(Carrier);
        auto Traffic = std::make_shared<TrafficRecorder>();
        Preview::Contract::DatagramServices Services;
        Services.Traffic = Traffic;
        auto Service = std::make_shared<Vmess::DatagramSession>(Vmess::DatagramWire{Datagram, {*Preview::Network::ParseHost("127.0.0.1"), 0}},
            Vmess::DatagramSession::Relay::Options{std::move(Services), {}});
        std::expected<void, Fault::Failure> Result{
            std::unexpected(Fault::Failure{Fault::Code::GenericError})};

        RunDatagramCase(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Service->Run();
                co_return;
            });

        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error().Code, Fault::Code::InvalidArgument);
        EXPECT_TRUE(Carrier->IsClosed());
        EXPECT_EQ(Traffic->Calls, 1U);
        EXPECT_EQ(Traffic->Up, 0U);
        EXPECT_EQ(Traffic->Down, 0U);
    }

TEST(ProtocolDatagramSession, VmessUsesAcceptedTargetForUdpDatagrams)
    {
        Net::io_context Io;
        auto EchoSocket = std::make_shared<Udp::socket>(
            Io.get_executor(), Udp::endpoint(Udp::v4(), 0));
        const auto EchoPort = EchoSocket->local_endpoint().port();
        auto EchoCompletion = std::make_shared<UdpEchoCompletion>(Io.get_executor());
        Net::co_spawn(
            Io.get_executor(), UdpEchoOnce(EchoSocket),
            [EchoCompletion](std::exception_ptr Failure)
            {
                EchoCompletion->Failure = std::move(Failure);
                (void)EchoCompletion->Done.try_send(boost::system::error_code{});
            });

        const auto Uuid = MakeUuid();
        auto Bytes = std::make_shared<Preview::Memory::BytePool>(
            Preview::Memory::BytePoolOptions{.BlockCount = 8});
        Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor=Io.get_executor();
        ListenerOptions.Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
            Preview::GenerationId{1});
        ListenerOptions.Factory = VmessDatagramSessionFactory{Uuid, Bytes};
        Runtime::TcpListener Listener(std::move(ListenerOptions));

        bool Echoed = false;
        RunDatagramCase(
            Io,
            RunVmessUdpEchoScenario(
                VmessUdpEchoRequest{
                    Io, Listener, Uuid, EchoPort, Echoed,
                    EchoSocket, EchoCompletion}));

        EXPECT_TRUE(Echoed);
        EXPECT_FALSE(EchoCompletion->Failure);
    }
