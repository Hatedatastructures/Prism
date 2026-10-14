#pragma once

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/SessionAdmissionTestSupport.hpp>
#include <Preview/Protocols/Socks5/UdpAssoc.hpp>
#include <Preview/Transport/Reliable.hpp>

namespace Socks5UdpTestSupport
{
    namespace Net = boost::asio;
    namespace Network = Preview::Network;
    namespace Runtime = Preview::Runtime;
    namespace Socks5 = Preview::Socks5;
    namespace Fault = Preview::Fault;
    using Tcp = Net::ip::tcp;
    using Udp = Net::ip::udp;
    using Error = Preview::Error;
    using SharedTransmission = Preview::SharedTransmission;
    using TrafficRecorder = Preview::Testing::TrafficRecorder;

    /** @brief 首次 WriteSome 可暂停的 TCP 包装层，用于确定性重叠 bind、Run 与回复等待。 */
    class BindGateTransmission final : public Preview::Transmission
    {
    public:
        explicit BindGateTransmission(std::shared_ptr<Preview::Transport::Reliable> Next)
            : Preview::Transmission(Next->Executor()), Next_(std::move(Next)),
              WriteStarted_(Executor(), 1), WriteRelease_(Executor(), 1)
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Next_->Executor();
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Next_->ReadSome(Buffer, std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            auto Owner = std::static_pointer_cast<BindGateTransmission>(
                Preview::Transmission::shared_from_this());
            Net::co_spawn(Executor(), Owner->Write(Buffer),
                [Owner, Handler = std::move(Handler)](
                    std::exception_ptr ErrorValue, Preview::IoResult Result) mutable
                {
                    if (ErrorValue) Result = {0, {Preview::Fault::Code::IoError}};
                    Handler(std::move(Result));
                });
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Next_->WriteShutdown(std::move(Handler));
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            ReleaseWrite();
            return Next_->Close();
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            ReleaseWrite();
            return Next_->Cancel();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return Next_.get();
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Next_->IsOpen();
        }

        [[nodiscard]] auto WaitForWriteStart() -> Net::awaitable<bool>
        {
            (void)co_await WriteStarted_.async_receive(Net::use_awaitable);
            co_return true;
        }

        auto ReleaseWrite() -> void
        {
            (void)WriteRelease_.try_send(boost::system::error_code{});
        }

        [[nodiscard]] auto BytesWritten() const noexcept -> std::size_t
        {
            return BytesWritten_;
        }

    private:
        [[nodiscard]] auto Write(std::span<const std::byte> Buffer)
            -> Net::awaitable<Preview::IoResult>
        {
            if (!WriteStartedOnce_)
            {
                WriteStartedOnce_ = true;
                (void)WriteStarted_.try_send(boost::system::error_code{});
                (void)co_await WriteRelease_.async_receive(Net::use_awaitable);
            }
            auto Result = co_await Next_->WriteSome(Buffer);
            BytesWritten_ += Result.Bytes;
            co_return Result;
        }

        std::shared_ptr<Preview::Transport::Reliable> Next_;
        Net::experimental::concurrent_channel<void(boost::system::error_code)> WriteStarted_;
        Net::experimental::concurrent_channel<void(boost::system::error_code)> WriteRelease_;
        std::size_t BytesWritten_{0};
        bool WriteStartedOnce_{false};
    };

    /// 构造 SOCKS5 服务端接入回调（UDP_ASSOCIATE → Dgram 会话标记）
    auto MakeSocks5UdpAccept(Preview::Contract::DatagramServices Datagrams) -> std::shared_ptr<Preview::Contract::StreamFactory>
    {
        Socks5::ServerConfig Configuration;
        Configuration.EnableUdp = true;
        // UDP_ASSOCIATE 应答必须由数据面 Bind 后发送（携带 BND），
        // 不能使用握手默认的 0.0.0.0:0
        Configuration.DeferConnectReply = true;
        return Preview::Testing::MakeSocks5Binding(std::move(Configuration), std::move(Datagrams));
    }

    auto MakeDatagramServices(Preview::Contract::DatagramServices::ResolveFn Resolve,
                              std::chrono::milliseconds IdleTimeout)
        -> Preview::Contract::DatagramServices
    {
        return {IdleTimeout, std::move(Resolve), {}};
    }

    auto MakeDatagramServices(std::uint16_t EchoPort, std::chrono::milliseconds IdleTimeout)
        -> Preview::Contract::DatagramServices
    {
        Preview::Contract::DatagramServices Services;
        Services.IdleTimeout = IdleTimeout;
        Services.Resolve = [EchoPort](Preview::Network::Target)
            -> Net::awaitable<std::expected<Udp::endpoint, Preview::Fault::Failure>>
        { co_return Udp::endpoint(Net::ip::address_v4::loopback(), EchoPort); };
        return Services;
    }

    /// 构造一个 SOCKS5 UDP 帧
    auto MakeFrame(const Socks5::Address &Target, std::string_view Payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Frame;
        Socks5::BuildUdpDatagram(
            Target,
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Payload.data()), Payload.size()),
            Frame);
        return Frame;
    }

    struct UdpRoundtripResult final
    {
        std::string Echo;
        Socks5::Address Source;
        bool Ok{false};
    };

    /// 客户端通过真实 UDP socket 与代理数据面往返一次
    auto RunUdpRoundtrip(Udp::socket &ClientSocket, const Udp::endpoint &BindEndpoint,
                         const std::vector<std::uint8_t> &Frame)
        -> Net::awaitable<UdpRoundtripResult>
    {
        UdpRoundtripResult ResultValue;
        boost::system::error_code ErrorCode;
        co_await ClientSocket.async_send_to(
            Net::buffer(Frame), BindEndpoint,
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (ErrorCode)
        {
            co_return ResultValue;
        }
        std::array<std::byte, 65535> Buffer{};
        Udp::endpoint SourceEndpoint;
        Net::steady_timer Watchdog(ClientSocket.get_executor());
        Watchdog.expires_after(std::chrono::seconds(2));
        auto Receive = ClientSocket.async_receive_from(
            Net::buffer(Buffer), SourceEndpoint,
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        auto Wait = Watchdog.async_wait(Net::use_awaitable);
        const auto Race = co_await Net::experimental::awaitable_operators::operator||(
            std::move(Receive), std::move(Wait));
        if (Race.index() == 1 || ErrorCode)
        {
            co_return ResultValue;
        }
        const auto Received = std::get<0>(std::move(Race));
        Socks5::Address Source;
        std::span<const std::uint8_t> Payload;
        if (Socks5::ParseUdpDatagram(
                std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(Buffer.data()), Received),
                Source, Payload) != Error::None)
        {
            co_return ResultValue;
        }
        ResultValue.Echo.assign(
            reinterpret_cast<const char *>(Payload.data()), Payload.size());
        ResultValue.Source = std::move(Source);
        ResultValue.Ok = true;
        co_return ResultValue;
    }

/** @brief 在期限内探测 UDP 是否收到数据报；用于验证非关联 peer 被丢弃。 */
    auto ReceiveUdpWithin(Udp::socket &Socket, std::chrono::milliseconds Timeout)
        -> Net::awaitable<bool>
    {
        std::array<std::byte, 65535> Buffer{};
        Udp::endpoint Source;
        boost::system::error_code ErrorCode;
        Net::steady_timer Wait(Socket.get_executor());
        Wait.expires_after(Timeout);
        auto Receive = Socket.async_receive_from(
            Net::buffer(Buffer), Source,
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        auto WaitOperation = Wait.async_wait(Net::use_awaitable);
        const auto Result = co_await Net::experimental::awaitable_operators::operator||(
            std::move(Receive), std::move(WaitOperation));
        co_return Result.index() == 0 && !ErrorCode;
    }

    auto WriteSocks5Wire(const SharedTransmission &Connection,
                         const std::vector<std::uint8_t> &Wire) -> Net::awaitable<bool>
    {
        std::error_code ErrorCode;
        const auto Bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Wire.data()), Wire.size());
        const auto Written = co_await Connection->WriteExact(Bytes);
        ErrorCode = Preview::Fault::ToNative(Written.Failure);
        co_return !ErrorCode && Written.Bytes == Wire.size();
    }

    /** @brief 仅完成到 UDP_ASSOCIATE 请求写出，随后由调用者主动关闭控制 TCP。 */
    auto SendSocks5UdpAssociateRequest(const SharedTransmission &Connection)
        -> Net::awaitable<bool>
    {
        Socks5::Greeting GreetingValue;
        GreetingValue.Methods = {static_cast<std::uint8_t>(Socks5::AuthMethod::NoAuth)};
        if (!co_await WriteSocks5Wire(Connection, Socks5::BuildGreeting(GreetingValue)))
            co_return false;
        std::array<std::byte, 2> Selection{};
        std::error_code ErrorCode;
        const auto Selected = co_await Connection->ReadExact(std::span(Selection));
        ErrorCode = Preview::Fault::ToNative(Selected.Failure);
        if (ErrorCode || Selected.Bytes != Selection.size() ||
            Selection[0] != std::byte{Socks5::Version} ||
            Selection[1] != std::byte{static_cast<std::uint8_t>(Socks5::AuthMethod::NoAuth)})
            co_return false;
        Socks5::Request RequestValue;
        RequestValue.Cmd = Socks5::Command::UdpAssociate;
        RequestValue.Target = Socks5::Address{
            Socks5::AddressType::Domain, "example.com", 53};
        co_return co_await WriteSocks5Wire(Connection, Socks5::BuildRequest(RequestValue));
    }

    struct Socks5UdpSessionFactory final
    {
        std::uint16_t EchoPort;
        std::chrono::milliseconds IdleTimeout;
        std::shared_ptr<TrafficRecorder> Traffic;
        Preview::Contract::DatagramServices::ResolveFn Resolver;

        auto operator()(Preview::Runtime::SessionAdmission) const
            -> std::shared_ptr<Runtime::Session>
        {
            auto Datagrams = Resolver
                                 ? MakeDatagramServices(Resolver, IdleTimeout)
                                 : MakeDatagramServices(EchoPort, IdleTimeout);
            Datagrams.Traffic = Traffic;
            Runtime::SessionOptions Options;
            Options.Services->AcceptProtocol = MakeSocks5UdpAccept(std::move(Datagrams));
            return std::make_shared<Runtime::Session>(std::move(Options));
        }
    };

    struct Socks5UdpFamilyFlow final
    {
        Net::io_context &Io;
        Tcp::endpoint ListenEndpoint;
        std::string DialHost;
        Udp::endpoint ClientEndpoint;
        Udp::endpoint EchoEndpoint;
        Socks5::AddressType ExpectedType;
        std::string ExpectedHost;
        std::shared_ptr<TrafficRecorder> Recorder;
        std::string &EchoOne;
        std::string &EchoTwo;
        bool &HandshakeOk;
    };

    /** @brief 驱动 SOCKS5 UDP_ASSOCIATE 的真实双报文往返和 BND family 合同。 */
    auto RunSocks5UdpFamilyFlow(Socks5UdpFamilyFlow Flow) -> Net::awaitable<void>
    {
        Udp::socket EchoSocket(Flow.Io.get_executor());
        boost::system::error_code ErrorCode;
        EchoSocket.open(Flow.EchoEndpoint.protocol(), ErrorCode);
        if (ErrorCode)
        {
            co_return;
        }
        EchoSocket.bind(Flow.EchoEndpoint, ErrorCode);
        if (ErrorCode)
        {
            co_return;
        }
        EXPECT_FALSE(ErrorCode);
        const auto EchoPort = EchoSocket.local_endpoint().port();
        auto UpstreamFailure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(Flow.Io.get_executor(), Preview::Testing::UdpEchoServer(
            std::move(EchoSocket)),
            [UpstreamFailure](const std::exception_ptr &Failure)
            { if (Failure) *UpstreamFailure = Failure; });
        const auto Echo = Flow.EchoEndpoint.address();
        auto Resolver = [Echo, EchoPort](Preview::Network::Target)
            -> Net::awaitable<std::expected<Udp::endpoint, Preview::Fault::Failure>>
        { co_return Udp::endpoint(Echo, EchoPort); };
        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = Flow.Io.get_executor(),
            .Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
                Preview::GenerationId{1}),
            .Factory = Socks5UdpSessionFactory{0, std::chrono::seconds(5), Flow.Recorder,
                                                std::move(Resolver)}});
        const auto StartResult = co_await Listener.Start(Flow.ListenEndpoint);
        EXPECT_EQ(StartResult, Fault::Code::Success);
        if (StartResult != Fault::Code::Success)
        {
            co_await Listener.Shutdown();
            co_return;
        }
        Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        auto Dialed = co_await Dialer.Connect({Preview::Network::ParseHost(Flow.DialHost).value_or(Preview::Network::Host{}), Listener.LocalEndpoint().port()});
        Preview::SharedTransmission Raw;
        if (Dialed)
        {
            Raw = std::move(*Dialed);
        }
        if (!Raw)
        {
            co_await Listener.Shutdown();
            co_return;
        }
        auto [ErrorValue, Connection] = co_await Socks5::Connect({
            std::move(Raw), Socks5::ClientConfig{},
            Socks5::Address{Socks5::AddressType::Ipv4, "127.0.0.1", 0},
            Socks5::Command::UdpAssociate});
        Flow.HandshakeOk = ErrorValue == Error::None && Connection != nullptr;
        if (!Connection)
        {
            co_await Listener.Shutdown();
            co_return;
        }
        const auto Bind = Connection->BindEndpoint();
        const Udp::endpoint BindEndpoint(
            Net::ip::make_address(Bind.Host), Bind.Port);
        EXPECT_EQ(Bind.Type, Flow.ExpectedType);
        EXPECT_EQ(Bind.Host, Flow.ExpectedHost);
        EXPECT_EQ(BindEndpoint.address(), Net::ip::make_address(Flow.ExpectedHost));
        Udp::socket ClientSocket(Flow.Io.get_executor());
        boost::system::error_code SocketError;
        ClientSocket.open(Flow.ClientEndpoint.protocol(), SocketError);
        ClientSocket.bind(Flow.ClientEndpoint, SocketError);
        EXPECT_FALSE(SocketError);
        const auto FirstFrame = MakeFrame(
            Socks5::Address{Socks5::AddressType::Domain, "example.com", 53},
            "udp payload one");
        const auto FirstResult = co_await RunUdpRoundtrip(
            ClientSocket, BindEndpoint, FirstFrame);
        EXPECT_TRUE(FirstResult.Ok);
        Flow.EchoOne = FirstResult.Echo;
        const auto SecondFrame = MakeFrame(
            Socks5::Address{Socks5::AddressType::Ipv4, "8.8.8.8", 443},
            "udp payload two");
        const auto SecondResult = co_await RunUdpRoundtrip(
            ClientSocket, BindEndpoint, SecondFrame);
        EXPECT_TRUE(SecondResult.Ok);
        Flow.EchoTwo = SecondResult.Echo;
        ClientSocket.close();
        (void)Connection->Close();
        Net::steady_timer Drain(Flow.Io.get_executor());
        const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (Flow.Recorder && Flow.Recorder->Calls == 0 &&
               std::chrono::steady_clock::now() < Deadline)
        {
            Drain.expires_after(std::chrono::milliseconds(5));
            co_await Drain.async_wait(Net::use_awaitable);
        }
        co_await Listener.Shutdown();
        EXPECT_FALSE(*UpstreamFailure);
    }

    struct Socks5UdpPeerFlow final
    {
        Net::io_context &Io;
        Runtime::TcpListener &Listener;
        bool &RogueAccepted;
        bool &ControlAccepted;
    };

    /** @brief 非 control TCP peer 的 UDP 帧必须丢弃，合法 peer 仍可往返。 */
    auto RunSocks5UdpPeerFlow(Socks5UdpPeerFlow Flow) -> Net::awaitable<void>
    {
        co_await Flow.Listener.Start(Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Flow.Listener.LocalEndpoint().port()});
        Preview::SharedTransmission Raw;
        if (Dialed)
        {
            Raw = std::move(*Dialed);
        }
        if (!Raw)
        {
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        auto [ErrorValue, Connection] = co_await Socks5::Connect({
            std::move(Raw), Socks5::ClientConfig{},
            Socks5::Address{Socks5::AddressType::Ipv4, "127.0.0.1", 0},
            Socks5::Command::UdpAssociate});
        if (ErrorValue != Error::None || !Connection)
        {
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        const auto Bind = Connection->BindEndpoint();
        const Udp::endpoint BindEndpoint(Net::ip::make_address(Bind.Host), Bind.Port);
        boost::system::error_code SocketError;
        Udp::socket Rogue(Flow.Io.get_executor());
        Rogue.open(Udp::v4(), SocketError);
        Rogue.bind(Udp::endpoint(Net::ip::make_address("127.0.0.2"), 0), SocketError);
        const auto Frame = MakeFrame(
            Socks5::Address{Socks5::AddressType::Domain, "example.com", 53},
            "rogue peer");
        co_await Rogue.async_send_to(
            Net::buffer(Frame), BindEndpoint,
            Net::redirect_error(Net::use_awaitable, SocketError));
        Flow.RogueAccepted = co_await ReceiveUdpWithin(Rogue, std::chrono::milliseconds(150));

        Udp::socket ControlPeer(Flow.Io.get_executor());
        ControlPeer.open(Udp::v4(), SocketError);
        ControlPeer.bind(
            Udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), SocketError);
        const auto Result = co_await RunUdpRoundtrip(ControlPeer, BindEndpoint, Frame);
        Flow.ControlAccepted = Result.Ok && Result.Echo == "rogue peer";
        Rogue.close();
        ControlPeer.close();
        (void)Connection->Close();
        co_await Flow.Listener.Shutdown();
    }

    /** @brief 保存一次 bind、Run 与并发 BindAndReply 的输入、结果和真实完成通知。 */
    struct BindGateRaceState final
    {
        explicit BindGateRaceState(Net::io_context &Context)
            : Io(Context), FirstDone(Io.get_executor(), 1),
              SecondDone(Io.get_executor(), 1), RunDone(Io.get_executor(), 1)
        {
        }

        Net::io_context &Io;
        std::shared_ptr<Preview::Transport::Reliable> Client;
        std::shared_ptr<BindGateTransmission> Carrier;
        std::shared_ptr<Socks5::UdpAssoc> Association;
        Socks5::ReplyResult<std::size_t> First{std::size_t{0}};
        Socks5::ReplyResult<std::size_t> Second{std::size_t{0}};
        std::array<std::byte, 10> Wire{};
        std::size_t ReadBytes{0};
        std::size_t WrittenBytes{0};
        std::expected<void, Fault::Failure> RunResult{
            std::unexpected(Fault::Failure{Fault::Code::GenericError})};
        std::exception_ptr FirstException;
        std::exception_ptr SecondException;
        std::exception_ptr RunException;
        Net::experimental::channel<void(boost::system::error_code)> FirstDone;
        Net::experimental::channel<void(boost::system::error_code)> SecondDone;
        Net::experimental::channel<void(boost::system::error_code)> RunDone;
        bool FirstStarted{false};
        bool SecondStarted{false};
        bool RunStarted{false};
        bool FirstFinished{false};
        bool SecondFinished{false};
        bool RunFinished{false};
        bool RunWaited{false};
        bool SecondWaited{false};
        bool SecondCanceled{false};
        bool FirstPendingAfterWaiterCancel{false};
        Net::cancellation_signal SecondCancellation;
        bool WriteStartTimedOut{false};
        bool ClientCloseAccepted{false};
        std::expected<void, Fault::Failure> ClientDrain{};
        std::expected<void, Fault::Failure> AssociationDrain{};
    };

    /** @brief 异步建立真实 TCP 控制通道，保留 Reliable 作为下一层 socket owner。 */
    auto MakeBindGateTcpPair(Net::io_context &Io)
        -> Net::awaitable<std::pair<
            std::shared_ptr<Preview::Transport::Reliable>,
            std::shared_ptr<Preview::Transport::Reliable>>>
    {
        Tcp::acceptor Acceptor(
            Io, Tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        Tcp::socket ClientSocket(Io.get_executor());
        co_await ClientSocket.async_connect(Acceptor.local_endpoint(), Net::use_awaitable);
        auto ServerSocket = co_await Acceptor.async_accept(Net::use_awaitable);
        co_return std::pair{
            std::make_shared<Preview::Transport::Reliable>(std::move(ClientSocket)),
            std::make_shared<Preview::Transport::Reliable>(std::move(ServerSocket))};
    }

    /** @brief 启动首次 BND 绑定写入并保存其真实 completion。 */
    auto StartFirstBind(const std::shared_ptr<BindGateRaceState> &State) -> void
    {
        const auto Owner = State->Association;
        Net::co_spawn(State->Io.get_executor(),
            [Owner, State]() -> Net::awaitable<void>
            {
                State->FirstStarted = true;
                State->First = co_await Owner->BindAndReply();
            },
            [State](std::exception_ptr Exception)
            {
                State->FirstException = std::move(Exception);
                State->FirstFinished = true;
                (void)State->FirstDone.try_send(boost::system::error_code{});
            });
    }

    /** @brief 与已挂起的 BindAndReply 重叠启动 Run 和第二个显式绑定请求。 */
    auto StartBindGateJoiners(const std::shared_ptr<BindGateRaceState> &State) -> void
    {
        const auto Owner = State->Association;
        Net::co_spawn(State->Io.get_executor(),
            [Owner, State]() -> Net::awaitable<void>
            {
                State->RunStarted = true;
                State->RunResult = co_await Owner->Run();
            },
            [State](std::exception_ptr Exception)
            {
                State->RunException = std::move(Exception);
                State->RunFinished = true;
                (void)State->RunDone.try_send(boost::system::error_code{});
            });
        Net::co_spawn(State->Io.get_executor(),
            [Owner, State]() -> Net::awaitable<void>
            {
                State->SecondStarted = true;
                State->Second = co_await Owner->BindAndReply();
            },
            [State](std::exception_ptr Exception)
            {
                State->SecondException = std::move(Exception);
                State->SecondFinished = true;
                (void)State->SecondDone.try_send(boost::system::error_code{});
            });
    }

    /** @brief 仅取消一个共享 bind waiter，并记录其独立完成结果。 */
    auto StartCanceledBindGateWaiter(const std::shared_ptr<BindGateRaceState> &State) -> void
    {
        const auto Owner = State->Association;
        Net::co_spawn(State->Io.get_executor(), Owner->BindAndReply(),
            Net::bind_cancellation_slot(State->SecondCancellation.slot(),
                [State](std::exception_ptr Exception,
                        Socks5::ReplyResult<std::size_t> Result) mutable
                {
                    State->SecondException = std::move(Exception);
                    State->Second = std::move(Result);
                    State->SecondFinished = true;
                    (void)State->SecondDone.try_send(boost::system::error_code{});
                }));
        State->SecondStarted = true;
    }

    /** @brief 完成 BND 读取、控制 TCP 关闭、三个任务等待和 owner drain。 */
    auto FinishBindGateRace(const std::shared_ptr<BindGateRaceState> &State)
        -> Net::awaitable<void>
    {
        const auto Reply = co_await State->Client->ReadExact(
            std::span<std::byte>(State->Wire));
        State->ReadBytes = Reply.Bytes;
        State->ClientCloseAccepted = static_cast<bool>(State->Client->Close());
        State->ClientDrain = co_await State->Client->Activity()->Drain();
        (void)co_await State->FirstDone.async_receive(Net::use_awaitable);
        (void)co_await State->SecondDone.async_receive(Net::use_awaitable);
        (void)co_await State->RunDone.async_receive(Net::use_awaitable);
        if (State->FirstException) std::rethrow_exception(State->FirstException);
        if (State->SecondException) std::rethrow_exception(State->SecondException);
        if (State->RunException) std::rethrow_exception(State->RunException);
        State->WrittenBytes = State->Carrier->BytesWritten();
        State->AssociationDrain = co_await State->Association->Activity()->Drain();
    }

    /** @brief 强制 Run 与第二个 BindAndReply 等待同一 pending BND operation。 */
    auto RunBindGateRace(Net::io_context &Io,
                         const std::shared_ptr<BindGateRaceState> &State)
        -> Net::awaitable<void>
    {
        auto [Client, Server] = co_await MakeBindGateTcpPair(Io);
        State->Client = std::move(Client);
        State->Carrier = std::make_shared<BindGateTransmission>(std::move(Server));
        auto Connection = std::make_shared<Socks5::Conn<>>(State->Carrier);
        Socks5::UdpAssocOptions Options;
        Options.IdleTimeout = std::chrono::milliseconds(10);
        State->Association = std::make_shared<Socks5::UdpAssoc>(
            Io.get_executor(), std::move(Connection), std::move(Options));
        State->Client->SetTimeout(std::chrono::seconds(2));

        StartFirstBind(State);
        using boost::asio::experimental::awaitable_operators::operator||;
        Net::steady_timer StartWatchdog(Io.get_executor());
        StartWatchdog.expires_after(std::chrono::seconds(2));
        const auto Started = co_await (State->Carrier->WaitForWriteStart() ||
                                       StartWatchdog.async_wait(Net::use_awaitable));
        if (Started.index() != 0U)
        {
            State->WriteStartTimedOut = true;
            State->Association->Close();
            State->AssociationDrain = co_await State->Association->Activity()->Drain();
            (void)co_await State->FirstDone.async_receive(Net::use_awaitable);
            if (State->FirstException) std::rethrow_exception(State->FirstException);
            State->ClientCloseAccepted = static_cast<bool>(State->Client->Close());
            State->ClientDrain = co_await State->Client->Activity()->Drain();
            co_return;
        }
        StartBindGateJoiners(State);
        Net::steady_timer Observation(Io.get_executor());
        Observation.expires_after(std::chrono::milliseconds(20));
        co_await Observation.async_wait(Net::use_awaitable);
        State->RunWaited = State->RunStarted && !State->RunFinished;
        State->SecondWaited = State->SecondStarted && !State->SecondFinished;
        State->Carrier->ReleaseWrite();
        co_await FinishBindGateRace(State);
    }

    /** @brief 验证取消一个等待者不会取消已准入的 bind/reply 或其另一预约。 */
    auto RunBindGateCancellation(Net::io_context &Io,
                                 const std::shared_ptr<BindGateRaceState> &State)
        -> Net::awaitable<void>
    {
        auto [Client, Server] = co_await MakeBindGateTcpPair(Io);
        State->Client = std::move(Client);
        State->Carrier = std::make_shared<BindGateTransmission>(std::move(Server));
        auto Connection = std::make_shared<Socks5::Conn<>>(State->Carrier);
        Socks5::UdpAssocOptions Options;
        Options.IdleTimeout = std::chrono::milliseconds(10);
        State->Association = std::make_shared<Socks5::UdpAssoc>(
            Io.get_executor(), std::move(Connection), std::move(Options));
        State->Client->SetTimeout(std::chrono::seconds(2));

        StartFirstBind(State);
        using boost::asio::experimental::awaitable_operators::operator||;
        Net::steady_timer StartWatchdog(Io.get_executor());
        StartWatchdog.expires_after(std::chrono::seconds(2));
        const auto Started = co_await (State->Carrier->WaitForWriteStart() ||
                                       StartWatchdog.async_wait(Net::use_awaitable));
        if (Started.index() != 0U)
        {
            State->WriteStartTimedOut = true;
            State->Association->Close();
            State->AssociationDrain = co_await State->Association->Activity()->Drain();
            (void)co_await State->FirstDone.async_receive(Net::use_awaitable);
            if (State->FirstException) std::rethrow_exception(State->FirstException);
            State->ClientCloseAccepted = static_cast<bool>(State->Client->Close());
            State->ClientDrain = co_await State->Client->Activity()->Drain();
            co_return;
        }

        StartCanceledBindGateWaiter(State);
        Net::steady_timer Observation(Io.get_executor());
        Observation.expires_after(std::chrono::milliseconds(20));
        co_await Observation.async_wait(Net::use_awaitable);
        State->SecondWaited = State->SecondStarted && !State->SecondFinished;
        State->SecondCancellation.emit(Net::cancellation_type::all);
        (void)co_await State->SecondDone.async_receive(Net::use_awaitable);
        if (State->SecondException) std::rethrow_exception(State->SecondException);
        State->SecondCanceled = !State->Second &&
            State->Second.error().Protocol == Error::Canceled;
        State->FirstPendingAfterWaiterCancel = !State->FirstFinished;
        State->Carrier->ReleaseWrite();

        const auto Reply = co_await State->Client->ReadExact(
            std::span<std::byte>(State->Wire));
        State->ReadBytes = Reply.Bytes;
        State->ClientCloseAccepted = static_cast<bool>(State->Client->Close());
        State->ClientDrain = co_await State->Client->Activity()->Drain();
        (void)co_await State->FirstDone.async_receive(Net::use_awaitable);
        if (State->FirstException) std::rethrow_exception(State->FirstException);
        State->WrittenBytes = State->Carrier->BytesWritten();
        State->AssociationDrain = co_await State->Association->Activity()->Drain();
    }
} // namespace Socks5UdpTestSupport

