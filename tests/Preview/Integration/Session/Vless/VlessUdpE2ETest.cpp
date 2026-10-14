/**
 * @file VlessUdpE2ETest.cpp
 * @brief VLESS UDP 命令纵向链路测试（阶段 4 遗留：复用 Dgram 编排）
 * @details 与 SOCKS5 UDP 共用 runtime `udp_service` 抽象：
 *          Client TCP 握手（cmd=udp）→ 流上 UDP 帧 → UdpTunnel
 *          解帧 → 真实 UDP socket 转发 → 上游 echo → 封帧写回流。
 *          覆盖：多包往返、空闲超时、流 EOF 终止。
 */

#include <gtest/gtest.h>
#include <Preview/Contract/Services/Datagram.hpp>
#include <TestSupport/Preview/ProtocolIngressBindings.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <expected>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Protocols/Anytls/IngressFactory.hpp>
#include <Preview/Protocols/Vless/IngressFactory.hpp>
#include <Preview/Protocols/Trojan/IngressFactory.hpp>
#include <Preview/Protocols/Vmess/IngressFactory.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Vless/Vless.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Runtime = Preview::Runtime;
    namespace Network = Preview::Network;
    namespace Vless = Preview::Vless;
    namespace Fault = Preview::Fault;
    namespace Middleware = Preview::Middleware;
    using Preview::Error;
    using Preview::SharedTransmission;
    using Preview::Middleware::Context;
    using boost::asio::experimental::awaitable_operators::operator||;
    using Tcp = Net::ip::tcp;
    using Udp = Net::ip::udp;

    using UdpEchoDone = Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct VlessUdpEchoOwner final
    {
        std::shared_ptr<Udp::socket> Socket;
        std::shared_ptr<UdpEchoDone> Done;
        std::shared_ptr<std::exception_ptr> Failure;
        boost::system::error_code OpenError;
    };

    /** @brief 驱动 VLESS UDP 回环上游并回显收到的数据报。 */
    auto RunVlessUdpEchoServer(const VlessUdpEchoOwner &Owner)
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

    /** @brief 首包静默、随后送出空包双回复与合法回复，并注入伪造来源。 */
    auto RunVlessUdpBurstServer(const VlessUdpEchoOwner &Owner)
        -> Net::awaitable<void>
    {
        Udp::socket Rogue(Owner.Socket->get_executor(),
            Udp::endpoint(Net::ip::address_v4::loopback(), 0));
        std::array<std::byte, 65535> Buffer{};
        for (std::size_t Index = 0; Index < 3U; ++Index)
        {
            Udp::endpoint Source;
            boost::system::error_code ErrorCode;
            const auto Size = co_await Owner.Socket->async_receive_from(
                Net::buffer(Buffer), Source,
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode) co_return;
            if (Index == 0U) continue;
            if (Index == 1U)
            {
                const std::array<std::uint8_t, 1> Spoofed{0xFE};
                co_await Rogue.async_send_to(Net::buffer(Spoofed), Source,
                    Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode) co_return;
            }
            co_await Owner.Socket->async_send_to(
                Net::buffer(Buffer.data(), Size), Source,
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode) co_return;
            if (Index == 1U)
            {
                co_await Owner.Socket->async_send_to(
                    Net::buffer(Buffer.data(), Size), Source,
                    Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode) co_return;
            }
        }
    }

    /** @brief 启动 VLESS UDP 回环上游并返回其关闭 owner。 */
    auto StartVlessUdpEcho(Net::io_context &Io) -> VlessUdpEchoOwner
    {
        VlessUdpEchoOwner Owner;
        Owner.Socket = std::make_shared<Udp::socket>(Io.get_executor());
        Owner.Socket->open(Udp::v4(), Owner.OpenError);
        Owner.Socket->bind(
            Udp::endpoint(Net::ip::make_address("127.0.0.1"), 0),
            Owner.OpenError);
        Owner.Done = std::make_shared<UdpEchoDone>(Io.get_executor(), 1);
        Owner.Failure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(
            Io.get_executor(), RunVlessUdpEchoServer(Owner),
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

    /** @brief 启动不按请求一问一答的固定场景 UDP 上游。 */
    auto StartVlessUdpBurstEcho(Net::io_context &Io) -> VlessUdpEchoOwner
    {
        VlessUdpEchoOwner Owner;
        Owner.Socket = std::make_shared<Udp::socket>(Io.get_executor());
        Owner.Socket->open(Udp::v4(), Owner.OpenError);
        Owner.Socket->bind(
            Udp::endpoint(Net::ip::make_address("127.0.0.1"), 0),
            Owner.OpenError);
        Owner.Done = std::make_shared<UdpEchoDone>(Io.get_executor(), 1);
        Owner.Failure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(
            Io.get_executor(), RunVlessUdpBurstServer(Owner),
            [Owner](const std::exception_ptr &ErrorValue)
            {
                if (ErrorValue && !*Owner.Failure)
                    *Owner.Failure = ErrorValue;
                (void)Owner.Done->try_send(boost::system::error_code{}, true);
            });
        return Owner;
    }

    /** @brief 关闭 VLESS UDP 回环上游并等待其协程结束。 */
    auto StopVlessUdpEcho(VlessUdpEchoOwner &Owner) -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        Owner.Socket->close(ErrorCode);
        (void)co_await Owner.Done->async_receive(Net::use_awaitable);
        if (*Owner.Failure)
        {
            std::rethrow_exception(*Owner.Failure);
        }
    }

    /** @brief 等待 VLESS UDP echo 和 listener 的真实关闭完成。 */
    auto FinishVlessUdpFlow(
        VlessUdpEchoOwner &Echo, Runtime::TcpListener &Listener,
        std::exception_ptr &FirstFailure) -> Net::awaitable<void>
    {
        try
        {
            co_await StopVlessUdpEcho(Echo);
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

    /** @brief 启动 VLESS UDP 测试 listener，并统一处理启动结果。 */
    auto StartVlessUdpListener(Runtime::TcpListener &Listener) -> Net::awaitable<bool>
    {
        const auto Result = co_await Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(Result, Fault::Code::Success);
        co_return Result == Fault::Code::Success;
    }

    /**
     * @brief 通过 VLESS UDP listener 建立承载连接。
     * @param Ioc 拨号 executor 所属的 io_context。
     * @param Listener 同步借用其本地 endpoint；协程返回前不保存引用。
     * @return 连接所有者或保留分类与原生原因的失败值；调用者拥有返回的 transmission。
     */
    auto DialVlessUdpListener(
        Net::io_context &Ioc, Runtime::TcpListener &Listener)
        -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
    {
        Network::Dialer::Dialer Dialer(Ioc.get_executor());
        co_return co_await Dialer.Connect(
            {*Preview::Network::ParseHost("127.0.0.1"), Listener.LocalEndpoint().port()});
    }

    /** @brief 关闭 VLESS UDP client connection，并保存首个关闭异常。 */
    auto CloseVlessUdpConnection(
        Vless::SharedDgram &Proxy,
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

    /** @brief 导入共享测试工具和流量记录器别名。 */
    using Preview::Testing::MakeUuid;
    using Preview::Testing::RunCoro;
    using TrafficRecorder = Preview::Testing::TrafficRecorder;

    /** @brief 生成固定测试 UUID（Vless::UuidLen == 16）。 */
    inline auto TestUuid() -> std::array<std::uint8_t, Vless::UuidLen>
    {
        return MakeUuid();
    }


    /** @brief 构造启用 UDP 数据面的 VLESS 服务端接入工厂。 */
    auto MakeAcceptVlessUdp(Preview::Contract::DatagramServices Datagrams,
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState,
        Net::any_io_executor Executor) -> std::shared_ptr<Preview::Contract::StreamFactory>
    {
        Vless::ServerConfig Configuration;
        Configuration.uuid = TestUuid();
        Configuration.EnableUdp = true;
        return Preview::Testing::MakeVlessIngress(std::move(Configuration),
            Preview::Testing::ProtocolIngressResources{
                std::move(Datagrams), std::move(UseState), std::move(Executor)},
            Preview::Vless::IngressRoute{});
    }

    /** @brief 构造 VLESS UDP 数据面服务及其回环地址解析器。 */
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

    struct VlessUdpSessionFactory final
    {
        std::uint16_t EchoPort;
        std::chrono::milliseconds IdleTimeout;
        std::shared_ptr<TrafficRecorder> Recorder;

        auto operator()(SharedTransmission Inbound, std::size_t, std::string_view) const
            -> std::shared_ptr<Runtime::Session>
        {
            Runtime::SessionOptions Options;
            auto Services = MakeDatagramServices(EchoPort, IdleTimeout);
            Services.Traffic = Recorder;
            auto UseState = Preview::Testing::MakeProtocolIngressUseState();
            Options.Services->GenerationUseState = UseState;
            Options.Services->AcceptProtocol = MakeAcceptVlessUdp(
                std::move(Services), UseState, Inbound->Executor());
            return std::make_shared<Runtime::Session>(std::move(Options));
        }
    };

    /** @brief 验证流承载 UDP 被服务端收口，而不是解析无长度的裸流。 */
    auto WaitForStreamRejection(const Vless::SharedDgram &Proxy)
        -> Net::awaitable<bool>
    {
        std::array<std::byte, 64> Buffer{};
        std::error_code ReadEc;
        Net::steady_timer Watchdog(Proxy->Executor());
        Watchdog.expires_after(std::chrono::seconds(2));
        auto Result = co_await (Proxy->async_read_some(std::span(Buffer), ReadEc) ||
                                Watchdog.async_wait(Net::use_awaitable));
        if (Result.index() == 1)
        {
            Proxy->Close();
            co_return false;
        }
        co_return std::get<0>(std::move(Result)) == 0 || ReadEc;
    }


    struct VlessUdpEchoScenario final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VlessUdpEchoOwner &Echo;
        std::uint16_t EchoPort;
        const std::vector<std::uint8_t> &Payload;
        bool &HandshakeOk;
    };

    struct VlessUdpPacketExchange final
    {
        Runtime::TcpListener &Listener;
        Vless::SharedDgram Proxy;
        const std::vector<std::uint8_t> &Payload;
    };

    auto RunVlessUdpPacketExchange(VlessUdpPacketExchange Flow)
        -> Net::awaitable<void>
    {
        const auto Sent = co_await Flow.Proxy->AsyncSendDatagram(
            std::span<const std::uint8_t>(Flow.Payload));
        EXPECT_TRUE(Sent);
        if (!Sent)
        {
            Flow.Proxy->Close();
            co_return;
        }
        std::vector<std::uint8_t> Reply;
        const auto Received = co_await Flow.Proxy->AsyncReceiveDatagram(Reply);
        EXPECT_TRUE(Received);
        if (!Received)
        {
            Flow.Proxy->Close();
            co_return;
        }
        EXPECT_EQ(Reply, Flow.Payload);
        Flow.Proxy->Close();
    }

    auto RunVlessUdpEchoScenario(VlessUdpEchoScenario &Scenario)
        -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        Vless::SharedDgram Proxy;
        try
        {
            if (co_await StartVlessUdpListener(Scenario.Listener))
            {
                auto Raw = co_await DialVlessUdpListener(
                    Scenario.Ioc, Scenario.Listener);
                if (Raw)
                {
                    Vless::ClientConfig ClientConfig;
                    ClientConfig.uuid = TestUuid();
                    auto ConnectResult = co_await Vless::ConnectPacket(
                        std::move(*Raw), ClientConfig,
                        Vless::Address{Vless::AddressType::Ipv4, "127.0.0.1", Scenario.EchoPort});
                    Scenario.HandshakeOk = static_cast<bool>(ConnectResult) &&
                                           static_cast<bool>(*ConnectResult);
                    if (ConnectResult)
                    {
                        EXPECT_TRUE(*ConnectResult);
                        if (*ConnectResult)
                        {
                            Proxy = std::move(*ConnectResult);
                        }
                        else
                        {
                            ADD_FAILURE() << "VLESS factory returned an empty successful owner";
                        }
                    }
                    else
                    {
                        ADD_FAILURE() << "VLESS UDP handshake failed: "
                            << Preview::Fault::Describe(ConnectResult.error().Code)
                            << " Native=" << ConnectResult.error().Native.category().name()
                            << ":" << ConnectResult.error().Native.value();
                    }
                    if (Proxy)
                    {
                        co_await RunVlessUdpPacketExchange(VlessUdpPacketExchange{
                            Scenario.Listener, Proxy, Scenario.Payload});
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        CloseVlessUdpConnection(Proxy, FirstFailure);
        co_await FinishVlessUdpFlow(Scenario.Echo, Scenario.Listener, FirstFailure);
    }
    struct VlessUdpStreamCloseFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VlessUdpEchoOwner &Echo;
        std::uint16_t EchoPort;
        bool &Closed;
        bool SendEof;
    };

    struct VlessUdpBurstFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VlessUdpEchoOwner &Echo;
        std::uint16_t EchoPort;
        std::exception_ptr &FirstFailure;
        bool &Completed;
    };

    /** @brief 不等待请求对应回包地连续发送 VLESS 数据报并验证多回包与来源过滤。 */
    auto RunVlessUdpBurstFlow(VlessUdpBurstFlow Flow) -> Net::awaitable<void>
    {
        Flow.Completed = co_await StartVlessUdpListener(Flow.Listener);
        Vless::SharedDgram Proxy;
        if (Flow.Completed)
        {
            auto Raw = co_await DialVlessUdpListener(
                Flow.Ioc, Flow.Listener);
            Flow.Completed = bool(Raw);
            if (Flow.Completed)
            {
                Vless::ClientConfig Config;
                Config.uuid = TestUuid();
                auto Connection = co_await Vless::ConnectPacket(
                    std::move(*Raw), Config,
                    Vless::Address{Vless::AddressType::Ipv4, "127.0.0.1", Flow.EchoPort});
                Flow.Completed = static_cast<bool>(Connection) &&
                                 static_cast<bool>(*Connection);
                if (Connection)
                {
                    EXPECT_TRUE(*Connection);
                    if (*Connection)
                    {
                        Proxy = std::move(*Connection);
                    }
                    else
                    {
                        ADD_FAILURE() << "VLESS factory returned an empty successful owner";
                    }
                }
                else
                {
                    ADD_FAILURE() << "VLESS UDP burst handshake failed: "
                        << Preview::Fault::Describe(Connection.error().Code)
                        << " Native=" << Connection.error().Native.category().name()
                        << ":" << Connection.error().Native.value();
                }
            }
        }

        const std::array<std::vector<std::uint8_t>, 3> Inputs{{{0x11}, {}, {0x22, 0x23}}};
        if (Flow.Completed)
        {
            for (const auto& Input : Inputs)
            {
                const auto Sent = co_await Proxy->AsyncSendDatagram(
                    std::span<const std::uint8_t>(Input));
                if (!Sent)
                {
                    Flow.Completed = false;
                    break;
                }
            }
        }

        std::vector<std::vector<std::uint8_t>> Received;
        if (Flow.Completed)
        {
            for (std::size_t Index = 0; Index < 3U; ++Index)
            {
                std::vector<std::uint8_t> Payload;
                Net::steady_timer Watchdog(Proxy->Executor());
                Watchdog.expires_after(std::chrono::seconds(2));
                using Net::experimental::awaitable_operators::operator||;
                const auto Race = co_await (Proxy->AsyncReceiveDatagram(Payload) ||
                    Watchdog.async_wait(Net::use_awaitable));
                if (Race.index() != 0U || !std::get<0>(Race))
                {
                    Flow.Completed = false;
                    break;
                }
                Received.push_back(std::move(Payload));
            }
        }
        const std::vector<std::vector<std::uint8_t>> Expected{{}, {}, {0x22, 0x23}};
        if (Flow.Completed) Flow.Completed = Received == Expected;

        if (Flow.Completed)
        {
            std::vector<std::uint8_t> Unexpected;
            Net::steady_timer ExtraReplyWatchdog(Proxy->Executor());
            ExtraReplyWatchdog.expires_after(std::chrono::milliseconds(100));
            const auto Extra = co_await (Proxy->AsyncReceiveDatagram(Unexpected) ||
                ExtraReplyWatchdog.async_wait(Net::use_awaitable));
            Flow.Completed = Extra.index() == 1U;
        }

        CloseVlessUdpConnection(Proxy, Flow.FirstFailure);
        co_await FinishVlessUdpFlow(Flow.Echo, Flow.Listener, Flow.FirstFailure);
    }

    /** @brief 驱动流式 UDP 命令的拒绝/EOF 收口场景。 */
    auto RunVlessUdpStreamCloseFlow(VlessUdpStreamCloseFlow Flow)
        -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        Vless::SharedDgram Proxy;
        try
        {
            if (co_await StartVlessUdpListener(Flow.Listener))
            {
                auto Raw = co_await DialVlessUdpListener(
                    Flow.Ioc, Flow.Listener);
                if (Raw)
                {
                    Vless::ClientConfig ClientConfig;
                    ClientConfig.uuid = TestUuid();
                    auto ConnectResult = co_await Vless::ConnectPacket(
                        std::move(*Raw), ClientConfig,
                        Vless::Address{Vless::AddressType::Ipv4, "127.0.0.1", Flow.EchoPort});
                    if (!ConnectResult)
                    {
                        ADD_FAILURE() << "VLESS UDP stream-close handshake failed: "
                            << Preview::Fault::Describe(ConnectResult.error().Code)
                            << " Native=" << ConnectResult.error().Native.category().name()
                            << ":" << ConnectResult.error().Native.value();
                    }
                    else if (!*ConnectResult)
                    {
                        ADD_FAILURE() << "VLESS factory returned an empty successful owner";
                    }
                    else
                    {
                        Proxy = std::move(*ConnectResult);
                    }
                    if (Proxy)
                    {
                        if (Flow.SendEof)
                        {
                            Proxy->Shutdown();
                        }
                        Flow.Closed = co_await WaitForStreamRejection(Proxy);
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        CloseVlessUdpConnection(Proxy, FirstFailure);
        co_await FinishVlessUdpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    TEST(TcpListener, VlessUdpConnectEcho)
    {
        const std::vector<std::uint8_t> Payload{'v', 'l', 'e', 's', 's'};
        Net::io_context Io;
        auto Echo = StartVlessUdpEcho(Io);
        ASSERT_FALSE(Echo.OpenError);
        const auto EchoPort = Echo.Socket->local_endpoint().port();
        auto UpstreamFailure = Echo.Failure;

        auto Recorder = std::make_shared<Preview::Testing::TrafficRecorder>();
        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = Io.get_executor(),
            .Factory = VlessUdpSessionFactory{EchoPort, std::chrono::seconds(5), Recorder}});

        bool HandshakeOk = false;
        VlessUdpEchoScenario Scenario{
            Io, Listener, Echo, EchoPort, Payload, HandshakeOk};
        RunCoro(Io, RunVlessUdpEchoScenario(Scenario));

        EXPECT_TRUE(HandshakeOk);
        EXPECT_FALSE(*UpstreamFailure);
        EXPECT_EQ(Recorder->Up, Payload.size());
        EXPECT_EQ(Recorder->Down, Payload.size());
        EXPECT_EQ(Recorder->ByteCalls, 2);
        EXPECT_EQ(Recorder->Calls, 1);
    }

    TEST(TcpListener, VlessUdpBurstKeepsSendingAcrossSilenceAndAcceptsEmptyMultiReply)
    {
        Net::io_context Io;
        auto Echo = StartVlessUdpBurstEcho(Io);
        EXPECT_FALSE(Echo.OpenError);
        const auto EchoPort = Echo.Socket->local_endpoint().port();
        auto UpstreamFailure = Echo.Failure;
        auto Recorder = std::make_shared<Preview::Testing::TrafficRecorder>();
        Runtime::TcpListener Listener(Runtime::TcpListener::Options{
            .Executor = Io.get_executor(),
            .Factory = VlessUdpSessionFactory{EchoPort, std::chrono::seconds(2), Recorder}});
        bool Completed = false;
        std::exception_ptr FirstFailure;
        RunCoro(Io, RunVlessUdpBurstFlow(
            VlessUdpBurstFlow{Io, Listener, Echo, EchoPort, FirstFailure, Completed}));

        EXPECT_TRUE(Completed);
        EXPECT_FALSE(*UpstreamFailure);
        EXPECT_EQ(Recorder->Up, 3U);
        EXPECT_EQ(Recorder->Down, 2U);
    }

    TEST(TcpListener, VlessUdpConnectIdleTimeout)
    {
        Net::io_context Io;
        auto Echo = StartVlessUdpEcho(Io);
        ASSERT_FALSE(Echo.OpenError);
        const auto EchoPort = Echo.Socket->local_endpoint().port();
        auto UpstreamFailure = Echo.Failure;

        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = Io.get_executor(),
            .Factory = VlessUdpSessionFactory{EchoPort, std::chrono::milliseconds(120), {}}});

        bool Closed = false;
        RunCoro(Io, RunVlessUdpStreamCloseFlow(
            VlessUdpStreamCloseFlow{Io, Listener, Echo, EchoPort, Closed, false}));

        EXPECT_TRUE(Closed);
        EXPECT_FALSE(*UpstreamFailure);
    }

    TEST(TcpListener, VlessUdpConnectStreamEofTerminates)
    {
        Net::io_context Io;
        auto Echo = StartVlessUdpEcho(Io);
        ASSERT_FALSE(Echo.OpenError);
        const auto EchoPort = Echo.Socket->local_endpoint().port();
        auto UpstreamFailure = Echo.Failure;

        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = Io.get_executor(),
            .Factory = VlessUdpSessionFactory{EchoPort, std::chrono::seconds(5), {}}});

        bool StreamClosed = false;
        RunCoro(Io, RunVlessUdpStreamCloseFlow(
            VlessUdpStreamCloseFlow{Io, Listener, Echo, EchoPort, StreamClosed, true}));

        EXPECT_TRUE(StreamClosed);
        EXPECT_FALSE(*UpstreamFailure);
    }

} // namespace
