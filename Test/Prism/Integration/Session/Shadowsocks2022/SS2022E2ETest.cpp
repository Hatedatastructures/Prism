#include <TestSupport/Prism/ProviderBindings.hpp>
/**
 * @file SS2022E2ETest.cpp
 * @brief Shadowsocks2022 纵向链路测试（链 P：代理协议 L3 经 adapter 接入缝）
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Anytls/IngressFactory.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Protocols/Trojan/IngressFactory.hpp>
#include <Prism/Protocols/Vmess/IngressFactory.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Test/Prism/Runtime/Session/AdmissionSupport.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Network = Prism::Network;
    namespace Runtime = Prism::Runtime;
    namespace Shadowsocks2022 = Prism::Shadowsocks2022;
    using Tcp = Net::ip::tcp;
    using Prism::SharedTransmission;

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Prism::Testing::AcceptEchoLoop;
    using Prism::Testing::ChainState;
    using ConnectResult = Prism::Testing::ConnectResult;
    using Prism::Testing::RunCoro;
    using Prism::Testing::TcpEchoServer;

    inline constexpr std::array<std::uint8_t, 16> E2ePsk{
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40};
    inline constexpr std::array<std::uint8_t, 16> WrongE2ePsk{
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50};

    /// SS2022 纵向测试共享状态（复用公共 Prism::Testing::ChainState）
    using ss2022_chain_state = Prism::Testing::ChainState;

    /// 连接 SS2022 纵向测试的回环上游（复用公共 DialUpstream）
    auto DialSs2022Upstream(
        const std::shared_ptr<ss2022_chain_state> &State,
        const Network::Target &Target)
        -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
    {
        co_return co_await Prism::Testing::DialUpstream(State, Target);
    }

    struct Ss2022SessionRequest final
    {
        std::shared_ptr<ss2022_chain_state> State;
        Shadowsocks2022::ServerConfig Configuration;
        std::shared_ptr<Prism::Testing::TrafficRecorder> Traffic;
    };

    /** @brief 构造固定 SS2022 server binding 与共享上游 dial owner。 */
    auto MakeSs2022Session(Ss2022SessionRequest Request)
        -> std::shared_ptr<Runtime::Session>
    {
        Runtime::SessionOptions Options;
        Options.Services->Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8});
        Options.Services->AcceptProtocol = Prism::Testing::MakeSs2022Binding(Request.Configuration);
        Options.Services->Dial = [State = std::move(Request.State)](const Network::Target &Target)
            -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
        {
            co_return co_await DialSs2022Upstream(State, Target);
        };
        if (Request.Traffic)
        {
            Options.Services->Traffic = std::move(Request.Traffic);
        }
        return std::make_shared<Runtime::Session>(std::move(Options));
    }

    /** @brief 生成测试中的真实 connection-refused 上游服务。 */
    /** @brief 构造连接拒绝用 SS2022 binding 与上游服务。 */
    auto MakeRefusedSs2022Session() -> std::shared_ptr<Runtime::Session>
    {
        Runtime::SessionOptions Options;
        Options.Services->Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8});
        Options.Services->AcceptProtocol = Prism::Testing::MakeSs2022Binding(
            Shadowsocks2022::ServerConfig{E2ePsk});
        Options.Services->Dial = [](const Network::Target &)
            -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
        {
            co_return std::unexpected(Fault::Failure{Fault::Code::ConnectionRefused});
        };
        return std::make_shared<Runtime::Session>(std::move(Options));
    }

    struct Ss2022ConnectScenario final
    {
        Runtime::TcpListener &Listener;
        Tcp::acceptor &EchoAcceptor;
        std::shared_ptr<ss2022_chain_state> State;
        Shadowsocks2022::Address Target;
        Shadowsocks2022::ClientConfig ClientConfiguration;
        ConnectResult &Output;
    };

    /** @brief 运行 SS2022 listener、代理握手、上游 echo 与真实 listener stop。 */
    auto RunSs2022ConnectScenario(Ss2022ConnectScenario Scenario) -> Net::awaitable<void>
    {
        const auto StartResult = co_await Scenario.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        if (StartResult != Fault::Code::Success)
        {
            Scenario.Output.Failure = {StartResult, {}};
            co_return;
        }
        const auto ListenPort = Scenario.Listener.LocalEndpoint().port();
        Network::Dialer::Dialer Dialer(Scenario.EchoAcceptor.get_executor());
        auto Raw = co_await Dialer.Connect(
            {*Prism::Network::ParseHost("127.0.0.1"), ListenPort});
        if (!Raw)
        {
            Scenario.Output.Failure = Raw.error();
            Scenario.Listener.Stop();
            co_return;
        }
        auto ProxyResult = co_await Shadowsocks2022::Connect(
            std::move(*Raw), Scenario.ClientConfiguration, Scenario.Target);
        if (!ProxyResult)
        {
            Scenario.Output.Failure = ProxyResult.error();
            Scenario.Listener.Stop();
            co_return;
        }
        Scenario.Output.Failure = {};
        auto Proxy = std::move(*ProxyResult);

        const std::string Payload = "ss2022 runtime payload";
        const auto WriteResult = co_await Proxy->WriteExact(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
        std::array<std::byte, 64> Buffer{};
        std::size_t Received = 0;
        Prism::IoResult ReadResult{};
        while (!WriteResult.Failure.Failed() && Received < Payload.size())
        {
            ReadResult = co_await Proxy->ReadSome(
                std::span<std::byte>(Buffer).subspan(Received));
            if (ReadResult.Bytes == 0)
            {
                break;
            }
            Received += ReadResult.Bytes;
            if (ReadResult.Failure.Failed())
            {
                break;
            }
        }
        Scenario.Output.Echo.assign(reinterpret_cast<const char *>(Buffer.data()), Received);
        Scenario.Output.Host = Scenario.State->RequestedHost;
        Scenario.Output.Port = Scenario.State->RequestedPort;
        Proxy->Close();
        const auto Shutdown = co_await Scenario.Listener.Shutdown();
        if (!Shutdown && Scenario.Output.Failure.Succeeded())
        {
            Scenario.Output.Failure = Shutdown.error();
        }
        boost::system::error_code CloseError;
        Scenario.EchoAcceptor.close(CloseError);
    }

    struct Ss2022RefusedScenario final
    {
        Runtime::TcpListener &Listener;
        bool &SawClose;
    };

    /** @brief 保留连接拒绝后的 SOCKS client close 检查与 listener 停止顺序。 */
    auto RunSs2022RefusedScenario(Ss2022RefusedScenario Scenario) -> Net::awaitable<void>
    {
        const auto StartResult = co_await Scenario.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartResult, Fault::Code::Success);
        const auto ListenPort = Scenario.Listener.LocalEndpoint().port();
        Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        auto Raw = co_await Dialer.Connect(
            {*Prism::Network::ParseHost("127.0.0.1"), ListenPort});
        if (!Raw)
        {
            co_return;
        }
        auto ProxyResult = co_await Shadowsocks2022::Connect(
            std::move(*Raw), Shadowsocks2022::ClientConfig{E2ePsk},
            Shadowsocks2022::Address{Shadowsocks2022::AddressType::Domain, "example.com", 80});
        if (!ProxyResult)
        {
            Scenario.Listener.Stop();
            co_return;
        }
        auto Proxy = std::move(*ProxyResult);
        std::array<std::byte, 8> Buffer{};
        const auto ReadResult = co_await Proxy->ReadSome(Buffer);
        Scenario.SawClose = (ReadResult.Bytes == 0 || ReadResult.Failure.Failed());
        Proxy->Close();
        Scenario.Listener.Stop();
    }

    struct Ss2022TrafficScenario final
    {
        Runtime::TcpListener &Listener;
        Tcp::acceptor &EchoAcceptor;
        std::shared_ptr<Prism::Testing::TrafficRecorder> Recorder;
    };

    /** @brief 完成 SS2022 echo 后收集唯一 traffic recorder 的事件与字节数。 */
    auto RunSs2022TrafficScenario(Ss2022TrafficScenario Scenario) -> Net::awaitable<void>
    {
        const auto StartResult = co_await Scenario.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartResult, Fault::Code::Success);
        const auto ListenPort = Scenario.Listener.LocalEndpoint().port();
        Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        auto Raw = co_await Dialer.Connect(
            {*Prism::Network::ParseHost("127.0.0.1"), ListenPort});
        if (!Raw)
        {
            co_return;
        }
        auto ProxyResult = co_await Shadowsocks2022::Connect(
            std::move(*Raw), Shadowsocks2022::ClientConfig{E2ePsk},
            Shadowsocks2022::Address{Shadowsocks2022::AddressType::Domain, "example.com", 80});
        if (!ProxyResult)
        {
            Scenario.Listener.Stop();
            co_return;
        }
        auto Proxy = std::move(*ProxyResult);
        const std::string Payload = "traffic Probe";
        const auto WriteResult = co_await Proxy->WriteExact(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
        EXPECT_FALSE(WriteResult.Failure.Failed());
        EXPECT_EQ(WriteResult.Bytes, Payload.size());
        std::array<std::byte, 64> Buffer{};
        std::size_t Received = 0;
        Prism::IoResult ReadResult{};
        while (!WriteResult.Failure.Failed() && Received < Payload.size())
        {
            ReadResult = co_await Proxy->ReadSome(
                std::span<std::byte>(Buffer).subspan(Received));
            if (ReadResult.Bytes == 0)
            {
                break;
            }
            Received += ReadResult.Bytes;
            if (ReadResult.Failure.Failed())
            {
                break;
            }
        }
        EXPECT_FALSE(ReadResult.Failure.Failed());
        EXPECT_EQ(Received, Payload.size());
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), Received), Payload);
        Proxy->Close();
        co_await Scenario.Listener.Shutdown();
        boost::system::error_code CloseError;
        Scenario.EchoAcceptor.close(CloseError);
    }

    auto run_ss2022_connect(const Shadowsocks2022::Address &Target,
                            Shadowsocks2022::ClientConfig ccfg = Shadowsocks2022::ClientConfig{},
                            Shadowsocks2022::ServerConfig scfg = Shadowsocks2022::ServerConfig{})
        -> ConnectResult
    {
        ConnectResult out;
        Net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto StateObj = std::make_shared<ss2022_chain_state>(
            ss2022_chain_state{ioc.get_executor(), echo_port});
        Net::co_spawn(ioc.get_executor(), Prism::Testing::AcceptEchoLoop(echo_acceptor),
                      [](const std::exception_ptr &) {});

        Runtime::TcpListener listener(
            Runtime::TcpListener::Options{
            .Executor = ioc.get_executor(),
            .Factory = [StateObj, scfg](Prism::Runtime::SessionAdmission)
            {
                return MakeSs2022Session(Ss2022SessionRequest{StateObj, scfg, {}});
            },
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{1})});

        RunCoro(ioc, RunSs2022ConnectScenario(
            Ss2022ConnectScenario{listener, echo_acceptor, StateObj, Target, ccfg, out}));
        return out;
    }

    TEST(TcpListener, SS2022TcpConnectFullChain)
    {
        const auto r = run_ss2022_connect(
            Shadowsocks2022::Address{Shadowsocks2022::AddressType::Domain, "example.com", 443},
            Shadowsocks2022::ClientConfig{E2ePsk},
            Shadowsocks2022::ServerConfig{E2ePsk});
        EXPECT_TRUE(r.Failure.Succeeded());
        EXPECT_EQ(r.Failure.Code, Fault::Code::Success);
        EXPECT_EQ(r.Echo, "ss2022 runtime payload");
        EXPECT_EQ(r.Host, "example.com");
        EXPECT_EQ(r.Port, "443");
    }

    TEST(TcpListener, SS2022TcpConnectIpv4)
    {
        const auto r = run_ss2022_connect(
            Shadowsocks2022::Address{Shadowsocks2022::AddressType::Ipv4, "1.2.3.4", 80},
            Shadowsocks2022::ClientConfig{E2ePsk},
            Shadowsocks2022::ServerConfig{E2ePsk});
        EXPECT_TRUE(r.Failure.Succeeded());
        EXPECT_EQ(r.Failure.Code, Fault::Code::Success);
        EXPECT_EQ(r.Echo, "ss2022 runtime payload");
        EXPECT_EQ(r.Host, "1.2.3.4");
        EXPECT_EQ(r.Port, "80");
    }

    TEST(TcpListener, SS2022TcpConnectBadPassword)
    {
        const auto r = run_ss2022_connect(
            Shadowsocks2022::Address{Shadowsocks2022::AddressType::Domain, "example.net", 22},
            Shadowsocks2022::ClientConfig{WrongE2ePsk},
            Shadowsocks2022::ServerConfig{E2ePsk});
        EXPECT_TRUE(r.Failure.Failed());
        EXPECT_TRUE(r.Echo.empty());
    }

    TEST(TcpListener, SS2022TcpConnectDialRefused)
    {
        Net::io_context ioc;
        Runtime::TcpListener listener(
            Runtime::TcpListener::Options{
            .Executor = ioc.get_executor(),
            .Factory = [](Prism::Runtime::SessionAdmission)
            {
                return MakeRefusedSs2022Session();
            },
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{2})});
        bool saw_close = false;
        RunCoro(ioc, RunSs2022RefusedScenario(Ss2022RefusedScenario{listener, saw_close}));
        EXPECT_TRUE(saw_close);
    }

    TEST(TcpListener, SS2022TrafficIdentity)
    {
        Net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto StateObj = std::make_shared<ss2022_chain_state>(ss2022_chain_state{ioc.get_executor(), echo_port});
        auto recorder = std::make_shared<Prism::Testing::TrafficRecorder>();
        Net::co_spawn(ioc.get_executor(), Prism::Testing::AcceptEchoLoop(echo_acceptor),
                      [](const std::exception_ptr &) {});
        Runtime::TcpListener listener(
            Runtime::TcpListener::Options{
            .Executor = ioc.get_executor(),
            .Factory = [StateObj, recorder](Prism::Runtime::SessionAdmission)
            {
                return MakeSs2022Session(Ss2022SessionRequest{
                    StateObj, Shadowsocks2022::ServerConfig{E2ePsk}, recorder});
            },
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{3})});
        RunCoro(ioc, RunSs2022TrafficScenario(
            Ss2022TrafficScenario{listener, echo_acceptor, recorder}));
        EXPECT_EQ(recorder->LastEvent.Kind, Prism::Foundation::TrafficEventKind::Completed);
        EXPECT_EQ(recorder->LastEvent.Account, Prism::AccountId{1});
        EXPECT_GT(recorder->Up, 0u);
        EXPECT_GT(recorder->Down, 0u);
    }

} // namespace
