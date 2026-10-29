/**
 * @file TrafficTest.cpp
 * @brief 验证 Trojan runtime traffic identity 与数据面生命周期。
 */
#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Transport/Transmission.hpp>

#include "RuntimeTestSupport.hpp"

namespace
{
    namespace Net = boost::asio;
    namespace Runtime = Prism::Runtime;
    namespace Network = Prism::Network;
    namespace Trojan = Prism::Trojan;
    namespace Fault = Prism::Fault;
    using Prism::SharedTransmission;
    using Tcp = Net::ip::tcp;
    namespace TrojanE2E = Prism::Testing::TrojanE2E;
    using TrojanE2E::CloseAndDrain;
    using TrojanE2E::FinishTrojanTcpFlow;
    using TrojanE2E::RunCoro;
    using TrojanE2E::StartTrojanTcpEcho;
    using TrojanE2E::TrojanChainState;
    using TrojanE2E::TrojanSessionFactory;
    using TrojanE2E::TrojanTcpEchoOwner;
    struct TrojanTrafficFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        TrojanTcpEchoOwner &Echo;
        Prism::Testing::TrafficRecorder &Recorder;
    };

    /** @brief 驱动 Trojan payload 并等待 traffic identity 记录收尾。 */
    auto RunTrojanTrafficFlow(TrojanTrafficFlow Flow) -> Net::awaitable<void>
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
                        const std::string Payload = "traffic identity Probe";
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
                        Net::steady_timer Timer(Flow.Ioc.get_executor());
                        const auto Deadline = std::chrono::steady_clock::now() +
                                              std::chrono::seconds(2);
                        while ((Flow.Recorder.Up == 0u || Flow.Recorder.Down == 0u) &&
                               std::chrono::steady_clock::now() < Deadline)
                        {
                            Timer.expires_after(std::chrono::milliseconds(5));
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

    TEST(TcpListener, TrojanTrafficIdentity)
    {
        // 认证身份不应携带明文密码（防统计/日志泄露）
        Net::io_context IoContext;
        auto Echo = StartTrojanTcpEcho(IoContext);
        const auto EchoPort = Echo.Acceptor->local_endpoint().port();
        auto StateObj = std::make_shared<TrojanChainState>(
            TrojanChainState{IoContext.get_executor(), EchoPort});
        const Trojan::ServerConfig Configuration{"Secret"};
        auto Accounts = TrojanE2E::MakeTrojanListenerAccounts(
            Configuration, Prism::GenerationId{5});

        auto Recorder = std::make_shared<Prism::Testing::TrafficRecorder>();


        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = IoContext.get_executor(),
            .Factory = TrojanSessionFactory{
                .Chain = StateObj, .Configuration = Configuration, .Accounts = Accounts,
                .Traffic = Recorder},
            .Publication = Accounts->Publication});

        RunCoro(IoContext, RunTrojanTrafficFlow(
            TrojanTrafficFlow{IoContext, Listener, Echo, *Recorder}));
        EXPECT_EQ(Recorder->LastEvent.Account, Prism::AccountId{1});
        ASSERT_TRUE(Accounts->Generation);
        EXPECT_EQ(Accounts->Generation->Id(), Prism::GenerationId{5});
        EXPECT_EQ(Recorder->LastEvent.Generation, Accounts->Generation->Id());
        EXPECT_GT(Recorder->Up, 0u);
        EXPECT_GT(Recorder->Down, 0u);
        EXPECT_FALSE(*Echo.Failure);
    }

} // namespace
