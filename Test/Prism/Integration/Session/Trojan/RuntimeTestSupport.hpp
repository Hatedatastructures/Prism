/**
 * @file RuntimeTestSupport.hpp
 * @brief Trojan runtime TCP E2E 共用 fixture 与 listener 生命周期。
 */
#pragma once

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Trojan/IngressFactory.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Prism/Protocol/Ingress.hpp>

namespace Prism::Testing::TrojanE2E
{
    namespace Net = boost::asio;
    namespace Runtime = Prism::Runtime;
    namespace Network = Prism::Network;
    namespace Trojan = Prism::Trojan;
    namespace Fault = Prism::Fault;
    using Prism::SharedTransmission;
    using Tcp = Net::ip::tcp;
    /** @brief 关闭协议连接并等待全部 carrier I/O 真实退栈。 */
    inline auto CloseAndDrain(SharedTransmission Connection) -> Net::awaitable<void>
    {
        if (!Connection)
        {
            co_return;
        }
        const auto Close = Connection->Close();
        EXPECT_TRUE(Close);
        const auto Drain = co_await Connection->Activity()->Drain();
        EXPECT_TRUE(Drain);
    }

    using TcpEchoDone = Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct TrojanTcpEchoOwner final
    {
        std::shared_ptr<Tcp::acceptor> Acceptor;
        std::shared_ptr<TcpEchoDone> Done;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    inline auto StartTrojanTcpEcho(Net::io_context &Io) -> TrojanTcpEchoOwner
    {
        TrojanTcpEchoOwner Owner;
        Owner.Acceptor = std::make_shared<Tcp::acceptor>(
            Io, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        Owner.Done = std::make_shared<TcpEchoDone>(Io.get_executor(), 1);
        Owner.Failure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(
            Io.get_executor(), Prism::Testing::AcceptEchoLoop(*Owner.Acceptor),
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

    inline auto StopTrojanTcpEcho(TrojanTcpEchoOwner &Owner) -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        Owner.Acceptor->close(ErrorCode);
        (void)co_await Owner.Done->async_receive(Net::use_awaitable);
        if (*Owner.Failure)
        {
            std::rethrow_exception(*Owner.Failure);
        }
    }

    /** @brief 等待 Trojan TCP echo 和 listener 的真实关闭完成。 */
    inline auto FinishTrojanTcpFlow(
        TrojanTcpEchoOwner &Echo, Runtime::TcpListener &Listener,
        std::exception_ptr &FirstFailure) -> Net::awaitable<void>
    {
        try
        {
            co_await StopTrojanTcpEcho(Echo);
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

    /** @brief 等待没有 echo owner 的 Trojan TCP listener 真实关闭。 */
    inline auto FinishTrojanListener(
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

    // 公共样板（RunCoro/echo 上游/TailReadGuarded 等见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）

    using ConnectResult = Prism::Testing::ConnectResult;
    using Prism::Testing::RunCoro;
    using Prism::Testing::AcceptEchoLoop;
    using Prism::Testing::TailReadGuarded;
    using Prism::Testing::TcpEchoServer;
    using TrafficRecorder = Prism::Testing::TrafficRecorder;

    using boost::asio::experimental::awaitable_operators::operator||;

    /// Trojan 纵向测试共享状态（复用公共 Prism::Testing::ChainState）
    using TrojanChainState = Prism::Testing::ChainState;

    /// 连接 Trojan 纵向测试的回环上游（复用公共 DialUpstream）
    inline auto DialTrojanUpstream(
        const std::shared_ptr<TrojanChainState> &State,
        const Network::Target &Target)
        -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
    {
        co_return co_await Prism::Testing::DialUpstream(State, Target);
    }

    /** @brief 为 listener 测试构造唯一账户、代次发布和活动计数 owner。 */
    inline auto MakeTrojanListenerAccounts(
        const Trojan::ServerConfig &Configuration,
        const Prism::GenerationId Generation)
        -> std::shared_ptr<Prism::Testing::ProtocolIngressAccounts>
    {
        return Prism::Testing::MakeProtocolIngressAccounts(
            Prism::Testing::ProtocolIngressAccountInput{
                .CredentialValue = Trojan::PrepareAccountCredential(Configuration.Password),
                .Id = Prism::AccountId{1},
                .GenerationId = Generation,
                .GenerationUseState = Prism::Testing::MakeProtocolIngressUseState()});
    }

    struct TrojanSessionFactory final
    {
        std::shared_ptr<TrojanChainState> Chain;
        Trojan::ServerConfig Configuration;
        std::shared_ptr<Prism::Testing::ProtocolIngressAccounts> Accounts;
        std::chrono::milliseconds RelayIdleTimeout{0};
        std::shared_ptr<TrafficRecorder> Traffic;
        bool RejectDial{false};
        std::shared_ptr<Prism::Memory::BytePool> Bytes{
            std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{.BlockCount = 8})};

        auto operator()(Prism::Runtime::SessionAdmission Admission) const
            -> std::shared_ptr<Runtime::Session>
        {
            if (!Accounts || !Accounts->Generation ||
                Admission.Generation != Accounts->Generation || !Accounts->GenerationUseState)
            {
                throw std::logic_error("Trojan listener admission owner mismatch");
            }
            Runtime::SessionOptions Options;
            Options.Services->Bytes = Bytes;
            auto UseState = Accounts->GenerationUseState;
            Options.Services->GenerationUseState = UseState;
            Options.Services->AcceptProtocol = Prism::Testing::MakeTrojanIngress(
                Configuration, Prism::Testing::ProtocolIngressResources{
                    .Datagrams = {}, .UseState = UseState,
                    .Executor = Admission.Inbound->Executor(), .Accounts = Accounts},
                Prism::Trojan::IngressRoute{});
            if (RejectDial)
            {
                Options.Services->Dial = [](const Network::Target &)
                    -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
                { co_return std::unexpected(Fault::Failure{Fault::Code::ConnectionRefused, {}}); };
            }
            else
            {
                const auto ChainValue = Chain;
                Options.Services->Dial = [ChainValue](const Network::Target &Target)
                    -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
                { co_return co_await DialTrojanUpstream(ChainValue, Target); };
            }
            if (RelayIdleTimeout.count() != 0) Options.Services->RelayIdleTimeout = RelayIdleTimeout;
            Options.Services->Traffic = Traffic;
            return std::make_shared<Runtime::Session>(std::move(Options));
        }
    };

} // namespace Prism::Testing::TrojanE2E
