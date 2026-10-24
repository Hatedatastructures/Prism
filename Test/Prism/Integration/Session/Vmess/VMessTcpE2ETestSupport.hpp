#pragma once

#include <gtest/gtest.h>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Vmess/IngressFactory.hpp>
#include <Prism/Protocols/Vmess/Vmess.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Prism/ProtocolIngressBindings.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Testing::VmessTcpE2E
{

    namespace Net = boost::asio;
    namespace Runtime = Prism::Runtime;
    namespace Network = Prism::Network;
    namespace Vmess = Prism::Vmess;
    namespace Fault = Prism::Fault;
    using Prism::SharedTransmission;
    using Tcp = Net::ip::tcp;
    using ConnectResult = Prism::Testing::ConnectResult;
    using vmess_chain_state = Prism::Testing::ChainState;
    using TrafficRecorder = Prism::Testing::TrafficRecorder;

    using TcpEchoDone = Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct VmessTcpEchoOwner final
    {
        std::shared_ptr<Tcp::acceptor> Acceptor;
        std::shared_ptr<TcpEchoDone> Done;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    inline auto StartVmessTcpEcho(Net::io_context &Io) -> VmessTcpEchoOwner
    {
        VmessTcpEchoOwner Owner;
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

    inline auto StopVmessTcpEcho(VmessTcpEchoOwner &Owner) -> Net::awaitable<void>
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
    inline auto FinishVmessTcpFlow(
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
    inline auto FinishVmessListener(
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
    inline auto StartVmessListener(Runtime::TcpListener &Listener) -> Net::awaitable<bool>
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
    inline auto DialVmessListener(
        Net::io_context &Ioc, Runtime::TcpListener &Listener)
        -> Net::awaitable<std::expected<SharedTransmission, Prism::Fault::Failure>>
    {
        Network::Dialer::Dialer Dialer(Ioc.get_executor());
        co_return co_await Dialer.Connect(
            {*Prism::Network::ParseHost("127.0.0.1"), Listener.LocalEndpoint().port()});
    }

    /** @brief 关闭 VMess client connection，并保存首个关闭异常。 */
    inline auto CloseVmessConnection(
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

    /** @brief 返回 VMess 纵向测试使用的 UUID。 */
    inline auto TestUuid() -> std::array<std::uint8_t, 16>
    {
        return Prism::Testing::MakeUuid();
    }

    /** @brief 连接 VMess 纵向测试的回环上游。 */
    inline auto DialVmessUpstream(
        const std::shared_ptr<vmess_chain_state> &State,
        const Network::Target &Target)
        -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
    {
        co_return co_await Prism::Testing::DialUpstream(State, Target);
    }

    struct VmessSessionFactory final
    {
        std::shared_ptr<vmess_chain_state> Chain;
        Vmess::ServerConfig Configuration;
        std::chrono::milliseconds RelayIdleTimeout{0};
        std::shared_ptr<TrafficRecorder> Traffic;
        bool RejectDial{false};

        auto operator()(Prism::Runtime::SessionAdmission Admission) const
            -> std::shared_ptr<Runtime::Session>
        {
            Runtime::SessionOptions Options;
            Options.Services->Bytes = std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{.BlockCount = 8});
            auto UseState = Prism::Testing::MakeProtocolIngressUseState();
            Options.Services->GenerationUseState = UseState;
            Options.Services->AcceptProtocol = Prism::Testing::MakeVmessIngress(
                Configuration, Prism::Testing::VmessIngressResources{
                    {}, {}, {}, UseState, Admission.Inbound->Executor()}, Prism::Vmess::IngressRoute{});
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
                { co_return co_await DialVmessUpstream(ChainValue, Target); };
            }
            if (RelayIdleTimeout.count() != 0) Options.Services->RelayIdleTimeout = RelayIdleTimeout;
            Options.Services->Traffic = Traffic;
            return std::make_shared<Runtime::Session>(std::move(Options));
        }
    };

}
