/**
 * @file VlessTestSupport.hpp
 * @brief VLESS 真实 Runtime Session 测试共享 fixture 与生命周期辅助。
 * @details 只承载被多个 VLESS E2E 测试编译单元实际消费的 owner、连接辅助和
 *          listener/echo 收口逻辑，不承载 TEST 宏或单个场景的测试正文。
 */

#pragma once

#include <gtest/gtest.h>
#include <Preview/Runtime/SessionAdmissionTestSupport.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <string_view>
#include <system_error>
#include <utility>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Protocols/Vless/IngressFactory.hpp>
#include <Preview/Protocols/Vless/Vless.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Preview/ProtocolIngressBindings.hpp>

namespace Preview::Testing::VlessE2E
{

    namespace Net = boost::asio;
    namespace Runtime = Preview::Runtime;
    namespace Network = Preview::Network;
    namespace Vless = Preview::Vless;
    namespace Fault = Preview::Fault;

    using Preview::Error;
    using Preview::SharedTransmission;
    using VlessChainState = Preview::Testing::ChainState;
    using TrafficRecorder = Preview::Testing::TrafficRecorder;
    using Tcp = Net::ip::tcp;

    using TcpEchoDone = Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct VlessTcpEchoOwner final
    {
        std::shared_ptr<Tcp::acceptor> Acceptor;
        std::shared_ptr<TcpEchoDone> Done;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    /** @brief 启动 VLESS TCP 回环上游并返回其关闭 owner。 */
    inline auto StartVlessTcpEcho(Net::io_context &Io) -> VlessTcpEchoOwner
    {
        VlessTcpEchoOwner Owner;
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

    /** @brief 关闭 VLESS TCP 回环上游并等待其协程结束。 */
    inline auto StopVlessTcpEcho(VlessTcpEchoOwner &Owner) -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        Owner.Acceptor->close(ErrorCode);
        (void)co_await Owner.Done->async_receive(Net::use_awaitable);
        if (*Owner.Failure)
        {
            std::rethrow_exception(*Owner.Failure);
        }
    }

    /** @brief 等待 VLESS TCP echo 和 listener 的真实关闭完成。 */
    inline auto FinishVlessTcpFlow(
        VlessTcpEchoOwner &Echo, Runtime::TcpListener &Listener,
        std::exception_ptr &FirstFailure) -> Net::awaitable<void>
    {
        try
        {
            co_await StopVlessTcpEcho(Echo);
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

    /** @brief 等待没有 echo owner 的 VLESS listener 真实关闭。 */
    inline auto FinishVlessListener(
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

    /** @brief 启动 VLESS 测试 listener，并统一处理启动结果。 */
    inline auto StartVlessListener(Runtime::TcpListener &Listener) -> Net::awaitable<bool>
    {
        const auto Result = co_await Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(Result, Fault::Code::Success);
        co_return Result == Fault::Code::Success;
    }

    /**
     * @brief 通过 VLESS listener 建立测试 client 的 TCP 连接。
     * @param Ioc 拨号 executor 所属的 io_context。
     * @param Listener 同步借用其本地 endpoint；协程返回前不保存引用。
     * @return 连接所有者或保留分类与原生原因的失败值；调用者拥有返回的 transmission。
     */
    inline auto DialVlessListener(
        Net::io_context &Ioc, Runtime::TcpListener &Listener)
        -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
    {
        Network::Dialer::Dialer Dialer(Ioc.get_executor());
        co_return co_await Dialer.Connect(
            {*Preview::Network::ParseHost("127.0.0.1"), Listener.LocalEndpoint().port()});
    }

    /** @brief 关闭 VLESS client transmission，并保存首个关闭异常。 */
    inline auto CloseVlessTransmission(
        SharedTransmission &Proxy, std::exception_ptr &FirstFailure) -> void
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

    /** @brief 生成供 VLESS client 使用的固定测试 UUID。 */
    inline auto TestUuid() -> std::array<std::uint8_t, Vless::UuidLen>
    {
        return Preview::Testing::MakeUuid();
    }

    /** @brief 使用固定测试 UUID 建立 VLESS client connection。 */
    inline auto ConnectVlessWithTestUuid(
        SharedTransmission Upstream, const Vless::Address &Target)
        -> Net::awaitable<std::expected<Vless::SharedConn, Fault::Failure>>
    {
        Vless::ClientConfig Config;
        Config.uuid = TestUuid();
        auto Result = co_await Vless::Connect(
            Vless::ConnectParameters{std::move(Upstream), Config, Target});
        if (!Result)
        {
            co_return std::unexpected(Result.error());
        }
        if (!*Result)
        {
            co_return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        }
        co_return Result;
    }

    /** @brief 连接 VLESS 纵向测试的回环上游。 */
    inline auto DialVlessUpstream(
        const std::shared_ptr<VlessChainState> &State,
        const Network::Target &Target)
        -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
    {
        co_return co_await Preview::Testing::DialUpstream(State, Target);
    }

    /** @brief 为 VLESS Runtime Session 构造协议服务和上游拨号策略。 */
    struct VlessSessionFactory final
    {
        std::shared_ptr<VlessChainState> Chain;
        Vless::ServerConfig Configuration;
        std::chrono::milliseconds RelayIdleTimeout{0};
        std::shared_ptr<TrafficRecorder> Traffic;
        bool RejectDial{false};

        /** @brief 创建一个绑定当前 VLESS 测试配置的 Runtime Session。 */
        auto operator()(Preview::Runtime::SessionAdmission Admission) const
            -> std::shared_ptr<Runtime::Session>
        {
            Runtime::SessionOptions Options;
            auto UseState = Preview::Testing::MakeProtocolIngressUseState();
            Options.Services->GenerationUseState = UseState;
            Options.Services->AcceptProtocol = Preview::Testing::MakeVlessIngress(
                Configuration, Preview::Testing::ProtocolIngressResources{
                    {}, UseState, Admission.Inbound->Executor()}, Preview::Vless::IngressRoute{});
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
                { co_return co_await DialVlessUpstream(ChainValue, Target); };
            }
            if (RelayIdleTimeout.count() != 0)
            {
                Options.Services->RelayIdleTimeout = RelayIdleTimeout;
            }
            Options.Services->Traffic = Traffic;
            return std::make_shared<Runtime::Session>(std::move(Options));
        }
    };

} // namespace Preview::Testing::VlessE2E
