/**
 * @file DialerTest.cpp
 * @brief TCP 拨号测试（T3-1）
 * @details 覆盖：
 *          - 成功连接（loopback）
 *          - 连接拒绝（未监听端口）
 *          - 超时（取消槽驱动的受控 pending 连接）
 *          - 无效端口 / IPv6 禁用
 */

#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Net/Dialer/Detail/AttemptRetirement.hpp>
#include <Prism/Net/Dns/Config.hpp>
#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Transport/Reliable.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    using Prism::SharedTransmission;

    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct AttemptRetirementEvent final
    {
        int Result{0};
        bool Retired{false};
        bool ObserveResult{false};
        std::shared_ptr<int> ResultValue;
        std::shared_ptr<CompletionChannel> ResultConsumed;

        AttemptRetirementEvent() = default;
        AttemptRetirementEvent(const AttemptRetirementEvent &) = delete;
        auto operator=(const AttemptRetirementEvent &) -> AttemptRetirementEvent & = delete;
        AttemptRetirementEvent(AttemptRetirementEvent &&) = default;
        auto operator=(AttemptRetirementEvent &&) -> AttemptRetirementEvent & = default;

        ~AttemptRetirementEvent()
        {
            if (!ObserveResult || Retired || !ResultValue || !ResultConsumed)
            {
                return;
            }
            *ResultValue = Result;
            (void)ResultConsumed->try_send(boost::system::error_code{});
        }
    };

    using AttemptRetirementEventChannel =
        Net::experimental::channel<void(boost::system::error_code, AttemptRetirementEvent)>;

    struct AttemptRetirementWaitState final
    {
        explicit AttemptRetirementWaitState(Net::any_io_executor Executor)
            : Events(Executor, 2), ResultValue(std::make_shared<int>(0)),
              ResultConsumed(std::make_shared<CompletionChannel>(Executor, 1)),
              Done(std::move(Executor), 1)
        {
        }

        AttemptRetirementEventChannel Events;
        std::shared_ptr<int> ResultValue;
        std::shared_ptr<CompletionChannel> ResultConsumed;
        CompletionChannel Done;
        bool ContinuationReturned{false};
        std::exception_ptr Exception;
    };

    auto WaitForAttemptRetirement(std::shared_ptr<AttemptRetirementWaitState> State)
        -> Net::awaitable<void>
    {
        boost::system::error_code Error;
        (void)co_await Prism::Network::Dialer::Detail::WaitUntilAttemptRetired(
            State->Events, Net::redirect_error(Net::use_awaitable, Error));
        State->ContinuationReturned = !Error;
    }

    auto RunAttemptRetirementWait(std::shared_ptr<AttemptRetirementWaitState> State)
        -> Net::awaitable<void>
    {
        const auto Executor = co_await Net::this_coro::executor;
        Net::co_spawn(Executor, WaitForAttemptRetirement(State),
            [State](std::exception_ptr Exception)
            {
                State->Exception = std::move(Exception);
                (void)State->Done.try_send(boost::system::error_code{});
            });

        AttemptRetirementEvent Result;
        Result.Result = 7;
        Result.ObserveResult = true;
        Result.ResultValue = State->ResultValue;
        Result.ResultConsumed = State->ResultConsumed;
        if (!State->Events.try_send(boost::system::error_code{}, std::move(Result)))
        {
            ADD_FAILURE() << "scripted result was not accepted";
            co_return;
        }
        co_await State->ResultConsumed->async_receive(Net::use_awaitable);
        EXPECT_EQ(*State->ResultValue, 7);
        EXPECT_FALSE(State->ContinuationReturned);

        AttemptRetirementEvent Retired;
        Retired.Retired = true;
        if (!State->Events.try_send(boost::system::error_code{}, std::move(Retired)))
        {
            ADD_FAILURE() << "scripted retirement was not accepted";
            co_return;
        }
        co_await State->Done.async_receive(Net::use_awaitable);
        EXPECT_FALSE(State->Exception);
        EXPECT_TRUE(State->ContinuationReturned);
    }

    struct CompletionState final
    {
        explicit CompletionState(Net::any_io_executor Executor) : Done(std::move(Executor), 1) {}

        CompletionChannel Done;
        std::exception_ptr Failure;
    };

    auto RecordCompletion(const std::shared_ptr<CompletionState> &State, std::exception_ptr Failure) -> void
    {
        State->Failure = Failure;
        (void)State->Done.try_send(boost::system::error_code{});
    }

    auto WaitForCompletion(const std::shared_ptr<CompletionState> &State) -> Net::awaitable<void>
    {
        co_await State->Done.async_receive(Net::use_awaitable);
        if (State->Failure)
        {
            std::rethrow_exception(State->Failure);
        }
    }

    auto RunCoro(Net::io_context &Ioc, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::move(Operation), [&](std::exception_ptr Error) { Exception = Error; });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /**
     * @brief 接受一个拨号连接并在完成后关闭服务端 socket。
     * @param Acceptor 监听 acceptor，由调用测试持有至 completion。
     * @return 接受和关闭完成后返回。
     */
    auto RunAcceptOnce(Tcp::acceptor &Acceptor) -> Net::awaitable<void>
    {
        auto Socket = co_await Acceptor.async_accept(Net::use_awaitable);
        Socket.close();
    }

    struct DialAttemptRequest final
    {
        Net::any_io_executor Executor;
        Prism::Network::Target Target;
        Prism::Network::Dialer::DialOptions Options{};
    };

    struct DialAttemptResult final
    {
        Prism::Fault::Failure Failure;
        SharedTransmission Connection;
    };

    struct PendingConnectState final
    {
        bool Entered{false};
    };

    /** @brief 保持连接待决，直到 Dialer 的总 deadline 通过注入取消槽中断它。 */
    auto WaitForConnectCancellation(
        Prism::Network::Dialer::DialOptions::ConnectRequest,
        Net::cancellation_slot Cancellation,
        std::shared_ptr<PendingConnectState> State) -> Net::awaitable<boost::system::error_code>
    {
        State->Entered = true;
        Net::steady_timer Timer(co_await Net::this_coro::executor);
        Timer.expires_after(std::chrono::hours(1));
        boost::system::error_code Error;
        co_await Timer.async_wait(
            Net::bind_cancellation_slot(
                Cancellation, Net::redirect_error(Net::use_awaitable, Error)));
        co_return Error;
    }

    /** @brief 执行一个明确目标和拨号选项并保留唯一 typed 结果。 */
    auto RunDialAttempt(DialAttemptRequest Request, DialAttemptResult &Result)
        -> Net::awaitable<void>
    {
        Prism::Network::Dialer::Dialer Dialer(Request.Executor, Request.Options);
        auto Dialed = co_await Dialer.Connect(Request.Target);
        if (Dialed)
        {
            Result.Connection = std::move(*Dialed);
        }
        else
        {
            Result.Failure = Dialed.error();
        }
    }

    struct SuccessfulDialRequest final
    {
        Tcp::acceptor &Acceptor;
        std::uint16_t Port;
    };

    /** @brief 拨号成功场景等待真实 accept owner 退栈。 */
    auto RunSuccessfulDial(SuccessfulDialRequest Request, DialAttemptResult &Result)
        -> Net::awaitable<void>
    {
        const auto Accepted = std::make_shared<CompletionState>(Request.Acceptor.get_executor());
        Net::co_spawn(Request.Acceptor.get_executor(), RunAcceptOnce(Request.Acceptor),
                      [Accepted](std::exception_ptr Failure)
                      { RecordCompletion(Accepted, Failure); });
        Prism::Network::Dialer::Dialer Dialer(Request.Acceptor.get_executor());
        auto Dialed = co_await Dialer.Connect(
            {*Prism::Network::ParseHost("127.0.0.1"), Request.Port});
        if (Dialed)
        {
            Result.Connection = std::move(*Dialed);
        }
        else
        {
            Result.Failure = Dialed.error();
        }
        co_await WaitForCompletion(Accepted);
    }

    /**
     * @brief 接受一次连接并完成一轮真实 echo 读写。
     * @param Acceptor 监听 acceptor，由调用测试持有至 completion。
     * @return echo 读写及 socket 关闭完成后返回。
     */
    auto RunEchoOnce(Tcp::acceptor &Acceptor) -> Net::awaitable<void>
    {
        auto Socket = co_await Acceptor.async_accept(Net::use_awaitable);
        std::array<std::byte, 64> Buffer{};
        boost::system::error_code ErrorCode;
        const auto Count = co_await Socket.async_read_some(
            Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (!ErrorCode && Count > 0)
        {
            co_await Socket.async_write_some(
                Net::buffer(Buffer, Count), Net::redirect_error(Net::use_awaitable, ErrorCode));
        }
        Socket.close();
    }

    struct EchoScenarioRequest final
    {
        Tcp::acceptor &Acceptor;
        std::uint16_t Port;
        SharedTransmission &Connection;
        Prism::Fault::Failure &DialFailure;
    };

    /**
     * @brief 拨号后完成 echo 传输，并等待服务端任务真实退栈。
     * @param Acceptor 监听 acceptor。
     * @param Port 监听端口。
     * @param Connection 输出的拨号传输所有者。
     * @param DialFailure 输出的 typed 拨号失败。
     * @return 拨号、双向传输和服务端关闭完成后返回。
     */
    auto RunEchoScenario(EchoScenarioRequest Request) -> Net::awaitable<void>
    {
        const auto Completion = std::make_shared<CompletionState>(Request.Acceptor.get_executor());
        Net::co_spawn(Request.Acceptor.get_executor(), RunEchoOnce(Request.Acceptor),
                      [Completion](std::exception_ptr Failure)
                      { RecordCompletion(Completion, Failure); });

        Prism::Network::Dialer::Dialer Dialer(Request.Acceptor.get_executor());
        auto Dialed = co_await Dialer.Connect(
            {*Prism::Network::ParseHost("127.0.0.1"), Request.Port});
        if (Dialed)
        {
            Request.Connection = std::move(*Dialed);
        }
        else
        {
            Request.DialFailure = Dialed.error();
        }
        if (!Request.Connection)
        {
            boost::system::error_code CloseError;
            Request.Acceptor.close(CloseError);
            co_await WaitForCompletion(Completion);
            co_return;
        }

        const std::string Message = "Dialer-echo";
        std::error_code WriteError;
        const auto Write = co_await Request.Connection->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Message.data()), Message.size()));
        WriteError = Prism::Fault::ToNative(Write.Failure);
        std::array<std::byte, 64> Buffer{};
        std::error_code ReadError;
        const auto Read = co_await Request.Connection->ReadSome(Buffer);
        ReadError = Prism::Fault::ToNative(Read.Failure);
        const auto Count = Read.Bytes;
        EXPECT_FALSE(WriteError);
        EXPECT_FALSE(ReadError);
        EXPECT_EQ(Count, Message.size());
        if (!ReadError && Count == Message.size())
        {
            EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Buffer.data()), Count), Message);
        }
        (void)Request.Connection->Close();
        co_await WaitForCompletion(Completion);
    }

    struct DialerCancellationSink final : Prism::Foundation::TrafficSink
    {
        DialerCancellationSink(Net::any_io_executor Executor,
            std::shared_ptr<Net::cancellation_signal> Cancellation)
            : Executor_(std::move(Executor)), Cancellation_(std::move(Cancellation))
        {
        }

        Net::any_io_executor Executor_;
        std::shared_ptr<Net::cancellation_signal> Cancellation_;
        std::size_t TcpConnectReports{0};

        auto Report(Prism::Foundation::TrafficEvent Event) noexcept -> void override
        {
            if (Event.Kind != Prism::Foundation::TrafficEventKind::NetworkLatency)
            {
                return;
            }
            if (Event.NetworkStage == Prism::Foundation::NetworkLatencyStage::DnsResolution)
            {
                try
                {
                    Net::post(Executor_, [Cancellation = Cancellation_]
                    {
                        Cancellation->emit(Net::cancellation_type::all);
                    });
                }
                catch (...)
                {
                }
            }
            else if (Event.NetworkStage == Prism::Foundation::NetworkLatencyStage::TcpConnect)
            {
                ++TcpConnectReports;
            }
        }

        auto Retire(Prism::Foundation::TrafficRetirement Owner)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            (void)Owner;
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
    };

    using DialResult = std::expected<SharedTransmission, Prism::Fault::Failure>;

    struct DialerCancellationResult final
    {
        std::exception_ptr Exception;
        std::optional<DialResult> Result;
        std::size_t TcpConnectReportsAtReturn{0};
        bool ResolverShutdownSucceeded{false};
    };

    struct DialerCancellationRequest final
    {
        Tcp::acceptor &Acceptor;
        DialerCancellationResult &Result;
    };

    /** @brief 驱动双候选外部取消并关闭注入的 Resolver owner。 */
    auto RunExternalCancellationDial(DialerCancellationRequest Request) -> Net::awaitable<void>
    {
        const auto Executor = Request.Acceptor.get_executor();
        Prism::Network::Dns::Config DnsConfig;
        DnsConfig.AddressRules.push_back({"dialer.cancel.test",
            {Net::ip::make_address("127.0.0.1"), Net::ip::make_address("127.0.0.2")}, false});
        const auto Resolver = std::make_shared<Prism::Network::Dns::Resolver>(Executor, DnsConfig);
        auto Cancellation = std::make_shared<Net::cancellation_signal>();
        const auto Sink = std::make_shared<DialerCancellationSink>(Executor, Cancellation);
        auto DialDone = std::make_shared<CompletionChannel>(Executor, 1);
        Prism::Network::Dialer::DialOptions Options;
        Options.Timeout = std::chrono::seconds(1);
        Options.Resolver = Resolver;
        Options.Observation = Prism::Network::Dialer::ObservationOwner{Sink, Prism::WorkerId{}};
        Prism::Network::Dialer::Dialer Dialer(Executor, Options);
        const Prism::Network::Target Target{
            *Prism::Network::ParseHost("dialer.cancel.test"),
            Request.Acceptor.local_endpoint().port()};

        Net::co_spawn(Executor, Dialer.Connect(Target), Net::bind_cancellation_slot(
            Cancellation->slot(), [Sink, DialDone, &Result = Request.Result]
            (std::exception_ptr Exception, DialResult Dialed)
            {
                Result.Exception = std::move(Exception);
                Result.Result.emplace(std::move(Dialed));
                Result.TcpConnectReportsAtReturn = Sink->TcpConnectReports;
                (void)DialDone->try_send(boost::system::error_code{});
            }));
        co_await DialDone->async_receive(Net::use_awaitable);
        Request.Result.ResolverShutdownSucceeded = (co_await Resolver->Shutdown()).has_value();
    }
} // namespace

TEST(Dialer, ConnectSuccess)
{
    Net::io_context ioc;
    Tcp::acceptor acceptor(ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    DialAttemptResult Result;
    RunCoro(ioc, RunSuccessfulDial(SuccessfulDialRequest{acceptor, port}, Result));
    EXPECT_TRUE(Result.Failure.Succeeded());
    EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::Success);
    ASSERT_NE(Result.Connection, nullptr);
    (void)Result.Connection->Close();
}

TEST(Dialer, ConnectRefused)
{
    Net::io_context ioc;
    // 找一个未监听端口
    Tcp::acceptor Probe(ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
    const auto port = Probe.local_endpoint().port();
    Probe.close();

    DialAttemptResult Result;
    RunCoro(ioc, RunDialAttempt(DialAttemptRequest{
        ioc.get_executor(), {*Prism::Network::ParseHost("127.0.0.1"), port}}, Result));
    EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::ConnectionRefused);
    EXPECT_TRUE(Result.Failure.Native);
    const auto ExpectedNative = static_cast<std::error_code>(
        Net::error::make_error_code(Net::error::connection_refused));
    EXPECT_EQ(Result.Failure.Native.category(), ExpectedNative.category());
    EXPECT_EQ(Result.Failure.Native.value(), ExpectedNative.value());
    EXPECT_EQ(Result.Connection, nullptr);
}

TEST(Dialer, ConnectTimeout)
{
    Net::io_context ioc;
    Prism::Network::Dialer::DialOptions Options;
    Options.Timeout = std::chrono::milliseconds(100);
    const auto Pending = std::make_shared<PendingConnectState>();
    Options.Connect = [Pending](Prism::Network::Dialer::DialOptions::ConnectRequest Request,
        Net::cancellation_slot Cancellation)
    {
        return WaitForConnectCancellation(Request, Cancellation, Pending);
    };
    DialAttemptResult Result;
    RunCoro(ioc, RunDialAttempt(DialAttemptRequest{
        ioc.get_executor(), {*Prism::Network::ParseHost("127.0.0.1"), 9}, Options}, Result));
    EXPECT_TRUE(Pending->Entered);
    EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::Timeout);
    EXPECT_EQ(Result.Connection, nullptr);
}

TEST(Dialer, ExternalCancellationWaitsForAttemptRetirement)
{
    Net::io_context Ioc;
    Tcp::acceptor Acceptor(Ioc, Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), 0));
    DialerCancellationResult Result;
    RunCoro(Ioc, RunExternalCancellationDial({Acceptor, Result}));

    ASSERT_TRUE(Result.Result.has_value());
    EXPECT_FALSE(Result.Exception);
    EXPECT_TRUE(Result.ResolverShutdownSucceeded);
    if (*Result.Result)
    {
        (void)(**Result.Result)->Close();
    }
    ASSERT_FALSE(*Result.Result);
    EXPECT_EQ(Result.Result->error().Code, Prism::Fault::Code::Canceled);
    EXPECT_FALSE(Result.Result->error().Native);
    EXPECT_EQ(Result.TcpConnectReportsAtReturn, 2U);
    boost::system::error_code CloseError;
    Acceptor.close(CloseError);
    EXPECT_FALSE(CloseError);
}

TEST(Dialer, AttemptRetirementWaitsAfterResultDelivery)
{
    Net::io_context Ioc;
    auto State = std::make_shared<AttemptRetirementWaitState>(Ioc.get_executor());
    RunCoro(Ioc, RunAttemptRetirementWait(std::move(State)));
}

TEST(Dialer, InvalidPortZero)
{
    Net::io_context ioc;
    DialAttemptResult Result;
    RunCoro(ioc, RunDialAttempt(DialAttemptRequest{
        ioc.get_executor(), {*Prism::Network::ParseHost("127.0.0.1"), 0}}, Result));
    // 端口 0 在拨号边界被明确拒绝。
    EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::InvalidArgument);
    EXPECT_EQ(Result.Connection, nullptr);
}

TEST(Dialer, Ipv6Disabled)
{
    Net::io_context ioc;
    Prism::Network::Dialer::DialOptions Options;
    Options.EnableIpv6 = false;
    DialAttemptResult Result;
    RunCoro(ioc, RunDialAttempt(DialAttemptRequest{
        ioc.get_executor(), {*Prism::Network::ParseHost("::1"), 8080}, Options}, Result));
    EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::NotSupported);
    EXPECT_EQ(Result.Connection, nullptr);
}

TEST(Dialer, ConnectEchoTransfer)
{
    Net::io_context ioc;
    Tcp::acceptor acceptor(ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    Prism::Fault::Failure DialFailure;
    SharedTransmission Conn;
    RunCoro(ioc, RunEchoScenario(EchoScenarioRequest{acceptor, port, Conn, DialFailure}));
    EXPECT_TRUE(DialFailure.Succeeded());
    ASSERT_NE(Conn, nullptr);
}
