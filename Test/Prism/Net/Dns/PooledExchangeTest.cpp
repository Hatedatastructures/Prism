/**
 * @file PooledExchangeTest.cpp
 * @brief 连接池交换中的取消、超时与普通失败重拨契约。
 */

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Net/DomainName.hpp>
#include <Prism/Net/Dns/AnswerSet.hpp>
#include <Prism/Net/Dns/AttemptDeadline.hpp>
#include <Prism/Net/Dns/ConnPool.hpp>
#include <Prism/Net/Dns/Detail/Exchange.hpp>
#include <Prism/Net/Dns/QueryIdentity.hpp>
#include <Prism/Net/Dns/Transport.hpp>
#include <Prism/Net/Dns/UpstreamTypes.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/errc.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Dns = Prism::Network::Dns;
    using PooledExchangeResult = Dns::EcResult<Dns::AnswerSet>;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    /** @brief 单次连接池交换的观察结果。 */
    struct PooledExchangeObservation final
    {
        std::exception_ptr TaskFailure;
        boost::system::error_code Failure;
        std::size_t FactoryCalls{0};
        std::size_t ReceiveCalls{0};
        std::size_t CloseCalls{0};
        std::size_t IdleCount{0};
        bool LinkOpen{true};
        bool Succeeded{false};
    };

    /** @brief 可被测试取消的池中连接；未取消时返回预设终态。 */
    class PooledExchangeLink final
    {
    public:
        PooledExchangeLink(Net::any_io_executor Executor, Net::cancellation_signal *Cancellation,
                           boost::system::error_code Failure)
            : Executor_(std::move(Executor)), Cancellation_(Cancellation), Failure_(Failure)
        {
        }

        auto Send(std::span<const std::uint8_t>, Dns::Detail::AttemptDeadline)
            -> Net::awaitable<boost::system::error_code>
        {
            co_return boost::system::error_code{};
        }

        auto Connect(const Net::ip::tcp::endpoint &, const Dns::Server &,
                     Dns::Detail::AttemptDeadline)
            -> Net::awaitable<boost::system::error_code>
        {
            co_return boost::system::error_code{};
        }

        auto Receive(Dns::Detail::AttemptDeadline)
            -> Net::awaitable<Dns::EcResult<std::vector<std::uint8_t>>>
        {
            ++ReceiveCalls_;
            if (Cancellation_)
            {
                auto *Signal = Cancellation_;
                Net::post(Executor_, [Signal] { Signal->emit(Net::cancellation_type::all); });
                Net::steady_timer Watchdog(Executor_);
                Watchdog.expires_after(std::chrono::seconds(5));
                boost::system::error_code ErrorCode;
                co_await Watchdog.async_wait(Net::redirect_error(Net::use_awaitable, ErrorCode));
                co_return std::unexpected(ErrorCode);
            }
            co_return std::unexpected(Failure_);
        }

        auto Close() -> void
        {
            ++CloseCalls_;
            Open_ = false;
        }

        [[nodiscard]] auto IsOpen() const noexcept -> bool
        {
            return Open_;
        }

        [[nodiscard]] auto ReceiveCalls() const noexcept -> std::size_t
        {
            return ReceiveCalls_;
        }

        [[nodiscard]] auto CloseCalls() const noexcept -> std::size_t
        {
            return CloseCalls_;
        }

    private:
        Net::any_io_executor Executor_;
        Net::cancellation_signal *Cancellation_;
        boost::system::error_code Failure_;
        std::size_t ReceiveCalls_{0};
        std::size_t CloseCalls_{0};
        bool Open_{true};
    };

    /** @brief 记录重拨请求并以连接拒绝结束，避免任何公网依赖。 */
    struct RejectingLinkFactory final
    {
        std::size_t *Calls;

        auto operator()(const Net::ip::tcp::endpoint &, const Dns::Server &)
            -> Net::awaitable<Dns::EcResult<std::shared_ptr<PooledExchangeLink>>>
        {
            ++*Calls;
            co_return std::unexpected(
                Net::error::make_error_code(Net::error::connection_refused));
        }
    };

    /** @brief 一次池交换的有界测试输入。 */
    struct PooledExchangeScenario final
    {
        Net::io_context &Context;
        bool CancelOnReceive;
        boost::system::error_code Failure;
        PooledExchangeObservation *Observation;
    };

    /** @brief 保存池交换完成结果并通知等待其退栈的场景协程。 */
    struct PooledExchangeCompletion final
    {
        PooledExchangeObservation *Observation;
        std::shared_ptr<CompletionChannel> Completed;

        auto operator()(std::exception_ptr Failure, PooledExchangeResult Result) -> void
        {
            Observation->TaskFailure = std::move(Failure);
            if (!Observation->TaskFailure)
            {
                Observation->Succeeded = Result.has_value();
                if (!Result)
                {
                    Observation->Failure = Result.error();
                }
            }
            (void)Completed->try_send(boost::system::error_code{});
        }
    };

    /** @brief 运行一次真实 ExchangePooled 模板路径并记录池中链路结果。 */
    auto RunPooledExchangeScenario(PooledExchangeScenario Scenario) -> Net::awaitable<void>
    {
        auto *Observation = Scenario.Observation;
        std::optional<Net::cancellation_signal> Cancellation;
        if (Scenario.CancelOnReceive)
        {
            Cancellation.emplace();
        }
        const auto Executor = Scenario.Context.get_executor();
        auto Link = std::make_shared<PooledExchangeLink>(
            Executor, Cancellation ? &*Cancellation : nullptr, Scenario.Failure);
        Dns::ConnPool<PooledExchangeLink> Pool;
        Pool.Release("dns.example", Link);
        Dns::Server ServerConfig;
        ServerConfig.KeepAlive = true;
        auto Domain = Prism::Network::DomainName::Parse("dns.example");
        if (!Domain)
        {
            co_return;
        }
        const Dns::QueryIdentity Identity(std::move(*Domain), Dns::QueryParameters{.Id = 0x1234});
        Prism::Memory::BytePool AnswerPool(Prism::Memory::BytePoolOptions{.BlockCount = 4});
        const std::array<std::uint8_t, 1> Wire{0x00};
        auto Completed = std::make_shared<CompletionChannel>(Scenario.Context, 1);
        RejectingLinkFactory Factory{&Observation->FactoryCalls};
        Dns::Detail::PooledExchangeRequest<PooledExchangeLink> Request{
            Pool, "dns.example", Net::ip::tcp::endpoint{}, ServerConfig, Wire,
            Dns::CheckedAnswerRequest{Identity, AnswerPool},
            Dns::Detail::AttemptDeadline::FromBudget(std::chrono::seconds(30))};
        Net::co_spawn(
            Executor, Dns::Detail::ExchangePooled(std::move(Request), Factory),
            Net::bind_cancellation_slot(
                Cancellation ? Cancellation->slot() : Net::cancellation_slot{},
                PooledExchangeCompletion{Observation, Completed}));
        (void)co_await Completed->async_receive(Net::use_awaitable);
        Observation->ReceiveCalls = Link->ReceiveCalls();
        Observation->CloseCalls = Link->CloseCalls();
        Observation->IdleCount = Pool.IdleCount();
        Observation->LinkOpen = Link->IsOpen();
    }

    [[nodiscard]] auto RunPooledExchange(const bool CancelOnReceive,
                                         const boost::system::error_code Failure)
        -> PooledExchangeObservation
    {
        Net::io_context Context;
        PooledExchangeObservation Observation;
        std::exception_ptr ScenarioFailure;
        Net::co_spawn(Context,
                      RunPooledExchangeScenario(
                          PooledExchangeScenario{Context, CancelOnReceive, Failure, &Observation}),
                      [&ScenarioFailure](std::exception_ptr Value)
                      { ScenarioFailure = std::move(Value); });
        Context.run();
        if (ScenarioFailure)
        {
            Observation.TaskFailure = std::move(ScenarioFailure);
        }
        return Observation;
    }

    auto ExpectNoRedial(const PooledExchangeObservation &Observation,
                        const boost::system::error_code ExpectedFailure) -> void
    {
        EXPECT_FALSE(Observation.TaskFailure);
        EXPECT_FALSE(Observation.Succeeded);
        EXPECT_EQ(Observation.Failure, ExpectedFailure);
        EXPECT_EQ(Observation.FactoryCalls, 0U);
        EXPECT_EQ(Observation.ReceiveCalls, 1U);
        EXPECT_EQ(Observation.CloseCalls, 1U);
        EXPECT_EQ(Observation.IdleCount, 0U);
        EXPECT_FALSE(Observation.LinkOpen);
    }
} // namespace

TEST(DnsPooledExchange, CancellationAndTimeoutDoNotRedial)
{
    const auto Canceled = RunPooledExchange(true, {});
    ExpectNoRedial(Canceled, Net::error::operation_aborted);

    const auto PrismCanceled = RunPooledExchange(
        false, Prism::make_error_code(Prism::Error::Canceled));
    ExpectNoRedial(PrismCanceled, Prism::make_error_code(Prism::Error::Canceled));

    const auto FaultCanceled = RunPooledExchange(
        false, boost::system::make_error_code(Prism::Fault::Code::Canceled));
    ExpectNoRedial(FaultCanceled, boost::system::make_error_code(Prism::Fault::Code::Canceled));

    const auto GenericCanceled = RunPooledExchange(
        false, boost::system::errc::make_error_code(boost::system::errc::operation_canceled));
    ExpectNoRedial(GenericCanceled,
                   boost::system::errc::make_error_code(boost::system::errc::operation_canceled));

    const auto PrismTimeout = RunPooledExchange(
        false, Prism::make_error_code(Prism::Error::Timeout));
    ExpectNoRedial(PrismTimeout, Prism::make_error_code(Prism::Error::Timeout));

    const auto FaultTimeout = RunPooledExchange(
        false, boost::system::make_error_code(Prism::Fault::Code::Timeout));
    ExpectNoRedial(FaultTimeout, boost::system::make_error_code(Prism::Fault::Code::Timeout));

    const auto AsioTimeout = RunPooledExchange(
        false, Net::error::make_error_code(Net::error::timed_out));
    ExpectNoRedial(AsioTimeout, Net::error::make_error_code(Net::error::timed_out));

    const auto GenericTimeout = RunPooledExchange(
        false, boost::system::errc::make_error_code(boost::system::errc::timed_out));
    ExpectNoRedial(GenericTimeout,
                   boost::system::errc::make_error_code(boost::system::errc::timed_out));
}

TEST(DnsPooledExchange, OrdinaryPooledTransportFailureStillRetriesOnce)
{
    const auto Reset = RunPooledExchange(
        false, Net::error::make_error_code(Net::error::connection_reset));

    EXPECT_FALSE(Reset.TaskFailure);
    EXPECT_FALSE(Reset.Succeeded);
    EXPECT_EQ(Reset.Failure, Net::error::make_error_code(Net::error::connection_refused));
    EXPECT_EQ(Reset.FactoryCalls, 1U);
    EXPECT_EQ(Reset.ReceiveCalls, 1U);
    EXPECT_EQ(Reset.CloseCalls, 1U);
    EXPECT_EQ(Reset.IdleCount, 0U);
    EXPECT_FALSE(Reset.LinkOpen);
}
