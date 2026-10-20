/**
 * @file DatagramRelayCloseTest.cpp
 * @brief 共用数据报 relay 区分正常关闭与显式取消的回归测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Protocols/Common/DatagramRelay.hpp>
#include <Prism/Protocols/Common/DatagramRelayPump.hpp>
#include <Prism/Protocols/Common/ProtocolActivity.hpp>

namespace
{
    namespace Net = boost::asio;
    using Failure = Prism::Fault::Failure;
    using Result = std::expected<void, Failure>;
    using Udp = Net::ip::udp;
    using Signal = Net::experimental::channel<void(boost::system::error_code)>;

    struct BlockingWireState final
    {
        explicit BlockingWireState(Net::any_io_executor Executor)
            : ReceiveStarted(Executor, 1), ResolverStarted(Executor, 1),
              ReceiveBlock(Executor), ResolverBlock(std::move(Executor))
        {
            ReceiveBlock.expires_after(std::chrono::minutes(5));
            ResolverBlock.expires_after(std::chrono::minutes(5));
        }

        Signal ReceiveStarted;
        Signal ResolverStarted;
        Net::steady_timer ReceiveBlock;
        Net::steady_timer ResolverBlock;
        bool EmitPacket{false};
        bool NativeCancellationOnClose{false};
        bool PacketDelivered{false};
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity;
        std::atomic<std::size_t> CancelCalls{0};
        std::atomic<std::size_t> CloseCalls{0};
    };

    /** @brief Drain 返回取消，但独立物理回执已确认 owner 退休。 */
    class CanceledRetiredActivity final : public Prism::Contract::CarrierActivity
    {
    public:
        explicit CanceledRetiredActivity(Net::any_io_executor Executor)
            : Executor_(std::move(Executor))
        {
        }

        auto Seal() noexcept -> void override
        {
            Sealed_.store(true, std::memory_order_release);
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Sealed_.load(std::memory_order_acquire) &&
                   Retired_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Failure>> override
        {
            Seal();
            Retired_.store(true, std::memory_order_release);
            co_return std::unexpected(Failure{Prism::Fault::Code::Canceled});
        }

    private:
        Net::any_io_executor Executor_;
        std::atomic<bool> Sealed_{false};
        std::atomic<bool> Retired_{false};
    };

    /** @brief 关闭时让挂起 Receive 返回原生 operation_aborted 的 wire。 */
    class BlockingWire final
    {
    public:
        BlockingWire(std::shared_ptr<BlockingWireState> State,
                     Net::any_io_executor Executor)
            : State_(std::move(State)),
              Activity_(State_->Activity ? State_->Activity :
                  std::make_shared<Prism::Protocols::ProtocolActivity>(
                      std::move(Executor)))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Activity_->Executor();
        }

        [[nodiscard]] auto CarrierActivities() const
            -> std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>>
        {
            return {Activity_};
        }

        [[nodiscard]] auto Validate() const noexcept -> Prism::Fault::Code
        {
            return Prism::Fault::Code::Success;
        }

        [[nodiscard]] auto Receive(Prism::Protocols::DatagramPacket& Packet)
            -> Net::awaitable<Result>
        {
            (void)State_->ReceiveStarted.try_send(boost::system::error_code{});
            if (State_->EmitPacket && !State_->PacketDelivered)
            {
                const auto Host = Prism::Network::ParseHost("127.0.0.1");
                if (!Host) co_return std::unexpected(Host.error());
                Packet.Target = Prism::Network::Target{*Host, 53};
                Packet.Payload = {0x5a};
                State_->PacketDelivered = true;
                co_return Result{};
            }
            boost::system::error_code Error;
            co_await State_->ReceiveBlock.async_wait(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error == Net::error::operation_aborted)
            {
                if (State_->NativeCancellationOnClose)
                {
                    co_return std::unexpected(Failure{
                        Prism::Fault::Code::IoError,
                        std::make_error_code(std::errc::operation_canceled)});
                }
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
            }
            co_return std::unexpected(Failure{Prism::Fault::Code::Timeout});
        }

        [[nodiscard]] auto Send(const Udp::endpoint&,
                                std::span<const std::uint8_t>) -> Net::awaitable<Result>
        {
            co_return Result{};
        }

        [[nodiscard]] auto Cancel() noexcept -> Result
        {
            State_->CancelCalls.fetch_add(1, std::memory_order_relaxed);
            try
            {
                (void)State_->ReceiveBlock.cancel();
            }
            catch (const boost::system::system_error& Error)
            {
                return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error.code())));
            }
            return {};
        }

        [[nodiscard]] auto Close() noexcept -> Result
        {
            State_->CloseCalls.fetch_add(1, std::memory_order_relaxed);
            try
            {
                (void)State_->ReceiveBlock.cancel();
            }
            catch (const boost::system::system_error& Error)
            {
                return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error.code())));
            }
            return {};
        }

    private:
        std::shared_ptr<BlockingWireState> State_;
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity_;
    };

    using Relay = Prism::Protocols::DatagramRelay<BlockingWire>;

    struct RelayCompletion final
    {
        explicit RelayCompletion(Net::any_io_executor Executor)
            : Finished(std::move(Executor), 1)
        {
        }

        Signal Finished;
        Result Value{std::unexpected(Failure{Prism::Fault::Code::Blocked})};
        std::exception_ptr Exception;
    };

    struct RelayScenario final
    {
        std::shared_ptr<Prism::Contract::CarrierActivity> CarrierActivity;
        bool ReceiveStarted{false};
        bool RunFinished{false};
        bool Retired{false};
        bool RunSucceeded{false};
        bool NativeCancellationOnClose{false};
        Prism::Fault::Code RunFailure{Prism::Fault::Code::Success};
        std::size_t CancelCalls{0};
        std::size_t CloseCalls{0};
        std::exception_ptr Exception;
    };

    auto RunRelayScenario(Net::io_context& Io, const bool ExplicitCancel,
                          RelayScenario& Scenario) -> Net::awaitable<void>
    {
        auto State = std::make_shared<BlockingWireState>(Io.get_executor());
        State->NativeCancellationOnClose = Scenario.NativeCancellationOnClose;
        State->Activity = Scenario.CarrierActivity;
        auto Protocol = std::make_shared<Relay>(
            BlockingWire(State, Io.get_executor()), Relay::Options{});
        const auto Activity = Protocol->Activity();
        auto Completion = std::make_shared<RelayCompletion>(Io.get_executor());
        Net::co_spawn(Io, Protocol->Run(),
            [Completion](std::exception_ptr Error, Result Value)
            {
                Completion->Exception = std::move(Error);
                Completion->Value = std::move(Value);
                (void)Completion->Finished.try_send(boost::system::error_code{});
            });

        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Watchdog(Io.get_executor());
        boost::system::error_code Error;
        Watchdog.expires_after(std::chrono::seconds(3));
        Error.clear();
        const auto Started = co_await (
            State->ReceiveStarted.async_receive(
                Net::redirect_error(Net::use_awaitable, Error)) ||
            Watchdog.async_wait(Net::use_awaitable));
        Watchdog.cancel();
        Scenario.ReceiveStarted = Started.index() == 0U && !Error;

        if (Scenario.ReceiveStarted && ExplicitCancel) Protocol->Cancel();
        else Protocol->Close();
        Watchdog.expires_after(std::chrono::seconds(3));
        Error.clear();
        auto Finished = co_await (
            Completion->Finished.async_receive(
                Net::redirect_error(Net::use_awaitable, Error)) ||
            Watchdog.async_wait(Net::use_awaitable));
        Watchdog.cancel();
        Scenario.RunFinished = Finished.index() == 0U && !Error;

        if (Scenario.RunFinished)
        {
            Scenario.Exception = Completion->Exception;
            Scenario.RunSucceeded = static_cast<bool>(Completion->Value);
            if (!Completion->Value)
                Scenario.RunFailure = Completion->Value.error().Code;
            Scenario.Retired = Activity->IsRetired();
        }
        Scenario.CancelCalls = State->CancelCalls.load(std::memory_order_relaxed);
        Scenario.CloseCalls = State->CloseCalls.load(std::memory_order_relaxed);
        co_return;
    }

    auto RunCoroutine(Net::io_context& Io, Net::awaitable<void> Scenario) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Io, std::move(Scenario),
            [&Exception](std::exception_ptr Value) { Exception = std::move(Value); });
        Io.run();
        if (Exception) std::rethrow_exception(Exception);
    }

    /** @brief 驱动显式 Close 后的 Drain 与 Run 顺序，并记录真实退休和控制次数。 */
    struct CloseBeforeRunInput final
    {
        std::shared_ptr<Relay> Protocol;
        std::shared_ptr<BlockingWireState> Wire;
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity;
        RelayScenario &Scenario;
    };

    [[nodiscard]] auto RunCloseBeforeRun(CloseBeforeRunInput Input)
        -> Net::awaitable<void>
    {
        Input.Protocol->Close();
        const auto Closed = co_await Input.Activity->Drain();
        EXPECT_TRUE(Closed);
        const auto Run = co_await Input.Protocol->Run();
        EXPECT_TRUE(Run);
        Input.Scenario.Retired = Input.Activity->IsRetired();
        Input.Scenario.CancelCalls = Input.Wire->CancelCalls.load(std::memory_order_relaxed);
        Input.Scenario.CloseCalls = Input.Wire->CloseCalls.load(std::memory_order_relaxed);
    }

    /** @brief 在指定 wire 上保持 resolver 挂起，直到关闭或原有超时路径结束。 */
    class BlockingResolver final
    {
    public:
        explicit BlockingResolver(std::shared_ptr<BlockingWireState> State)
            : State_(std::move(State))
        {
        }

        [[nodiscard]] auto operator()(Prism::Network::Target) const
            -> Net::awaitable<std::expected<Udp::endpoint, Failure>>
        {
            (void)State_->ResolverStarted.try_send(boost::system::error_code{});
            boost::system::error_code Error;
            co_await State_->ResolverBlock.async_wait(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
            co_return std::unexpected(Failure{Prism::Fault::Code::Timeout});
        }

    private:
        std::shared_ptr<BlockingWireState> State_;
    };

    /** @brief Resolver-close 测试协程所需的资源与结果引用。 */
    struct ResolverCloseInput final
    {
        Net::io_context &Io;
        RelayScenario &Scenario;
        std::shared_ptr<BlockingWireState> Wire;
        std::shared_ptr<Relay> Protocol;
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity;
        std::shared_ptr<RelayCompletion> Completion;
    };

    [[nodiscard]] auto RunResolverClose(ResolverCloseInput Input)
        -> Net::awaitable<void>
    {
        const auto Completion = Input.Completion;
        Net::co_spawn(Input.Io, Input.Protocol->Run(),
            [Completion](std::exception_ptr Error, Result Value)
            {
                Completion->Exception = std::move(Error);
                Completion->Value = std::move(Value);
                (void)Completion->Finished.try_send(
                    boost::system::error_code{});
            });

        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Watchdog(Input.Io.get_executor());
        boost::system::error_code Error;
        Watchdog.expires_after(std::chrono::seconds(3));
        const auto ResolveRace = co_await (
            Input.Wire->ResolverStarted.async_receive(
                Net::redirect_error(Net::use_awaitable, Error)) ||
            Watchdog.async_wait(Net::use_awaitable));
        Input.Scenario.ReceiveStarted = ResolveRace.index() == 0U && !Error;
        Input.Protocol->Close();
        Watchdog.expires_after(std::chrono::seconds(3));
        Error.clear();
        const auto FinishRace = co_await (
            Completion->Finished.async_receive(
                Net::redirect_error(Net::use_awaitable, Error)) ||
            Watchdog.async_wait(Net::use_awaitable));
        Watchdog.cancel();
        Input.Scenario.RunFinished = FinishRace.index() == 0U && !Error;
        if (Input.Scenario.RunFinished)
        {
            Input.Scenario.RunSucceeded = static_cast<bool>(Completion->Value);
            if (!Completion->Value)
                Input.Scenario.RunFailure = Completion->Value.error().Code;
            Input.Scenario.Exception = Completion->Exception;
            Input.Scenario.Retired = Input.Activity->IsRetired();
        }
        co_return;
    }

    TEST(DatagramRelayClose, NormalCloseDoesNotReportExplicitCancellation)
    {
        Net::io_context Io;
        RelayScenario Scenario;
        RunCoroutine(Io, RunRelayScenario(Io, false, Scenario));

        EXPECT_TRUE(Scenario.ReceiveStarted);
        EXPECT_TRUE(Scenario.RunFinished);
        EXPECT_TRUE(Scenario.RunSucceeded);
        EXPECT_EQ(Scenario.RunFailure, Prism::Fault::Code::Success);
        EXPECT_TRUE(Scenario.Retired);
        EXPECT_FALSE(Scenario.Exception);
        EXPECT_EQ(Scenario.CancelCalls, 0U);
        EXPECT_EQ(Scenario.CloseCalls, 1U);
    }

    TEST(DatagramRelayClose, NormalCloseNormalizesNativeOperationCanceled)
    {
        Net::io_context Io;
        RelayScenario Scenario;
        Scenario.NativeCancellationOnClose = true;
        RunCoroutine(Io, RunRelayScenario(Io, false, Scenario));

        EXPECT_TRUE(Scenario.ReceiveStarted);
        EXPECT_TRUE(Scenario.RunFinished);
        EXPECT_TRUE(Scenario.RunSucceeded);
        EXPECT_TRUE(Scenario.Retired);
        EXPECT_FALSE(Scenario.Exception);
        EXPECT_EQ(Scenario.CancelCalls, 0U);
        EXPECT_EQ(Scenario.CloseCalls, 1U);
    }

    TEST(DatagramRelayClose, ExplicitCancelRemainsCanceledAfterPhysicalRetirement)
    {
        Net::io_context Io;
        RelayScenario Scenario;
        RunCoroutine(Io, RunRelayScenario(Io, true, Scenario));

        EXPECT_TRUE(Scenario.ReceiveStarted);
        EXPECT_TRUE(Scenario.RunFinished);
        EXPECT_FALSE(Scenario.RunSucceeded);
        EXPECT_EQ(Scenario.RunFailure, Prism::Fault::Code::Canceled);
        EXPECT_TRUE(Scenario.Retired);
        EXPECT_FALSE(Scenario.Exception);
        EXPECT_EQ(Scenario.CancelCalls, 1U);
        EXPECT_EQ(Scenario.CloseCalls, 1U);
    }

    TEST(DatagramRelayClose, AcceptsCanceledCarrierDrainAfterPhysicalRetirement)
    {
        Net::io_context CloseIo;
        RelayScenario CloseScenario;
        CloseScenario.CarrierActivity = std::make_shared<CanceledRetiredActivity>(
            CloseIo.get_executor());
        RunCoroutine(CloseIo, RunRelayScenario(CloseIo, false, CloseScenario));

        EXPECT_TRUE(CloseScenario.ReceiveStarted);
        EXPECT_TRUE(CloseScenario.RunFinished);
        EXPECT_TRUE(CloseScenario.RunSucceeded);
        EXPECT_TRUE(CloseScenario.Retired);
        EXPECT_FALSE(CloseScenario.Exception);

        Net::io_context CancelIo;
        RelayScenario CancelScenario;
        CancelScenario.CarrierActivity = std::make_shared<CanceledRetiredActivity>(
            CancelIo.get_executor());
        RunCoroutine(CancelIo, RunRelayScenario(CancelIo, true, CancelScenario));

        EXPECT_TRUE(CancelScenario.ReceiveStarted);
        EXPECT_TRUE(CancelScenario.RunFinished);
        EXPECT_FALSE(CancelScenario.RunSucceeded);
        EXPECT_EQ(CancelScenario.RunFailure, Prism::Fault::Code::Canceled);
        EXPECT_TRUE(CancelScenario.Retired);
        EXPECT_FALSE(CancelScenario.Exception);
    }

    TEST(DatagramRelayClose, CloseBeforeRunRemainsSuccessfulAfterRetirement)
    {
        Net::io_context Io;
        RelayScenario Scenario;
        auto State = std::make_shared<BlockingWireState>(Io.get_executor());
        auto Protocol = std::make_shared<Relay>(
            BlockingWire(State, Io.get_executor()), Relay::Options{});
        const auto Activity = Protocol->Activity();

        RunCoroutine(Io, RunCloseBeforeRun(CloseBeforeRunInput{
            Protocol, State, Activity, Scenario}));

        EXPECT_TRUE(Scenario.Retired);
        EXPECT_EQ(Scenario.CancelCalls, 0U);
        EXPECT_EQ(Scenario.CloseCalls, 1U);
    }

    TEST(DatagramRelayClose, CloseInterruptsResolverWait)
    {
        Net::io_context Io;
        RelayScenario Scenario;
        auto State = std::make_shared<BlockingWireState>(Io.get_executor());
        State->EmitPacket = true;
        State->ResolverBlock.expires_after(std::chrono::seconds(4));
        Relay::Options Options;
        Options.Services.IdleTimeout = std::chrono::milliseconds::zero();
        Options.Services.Resolve = BlockingResolver{State};
        auto Protocol = std::make_shared<Relay>(
            BlockingWire(State, Io.get_executor()), std::move(Options));
        const auto Activity = Protocol->Activity();
        auto Completion = std::make_shared<RelayCompletion>(Io.get_executor());
        RunCoroutine(Io, RunResolverClose(ResolverCloseInput{
            Io, Scenario, State, Protocol, Activity, Completion}));

        EXPECT_TRUE(Scenario.ReceiveStarted);
        EXPECT_TRUE(Scenario.RunFinished);
        EXPECT_TRUE(Scenario.RunSucceeded);
        EXPECT_TRUE(Scenario.Retired);
        EXPECT_FALSE(Scenario.Exception);
        EXPECT_EQ(State->CancelCalls.load(std::memory_order_relaxed), 0U);
        EXPECT_EQ(State->CloseCalls.load(std::memory_order_relaxed), 1U);
    }

} // namespace
