/** @file H2MuxEngineRetirementTest.cpp @brief 验证 H2 close 取消仅在完整物理退休后归一化。 */
#include <gtest/gtest.h>

#include <boost/asio.hpp>

#include <atomic>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Protocols/Mux/H2Mux/Http2Dispatch.hpp>
#include <Preview/Protocols/Http2/Session.hpp>
#include <Preview/Transport/Detail/ActivityGroup.hpp>
#include <Preview/Transport/MemoryStream.hpp>

namespace
{
    namespace Net = boost::asio;

    class ScriptedDrainActivity final : public Preview::Contract::CarrierActivity
    {
    public:
        ScriptedDrainActivity(Net::any_io_executor ExecutorValue,
            Preview::Fault::Failure DrainFailureValue)
            : Executor_(std::move(ExecutorValue)), DrainFailure_(DrainFailureValue)
        {
        }

        auto Seal() noexcept -> void override {}
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Executor_; }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return true; }
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            if (DrainFailure_.Failed()) co_return std::unexpected(DrainFailure_);
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

    private:
        Net::any_io_executor Executor_;
        Preview::Fault::Failure DrainFailure_;
    };

    class ScriptedDrainTransmission final : public Preview::Transmission
    {
    public:
        ScriptedDrainTransmission(Net::any_io_executor ExecutorValue,
            const Preview::Fault::Failure DrainFailure)
            : Preview::Transmission(ExecutorValue),
              Activity_(std::make_shared<Preview::Transport::Detail::ActivityGroup>(
                  Preview::Transmission::Activity(),
                  MakeScriptedActivities(std::move(ExecutorValue), DrainFailure)))
        {
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override { return Activity_; }
        [[nodiscard]] auto IsOpen() const -> bool override { return !Closed_.load(std::memory_order_acquire); }

    protected:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        { Preview::Transport::Detail::PostResult(Executor(), std::move(Handler),
              {0U, {Preview::Fault::Code::Canceled}}); }
        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        { Preview::Transport::Detail::PostResult(Executor(), std::move(Handler),
              {0U, {Preview::Fault::Code::Canceled}}); }
        auto StartWriteShutdown(Completion Handler) -> void override
        { Preview::Transport::Detail::PostResult(Executor(), std::move(Handler),
              {0U, {Preview::Fault::Code::Canceled}}); }
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_.store(true, std::memory_order_release);
            return {};
        }
        [[nodiscard]] auto OnCancel() -> ControlResult override { return {}; }

    private:
        [[nodiscard]] static auto MakeScriptedActivities(Net::any_io_executor Executor,
            const Preview::Fault::Failure DrainFailure)
            -> std::vector<std::shared_ptr<Preview::Contract::CarrierActivity>>
        {
            std::vector<std::shared_ptr<Preview::Contract::CarrierActivity>> Activities;
            Activities.push_back(std::make_shared<ScriptedDrainActivity>(
                std::move(Executor), DrainFailure));
            return Activities;
        }

        std::shared_ptr<Preview::Contract::CarrierActivity> Activity_;
        std::atomic<bool> Closed_{false};
    };

    class CanceledWriteTransmission final : public Preview::Transmission
    {
    public:
        explicit CanceledWriteTransmission(Net::any_io_executor Executor)
            : Preview::Transmission(std::move(Executor))
        {
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_.load(std::memory_order_acquire);
        }

    protected:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(
                Executor(), std::move(Handler), {0U, {Preview::Fault::Code::Canceled}});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(
                Executor(), std::move(Handler), {0U, {Preview::Fault::Code::Canceled}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(
                Executor(), std::move(Handler), {0U, {Preview::Fault::Code::Canceled}});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_.store(true, std::memory_order_release);
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        std::atomic<bool> Closed_{false};
    };

    struct EngineDrainOutcome final
    {
        bool DrainSucceeded{false};
        bool EngineRetired{false};
        bool StreamActivityRetired{false};
        bool RawActivityRetired{false};
        std::size_t StreamsRemaining{0U};
        Preview::Fault::Failure DrainFailure;
    };

    auto RunEngineDrain(Net::any_io_executor Executor,
        const bool CloseCancellation, const bool RunCompleted,
        const bool RecordAfterClose = false)
        -> Net::awaitable<EngineDrainOutcome>
    {
        auto [RawEndpoint, PeerEndpoint] = Preview::MakeMemoryPair(Executor);
        auto Raw = std::make_shared<Preview::MemoryStream>(std::move(RawEndpoint));
        auto Peer = std::make_shared<Preview::MemoryStream>(std::move(PeerEndpoint));
        auto State = std::make_shared<Preview::Mux::H2Mux::Http2State>(Raw, 2U);
        auto Stream = std::make_shared<Preview::Mux::H2Mux::Http2Stream>(State, 1);
        State->Streams.emplace(Stream->StreamId(), Stream);
        State->RunCompleted.store(RunCompleted, std::memory_order_release);
        co_await Net::dispatch(State->Strand, Net::use_awaitable);
        if (CloseCancellation)
        {
            State->Close();
            State->RecordCloseCancellation({Preview::Fault::Code::Canceled});
        }
        else
        {
            if (RecordAfterClose) State->Close();
            State->RecordFailure({Preview::Fault::Code::Canceled});
        }

        const auto Drained = co_await State->Drain();
        EngineDrainOutcome Outcome;
        Outcome.DrainSucceeded = Drained.has_value();
        if (!Drained) Outcome.DrainFailure = Drained.error();
        Outcome.EngineRetired = State->Retired.load(std::memory_order_acquire);
        Outcome.StreamActivityRetired = Stream->Activity()->IsRetired();
        Outcome.StreamsRemaining = State->Streams.size();
        (void)Peer->Close();
        co_return Outcome;
    }

    auto RunEngineDrainTest(const bool CloseCancellation, const bool RunCompleted,
        const bool RecordAfterClose = false)
        -> EngineDrainOutcome
    {
        Net::io_context Io;
        EngineDrainOutcome Outcome;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunEngineDrain(
            Io.get_executor(), CloseCancellation, RunCompleted, RecordAfterClose),
            [&Outcome, &Exception](std::exception_ptr Error, EngineDrainOutcome Result)
            {
                Exception = std::move(Error);
                Outcome = std::move(Result);
            });
        Io.run();
        EXPECT_FALSE(Exception);
        return Outcome;
    }

    auto RunCanceledEngineDrain(Net::any_io_executor Executor)
        -> Net::awaitable<EngineDrainOutcome>
    {
        auto [RawEndpoint, PeerEndpoint] = Preview::MakeMemoryPair(Executor);
        auto Raw = std::make_shared<Preview::MemoryStream>(std::move(RawEndpoint));
        auto Peer = std::make_shared<Preview::MemoryStream>(std::move(PeerEndpoint));
        auto State = std::make_shared<Preview::Mux::H2Mux::Http2State>(Raw, 2U);
        State->RunCompleted.store(true, std::memory_order_release);
        boost::system::error_code GateError;
        co_await State->DrainGate->async_receive(
            Net::redirect_error(Net::use_awaitable, GateError));
        if (GateError)
        {
            co_return EngineDrainOutcome{
                false, false, false, false, 0U,
                Preview::Fault::FromNative(static_cast<std::error_code>(GateError))};
        }

        using DrainResult = std::expected<void, Preview::Fault::Failure>;
        auto Completed = std::make_shared<Net::experimental::channel<void(
            boost::system::error_code)>>(State->Strand, 1U);
        Net::cancellation_signal Cancellation;
        EngineDrainOutcome Outcome;
        std::exception_ptr Exception;
        Net::co_spawn(State->Strand, State->Drain(),
            Net::bind_cancellation_slot(Cancellation.slot(),
                [Completed, &Outcome, &Exception](std::exception_ptr Error,
                    DrainResult Result)
                {
                    Exception = std::move(Error);
                    Outcome.DrainSucceeded = Result.has_value();
                    if (!Result) Outcome.DrainFailure = Result.error();
                    (void)Completed->try_send(boost::system::error_code{});
                }));
        co_await Net::post(State->Strand, Net::use_awaitable);
        Cancellation.emit(Net::cancellation_type::all);
        (void)State->DrainGate->try_send(boost::system::error_code{});
        co_await Completed->async_receive(Net::use_awaitable);
        if (Exception) Outcome.DrainSucceeded = false;
        Outcome.EngineRetired = State->Retired.load(std::memory_order_acquire);
        Outcome.RawActivityRetired = Raw->Activity()->IsRetired();
        (void)Peer->Close();
        co_return Outcome;
    }

    auto RunCanceledEngineDrainTest() -> EngineDrainOutcome
    {
        Net::io_context Io;
        EngineDrainOutcome Outcome;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunCanceledEngineDrain(Io.get_executor()),
            [&Outcome, &Exception](std::exception_ptr Error, EngineDrainOutcome Result)
            {
                Exception = std::move(Error);
                Outcome = std::move(Result);
            });
        Io.run();
        EXPECT_FALSE(Exception);
        return Outcome;
    }

    auto RunClosedFlush(Net::any_io_executor Executor)
        -> Net::awaitable<Preview::Mux::H2Mux::Http2State::FlushResult>
    {
        auto [RawEndpoint, PeerEndpoint] = Preview::MakeMemoryPair(Executor);
        auto Raw = std::make_shared<Preview::MemoryStream>(std::move(RawEndpoint));
        auto Peer = std::make_shared<Preview::MemoryStream>(std::move(PeerEndpoint));
        auto State = std::make_shared<Preview::Mux::H2Mux::Http2State>(Raw, 2U);
        boost::system::error_code ConsumeError;
        co_await State->FlushGate->async_receive(
            Net::redirect_error(Net::use_awaitable, ConsumeError));
        if (ConsumeError)
            co_return Preview::Mux::H2Mux::Http2State::FlushResult{
                Preview::Fault::FromNative(static_cast<std::error_code>(ConsumeError)), false};

        auto Completed = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
            State->Strand, 1);
        Preview::Mux::H2Mux::Http2State::FlushResult Result;
        std::exception_ptr Exception;
        Net::co_spawn(State->Strand, State->Flush(),
            [Completed, &Result, &Exception](std::exception_ptr Error,
                Preview::Mux::H2Mux::Http2State::FlushResult Value)
            {
                Exception = std::move(Error);
                Result = std::move(Value);
                (void)Completed->try_send(boost::system::error_code{});
            });
        co_await Net::dispatch(State->Strand, Net::use_awaitable);
        State->Close();
        co_await Completed->async_receive(Net::use_awaitable);
        EXPECT_FALSE(Exception);
        (void)Peer->Close();
        co_return Result;
    }

    struct QueuedStreamControlOutcome final
    {
        bool Prepared{false};
        bool ControlQueuedBeforeClose{false};
        bool ControlCompleted{false};
        bool DrainSucceeded{false};
        bool EngineRetired{false};
        Preview::Fault::Failure FirstFailure{};
    };

    auto FinishQueuedStreamControlState(
        const std::shared_ptr<Preview::Mux::H2Mux::Http2State> &State,
        const std::shared_ptr<Preview::MemoryStream> &Peer)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        co_await Net::dispatch(State->Strand, Net::use_awaitable);
        State->Close();
        State->RunCompleted.store(true, std::memory_order_release);
        (void)State->RunCompletionNotify.try_send(boost::system::error_code{});
        const auto Result = co_await State->Drain();
        (void)Peer->Close();
        co_return Result;
    }

    struct QueuedStreamControlFixture final
    {
        using StateType = Preview::Mux::H2Mux::Http2State;
        using StreamType = Preview::Mux::H2Mux::Http2Stream;

        QueuedStreamControlFixture(
            std::shared_ptr<StateType> StateValue,
            const bool ResetStreamValue,
            const bool PrecloseSessionOnlyValue)
            : State(std::move(StateValue)), ResetStream(ResetStreamValue),
              PrecloseSessionOnly(PrecloseSessionOnlyValue)
        {
        }

        auto Prepare() -> void
        {
            State->Session = std::make_shared<Preview::Http2::Session>(State->Strand, true);
            const auto WeakState = std::weak_ptr<StateType>(State);
            State->Session->OnHeaders = [WeakState](const std::int32_t Id,
                const Preview::Http2::HeaderList &Headers, const bool EndStream)
            {
                if (const auto Value = WeakState.lock()) Value->OnHeaders(Id, Headers, EndStream);
            };
            State->Session->OnStreamClose = [WeakState](
                const Preview::Http2::StreamReceiveClosure &Closure)
            {
                if (const auto Value = WeakState.lock()) Value->OnRemoteClose(Closure);
            };
            Client = std::make_shared<Preview::Http2::Session>(State->Strand, false);
            Client->SendSettings();
            const auto StreamId = Client->OpenStream(
                Preview::Http2::HeaderList{{":method", "CONNECT"}}, !PrecloseSessionOnly);
            std::vector<std::byte> Wire;
            std::error_code FeedError;
            if (!StreamId || !Client->Collect(Wire) ||
                !State->Session->Feed(Wire, FeedError) || FeedError)
                return;
            const auto Iterator = State->Streams.find(*StreamId);
            if (Iterator == State->Streams.end()) return;
            Stream = Iterator->second;
            if (PrecloseSessionOnly)
            {
                if (!State->Session->ResetStream(
                    *StreamId, Preview::Http2::ErrorCancel)) return;
            }
            else if (State->Session->SubmitData(*StreamId, {}, true) !=
                Preview::Http2::SubmitDataStatus::Accepted) return;
            ControlAccepted = static_cast<bool>(ResetStream ? Stream->Cancel() : Stream->Close());
            Prepared = true;
        }

        std::shared_ptr<StateType> State;
        std::shared_ptr<Preview::Http2::Session> Client;
        std::shared_ptr<StreamType> Stream;
        bool ResetStream{false};
        bool PrecloseSessionOnly{false};
        bool Prepared{false};
        bool ControlAccepted{false};
    };

    auto RunQueuedStreamControl(
        const bool RequestRootClose,
        const bool ResetStream = false,
        const bool PrecloseSessionOnly = false) -> QueuedStreamControlOutcome
    {
        namespace H2Mux = Preview::Mux::H2Mux;
        Net::io_context Io;
        auto [RawEndpoint, PeerEndpoint] = Preview::MakeMemoryPair(Io.get_executor());
        auto Raw = std::make_shared<Preview::MemoryStream>(std::move(RawEndpoint));
        auto Peer = std::make_shared<Preview::MemoryStream>(std::move(PeerEndpoint));
        auto State = std::make_shared<H2Mux::Http2State>(Raw, 2U);
        QueuedStreamControlFixture Fixture(State, ResetStream, PrecloseSessionOnly);
        Net::post(State->Strand, [&Fixture] { Fixture.Prepare(); });
        if (Io.run_one() == 0U) return {};

        QueuedStreamControlOutcome Outcome;
        Outcome.Prepared = Fixture.Prepared && Fixture.ControlAccepted &&
            static_cast<bool>(Fixture.Stream);
        for (std::size_t Attempt = 0U; Outcome.Prepared && Attempt < 16U &&
             !Fixture.Stream->HasPendingControl(); ++Attempt)
        {
            if (Io.run_one() == 0U) break;
        }
        Outcome.ControlQueuedBeforeClose = Fixture.Stream && Fixture.Stream->HasPendingControl();
        if (RequestRootClose && Outcome.ControlQueuedBeforeClose)
            State->CloseRequested.store(true, std::memory_order_release);
        for (std::size_t Attempt = 0U; Outcome.ControlQueuedBeforeClose && Attempt < 16U &&
             Fixture.Stream->HasPendingControl(); ++Attempt)
        {
            if (Io.run_one() == 0U) break;
        }
        Outcome.ControlCompleted = Fixture.Stream && !Fixture.Stream->HasPendingControl();
        Outcome.FirstFailure = State->FirstFailure.Load();

        std::optional<std::expected<void, Preview::Fault::Failure>> DrainResult;
        std::exception_ptr DrainException;
        Io.restart();
        Net::co_spawn(Io, FinishQueuedStreamControlState(State, Peer),
            [&DrainResult, &DrainException](std::exception_ptr Error,
                std::expected<void, Preview::Fault::Failure> Result)
            {
                DrainException = std::move(Error);
                DrainResult.emplace(std::move(Result));
            });
        Io.run();
        EXPECT_FALSE(DrainException);
        EXPECT_TRUE(DrainResult.has_value());
        Outcome.DrainSucceeded = DrainResult && DrainResult->has_value();
        Outcome.EngineRetired = State->Retired.load(std::memory_order_acquire);
        Outcome.FirstFailure = State->FirstFailure.Load();
        return Outcome;
    }

    auto RunRawDrainTest(const Preview::Fault::Failure DrainFailure)
        -> EngineDrainOutcome
    {
        Net::io_context Io;
        EngineDrainOutcome Outcome;
        std::exception_ptr Exception;
        const auto Work = [&]() -> Net::awaitable<void>
        {
            auto Raw = std::make_shared<ScriptedDrainTransmission>(
                Io.get_executor(), DrainFailure);
            auto State = std::make_shared<Preview::Mux::H2Mux::Http2State>(Raw, 2U);
            State->RunCompleted.store(true, std::memory_order_release);
            const auto Drained = co_await State->Drain();
            Outcome.DrainSucceeded = Drained.has_value();
            if (!Drained) Outcome.DrainFailure = Drained.error();
            Outcome.EngineRetired = State->Retired.load(std::memory_order_acquire);
            Outcome.RawActivityRetired = Raw->Activity()->IsRetired();
            Outcome.StreamsRemaining = State->Streams.size();
        };
        Net::co_spawn(Io, Work(), [&Exception](std::exception_ptr Error)
        {
            Exception = std::move(Error);
        });
        Io.run();
        EXPECT_FALSE(Exception);
        return Outcome;
    }

    auto RunCanceledWriteFlush(Net::any_io_executor Executor, const bool CloseRequested)
        -> Net::awaitable<Preview::Mux::H2Mux::Http2State::FlushResult>
    {
        auto Raw = std::make_shared<CanceledWriteTransmission>(std::move(Executor));
        auto State = std::make_shared<Preview::Mux::H2Mux::Http2State>(Raw, 2U);
        State->Session = std::make_shared<Preview::Http2::Session>(State->Strand, true);
        State->Session->SendSettings();
        // 公开 Close 先发布意图，再由 strand 执行 State::Close。
        State->CloseRequested.store(CloseRequested, std::memory_order_release);
        co_return co_await State->Flush();
    }

    auto RunCanceledWriteFlushTest(const bool CloseRequested)
        -> Preview::Mux::H2Mux::Http2State::FlushResult
    {
        Net::io_context Io;
        using Result = Preview::Mux::H2Mux::Http2State::FlushResult;
        Result FlushResult;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunCanceledWriteFlush(Io.get_executor(), CloseRequested),
            [&FlushResult, &Exception](std::exception_ptr Error, Result Value)
            {
                Exception = std::move(Error);
                FlushResult = std::move(Value);
            });
        Io.run();
        EXPECT_FALSE(Exception);
        return FlushResult;
    }

    TEST(H2MuxEngineRetirement, CloseGateCanceledIsIgnoredAfterPhysicalRetirement)
    {
        const auto Outcome = RunEngineDrainTest(true, true);

        EXPECT_TRUE(Outcome.DrainSucceeded);
        EXPECT_EQ(Outcome.DrainFailure.Code, Preview::Fault::Code::Success);
        EXPECT_TRUE(Outcome.EngineRetired);
        EXPECT_TRUE(Outcome.StreamActivityRetired);
        EXPECT_EQ(Outcome.StreamsRemaining, 0U);
    }

    TEST(H2MuxEngineRetirement, DrainCompletesAfterItsCallerIsCanceled)
    {
        const auto Outcome = RunCanceledEngineDrainTest();

        EXPECT_TRUE(Outcome.DrainSucceeded);
        EXPECT_EQ(Outcome.DrainFailure.Code, Preview::Fault::Code::Success);
        EXPECT_TRUE(Outcome.EngineRetired);
        EXPECT_TRUE(Outcome.RawActivityRetired);
    }

    TEST(H2MuxEngineRetirement, CancellationBeforeCloseRemainsFailureAfterRetirement)
    {
        const auto Outcome = RunEngineDrainTest(false, true);

        EXPECT_FALSE(Outcome.DrainSucceeded);
        EXPECT_EQ(Outcome.DrainFailure.Code, Preview::Fault::Code::Canceled);
        EXPECT_TRUE(Outcome.EngineRetired);
        EXPECT_TRUE(Outcome.StreamActivityRetired);
        EXPECT_EQ(Outcome.StreamsRemaining, 0U);
    }

    TEST(H2MuxEngineRetirement, UnmarkedCancellationAfterCloseRemainsFailure)
    {
        const auto Outcome = RunEngineDrainTest(false, true, true);

        EXPECT_FALSE(Outcome.DrainSucceeded);
        EXPECT_EQ(Outcome.DrainFailure.Code, Preview::Fault::Code::Canceled);
        EXPECT_TRUE(Outcome.EngineRetired);
        EXPECT_TRUE(Outcome.StreamActivityRetired);
        EXPECT_EQ(Outcome.StreamsRemaining, 0U);
    }

    TEST(H2MuxEngineRetirement, CloseGateCanceledIsNotIgnoredWithoutRunRetirement)
    {
        const auto Outcome = RunEngineDrainTest(true, false);

        EXPECT_FALSE(Outcome.DrainSucceeded);
        EXPECT_EQ(Outcome.DrainFailure.Code, Preview::Fault::Code::Canceled);
        EXPECT_FALSE(Outcome.EngineRetired);
        EXPECT_TRUE(Outcome.StreamActivityRetired);
        EXPECT_EQ(Outcome.StreamsRemaining, 0U);
    }

    TEST(H2MuxEngineRetirement, ClosingFlushGateProducesTaggedCancellation)
    {
        Net::io_context Io;
        Preview::Mux::H2Mux::Http2State::FlushResult Result;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunClosedFlush(Io.get_executor()),
            [&Result, &Exception](std::exception_ptr Error,
                Preview::Mux::H2Mux::Http2State::FlushResult Value)
            {
                Exception = std::move(Error);
                Result = std::move(Value);
            });
        Io.run();

        EXPECT_FALSE(Exception);
        EXPECT_FALSE(Result);
        EXPECT_EQ(Result.Error.Code, Preview::Fault::Code::Canceled);
        EXPECT_TRUE(Result.CloseCanceled);
    }

    TEST(H2MuxEngineRetirement, QueuedFinIsSkippedAfterRootCloseRequest)
    {
        const auto Outcome = RunQueuedStreamControl(true);

        EXPECT_TRUE(Outcome.Prepared);
        EXPECT_TRUE(Outcome.ControlQueuedBeforeClose);
        EXPECT_TRUE(Outcome.ControlCompleted);
        EXPECT_EQ(Outcome.FirstFailure.Code, Preview::Fault::Code::Success);
        EXPECT_TRUE(Outcome.DrainSucceeded);
        EXPECT_TRUE(Outcome.EngineRetired);
    }

    TEST(H2MuxEngineRetirement, ClosedFinWithoutRootCloseRemainsConnectionAborted)
    {
        const auto Outcome = RunQueuedStreamControl(false);

        EXPECT_TRUE(Outcome.Prepared);
        EXPECT_TRUE(Outcome.ControlQueuedBeforeClose);
        EXPECT_TRUE(Outcome.ControlCompleted);
        EXPECT_EQ(Outcome.FirstFailure.Code, Preview::Fault::Code::ConnectionAborted);
        EXPECT_FALSE(Outcome.DrainSucceeded);
        EXPECT_TRUE(Outcome.EngineRetired);
    }

    TEST(H2MuxEngineRetirement, ResetAfterRemoteStreamClosureDoesNotFailConnection)
    {
        const auto Outcome = RunQueuedStreamControl(false, true);

        EXPECT_TRUE(Outcome.Prepared);
        EXPECT_TRUE(Outcome.ControlQueuedBeforeClose);
        EXPECT_TRUE(Outcome.ControlCompleted);
        EXPECT_EQ(Outcome.FirstFailure.Code, Preview::Fault::Code::Success);
        EXPECT_TRUE(Outcome.DrainSucceeded);
        EXPECT_TRUE(Outcome.EngineRetired);
    }

    TEST(H2MuxEngineRetirement, ClosedResetWithoutRemoteClosureRemainsConnectionAborted)
    {
        const auto Outcome = RunQueuedStreamControl(false, true, true);

        EXPECT_TRUE(Outcome.Prepared);
        EXPECT_TRUE(Outcome.ControlQueuedBeforeClose);
        EXPECT_TRUE(Outcome.ControlCompleted);
        EXPECT_EQ(Outcome.FirstFailure.Code, Preview::Fault::Code::ConnectionAborted);
        EXPECT_FALSE(Outcome.DrainSucceeded);
        EXPECT_TRUE(Outcome.EngineRetired);
    }

    TEST(H2MuxEngineRetirement, UnmarkedRawWriteCancellationRemainsFailure)
    {
        const auto Result = RunCanceledWriteFlushTest(false);

        EXPECT_EQ(Result.Error.Code, Preview::Fault::Code::Canceled);
        EXPECT_FALSE(Result.CloseCanceled);
    }

    TEST(H2MuxEngineRetirement, CloseMarkedRawWriteCancellationIsTagged)
    {
        const auto Result = RunCanceledWriteFlushTest(true);

        EXPECT_EQ(Result.Error.Code, Preview::Fault::Code::Canceled);
        EXPECT_TRUE(Result.CloseCanceled);
    }

    TEST(H2MuxEngineRetirement, RawDrainCancellationDoesNotErasePhysicalReceiptOrFailure)
    {
        const auto Outcome = RunRawDrainTest(
            {Preview::Fault::Code::Canceled});

        EXPECT_FALSE(Outcome.DrainSucceeded);
        EXPECT_EQ(Outcome.DrainFailure.Code, Preview::Fault::Code::Canceled);
        EXPECT_TRUE(Outcome.EngineRetired);
        EXPECT_TRUE(Outcome.RawActivityRetired);
        EXPECT_EQ(Outcome.StreamsRemaining, 0U);
    }

    TEST(H2MuxEngineRetirement, RawIoErrorRemainsFailureAfterPhysicalRetirement)
    {
        const auto Outcome = RunRawDrainTest(
            {Preview::Fault::Code::IoError});

        EXPECT_FALSE(Outcome.DrainSucceeded);
        EXPECT_EQ(Outcome.DrainFailure.Code, Preview::Fault::Code::IoError);
        EXPECT_TRUE(Outcome.EngineRetired);
        EXPECT_TRUE(Outcome.RawActivityRetired);
        EXPECT_EQ(Outcome.StreamsRemaining, 0U);
    }
}
