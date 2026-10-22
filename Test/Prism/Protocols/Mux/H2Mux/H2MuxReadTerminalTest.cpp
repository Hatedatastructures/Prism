/**
 * @file H2MuxReadTerminalTest.cpp
 * @brief H2Mux 在读取同时收到数据和连接终态时的 stream 交付契约。
 */
#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Mux/H2Mux/Http2Server.hpp>
#include <Prism/Protocols/Mux/H2Mux/Http2State.hpp>
#include <Prism/Protocols/Mux/H2Mux/Http2Stream.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;
    using TestSignal = Net::experimental::channel<void(boost::system::error_code)>;
    using Failure = Prism::Fault::Failure;

    auto RecordFirstFailure(Failure &First, Failure Candidate) -> void
    { if (First.Succeeded() && Candidate.Failed()) First = std::move(Candidate); }

    struct WatchdogCompletion final
    {
        explicit WatchdogCompletion(Net::any_io_executor Executor)
            : Done(std::move(Executor), 1U) {}
        auto Record(Failure Candidate) -> void
        { RecordFirstFailure(FirstFailure, std::move(Candidate)); }
        auto Complete() -> void
        { (void)Done.try_send(boost::system::error_code{}); }
        auto RecordError(const boost::system::error_code &Error) -> void
        {
            if (Error && Error != Net::error::operation_aborted)
                Record(Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
        }
        TestSignal Done;
        Failure FirstFailure;
    };

    auto FailureFromException(std::exception_ptr Exception) noexcept -> Failure
    {
        if (!Exception) return {};
        try
        {
            std::rethrow_exception(std::move(Exception));
        }
        catch (const boost::system::system_error &Error)
        { return Prism::Fault::FromNative(static_cast<std::error_code>(Error.code())); }
        catch (const std::system_error &Error)
        { return Prism::Fault::FromNative(Error.code()); }
        catch (...)
        { return Failure{Prism::Fault::Code::IoError}; }
        return {};
    }

    auto CancelWatchdog(
        Net::steady_timer &Watchdog,
        WatchdogCompletion &Completion) noexcept -> void
    {
        try
        {
            (void)Watchdog.cancel();
        }
        catch (...)
        {
            Completion.Record(
                FailureFromException(std::current_exception()));
        }
    }

    struct TerminalReadPlan final
    {
        Prism::Fault::Failure Terminal;
        std::size_t FirstReadBytes{(std::numeric_limits<std::size_t>::max)()};
    };

    struct ScenarioInput final
    {
        std::vector<std::byte> Wire;
        Prism::Fault::Failure Terminal;
        std::size_t FirstReadBytes{(std::numeric_limits<std::size_t>::max)()};
    };

    class TerminalTransmission final : public Prism::Transmission
    {
    public:
        TerminalTransmission(
            Net::any_io_executor Executor,
            std::vector<std::byte> Wire,
            TerminalReadPlan Plan)
            : Prism::Transmission(std::move(Executor)), Wire_(std::move(Wire)),
              Terminal_(Plan.Terminal),
              ClosedNotify_(Prism::Transmission::Executor(), 1),
              NextReadGate_(Prism::Transmission::Executor(), 1),
              FirstReadBytes_(Plan.FirstReadBytes), SplitRead_(FirstReadBytes_ < Wire_.size())
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Prism::Transmission::Executor();
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            const auto ReadCall = ReadCalls_.fetch_add(1U, std::memory_order_acq_rel) + 1U;
            if (SplitRead_ && ReadCall == 1U)
            {
                const auto Count = (std::min)(Buffer.size(), FirstReadBytes_);
                CopyWire(Buffer, Count);
                Prism::Transmission::PostResult(Executor(), std::move(Handler), {Count, {}});
                return;
            }
            if (SplitRead_ && ReadCall == 2U)
            {
                auto Self = std::static_pointer_cast<TerminalTransmission>(
                    Prism::Transmission::shared_from_this());
                Net::co_spawn(Executor(), ReadAfterRelease(
                    std::move(Self), Buffer, std::move(Handler)), Net::detached);
                return;
            }
            const auto Count = (std::min)(Buffer.size(), Wire_.size());
            CopyWire(Buffer, Count);
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {Count, Terminal_});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_.store(true, std::memory_order_release);
            (void)ClosedNotify_.try_send(boost::system::error_code{});
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto HasSplitRead() const noexcept -> bool
        {
            return SplitRead_;
        }

        auto ReleaseNextRead() -> void
        {
            (void)NextReadGate_.try_send(boost::system::error_code{});
        }

        auto WaitForClose() -> Net::awaitable<void>
        {
            if (!IsOpen()) co_return;
            co_await ClosedNotify_.async_receive(Net::use_awaitable);
        }

    private:
        auto CopyWire(std::span<std::byte> Buffer, const std::size_t Count) -> void
        {
            std::copy_n(Wire_.begin(), Count, Buffer.begin());
            Wire_.erase(Wire_.begin(), Wire_.begin() + static_cast<std::ptrdiff_t>(Count));
        }

        static auto ReadAfterRelease(
            std::shared_ptr<TerminalTransmission> Owner,
            std::span<std::byte> Buffer,
            Completion Handler) -> Net::awaitable<void>
        {
            co_await Owner->NextReadGate_.async_receive(Net::use_awaitable);
            const auto Count = (std::min)(Buffer.size(), Owner->Wire_.size());
            Owner->CopyWire(Buffer, Count);
            Prism::Transmission::PostResult(
                Owner->Executor(), std::move(Handler), {Count, Owner->Terminal_});
        }

        std::vector<std::byte> Wire_;
        Prism::Fault::Failure Terminal_;
        TestSignal ClosedNotify_;
        TestSignal NextReadGate_;
        std::atomic<std::size_t> ReadCalls_{0U};
        std::atomic<bool> Closed_{false};
        std::size_t FirstReadBytes_;
        bool SplitRead_;
    };

    struct ChildObservation final
    {
        bool Accepted{false};
        bool Closed{false};
        bool ForcedCloseAccepted{false};
        std::vector<std::byte> Data;
        std::shared_ptr<Prism::Mux::H2Mux::Http2Stream> Stream;
        std::array<Prism::IoResult, 3> Reads{};
    };

    struct ScenarioResult final
    {
        Prism::Fault::Failure RunFailure;
        Prism::Fault::Failure CleanupFailure;
        ChildObservation Child;
        std::size_t RawReadCalls{0U};
        bool TimedOut{false};
        bool ServerRetired{false};
        bool RawClosed{false};
    };

    struct RunObservation final
    {
        bool Threw{false};
        Prism::Fault::Failure Failure;
    };

    struct ChildReadGate final
    {
        explicit ChildReadGate(Net::any_io_executor Executor)
            : Accepted(Executor, 1), Release(Executor, 1)
        {
        }

        TestSignal Accepted;
        TestSignal Release;
    };

    struct ScenarioExpectation final
    {
        std::span<const std::byte> Data;
        Prism::Fault::Failure StreamTerminal;
        Prism::Fault::Failure RunTerminal;
        bool RunSuccess{false};
        std::size_t RawReadCalls{1U};
    };

    auto BuildClientWire(
        const std::span<const std::byte> Payload,
        const bool EndStream,
        std::vector<std::byte> &Wire) -> bool
    {
        Net::io_context Io;
        Prism::Http2::Session Client(Io.get_executor(), false);
        Client.SendSettings();
        const auto StreamId = Client.OpenStream(
            {{":method", "CONNECT"}, {":authority", "example.test:443"}}, false);
        if (!StreamId) return false;
        if (Client.SubmitData(*StreamId, Payload, EndStream) != Prism::Http2::SubmitDataStatus::Accepted)
            return false;
        return Client.Collect(Wire);
    }

    struct ClientResetWire final
    {
        std::vector<std::byte> Wire;
        std::size_t PrefixBytes{0U};
    };

    auto BuildClientResetWire(
        const std::span<const std::byte> Payload,
        const std::uint32_t ErrorCode) -> std::optional<ClientResetWire>
    {
        Net::io_context Io;
        Prism::Http2::Session Client(Io.get_executor(), false);
        Client.SendSettings();
        const auto StreamId = Client.OpenStream(
            {{":method", "CONNECT"}, {":authority", "example.test:443"}}, false);
        if (!StreamId) return std::nullopt;
        if (Client.SubmitData(*StreamId, Payload, false) != Prism::Http2::SubmitDataStatus::Accepted)
            return std::nullopt;

        std::vector<std::byte> Prefix;
        if (!Client.Collect(Prefix)) return std::nullopt;
        const auto Reset = Client.ResetStream(*StreamId, ErrorCode);
        if (!Reset) return std::nullopt;
        std::vector<std::byte> Tail;
        if (!Client.Collect(Tail) || Tail.empty()) return std::nullopt;

        ClientResetWire Result;
        Result.PrefixBytes = Prefix.size();
        Result.Wire = std::move(Prefix);
        Result.Wire.insert(Result.Wire.end(), Tail.begin(), Tail.end());
        return Result;
    }

    struct UnacceptedResetObservation final
    {
        bool DrainComplete{false};
        bool StreamRemoved{false};
        bool ActivityRetired{false};
        bool AwaitingTerminalClose{false};
        bool TimedOut{false};
        bool RawDrained{false};
        Prism::Fault::Failure StateFailure;
        Prism::Fault::Failure CleanupFailure;
    };

    struct UnacceptedResetWatchdog final
    {
        UnacceptedResetWatchdog(
            std::shared_ptr<Prism::Mux::H2Mux::Http2State> StateValue,
            std::shared_ptr<Prism::Mux::H2Mux::Http2Stream> StreamValue,
            Net::any_io_executor Executor)
            : State(std::move(StateValue)), Stream(std::move(StreamValue)),
              Completion(std::move(Executor)) {}

        auto OnTimer(const boost::system::error_code &Error) -> void
        {
            if (Error)
            {
                Completion.RecordError(Error);
                if (Error == Net::error::operation_aborted)
                {
                    Completion.Complete();
                    return;
                }
            }
            else
            {
                TimedOut.store(true, std::memory_order_release);
                Completion.Record(Failure{Prism::Fault::Code::Timeout});
            }
            CloseStateAndStream();
            Completion.Complete();
        }

        std::shared_ptr<Prism::Mux::H2Mux::Http2State> State;
        std::shared_ptr<Prism::Mux::H2Mux::Http2Stream> Stream;
        std::atomic<bool> TimedOut{false};
        WatchdogCompletion Completion;

    private:
        auto CloseStateAndStream() -> void
        {
            try
            {
                State->Close();
            }
            catch (...)
            {
                Completion.Record(FailureFromException(std::current_exception()));
            }
            try
            {
                const auto Closed = Stream->Close();
                if (!Closed) Completion.Record(Closed.error());
            }
            catch (...)
            {
                Completion.Record(FailureFromException(std::current_exception()));
            }
        }
    };

    auto RunUnacceptedReset(
        Net::any_io_executor Executor) -> Net::awaitable<UnacceptedResetObservation>
    {
        auto Raw = std::make_shared<TerminalTransmission>(
            Executor, std::vector<std::byte>{},
            TerminalReadPlan{Prism::Fault::Failure{Prism::Fault::Code::Eof}});
        auto State = std::make_shared<Prism::Mux::H2Mux::Http2State>(Raw, 1U);
        auto Stream = std::make_shared<Prism::Mux::H2Mux::Http2Stream>(State, 1);
        State->Streams.emplace(Stream->StreamId(), Stream);
        State->Incoming.push_back(Stream);
        Stream->MarkIncomingPending(true);
        auto WatchdogState = std::make_shared<UnacceptedResetWatchdog>(
            State, Stream, Executor);
        Net::steady_timer Watchdog(State->Strand);
        Watchdog.expires_after(std::chrono::seconds(5));
        Watchdog.async_wait([WatchdogState](
                                const boost::system::error_code &Error)
        { WatchdogState->OnTimer(Error); });

        co_await Net::dispatch(State->Strand, Net::use_awaitable);
        State->OnRemoteClose({
            Stream->StreamId(),
            Prism::Http2::StreamReceiveClosureKind::Reset,
            Prism::Http2::ErrorNoError});
        const auto DrainComplete = co_await State->DrainStreams();
        auto StateFailure = State->FirstFailure.Load();
        if (!DrainComplete)
        {
            RecordFirstFailure(
                StateFailure, Failure{Prism::Fault::Code::Blocked});
        }
        CancelWatchdog(Watchdog, WatchdogState->Completion);
        co_await WatchdogState->Completion.Done.async_receive(Net::use_awaitable);
        co_await Net::dispatch(State->Strand, Net::use_awaitable);
        try
        {
            State->Close();
        }
        catch (...)
        {
            RecordFirstFailure(StateFailure, FailureFromException(std::current_exception()));
        }
        const auto RawDrained = co_await State->DrainRaw();
        RecordFirstFailure(StateFailure, State->FirstFailure.Load());
        if (!RawDrained)
        {
            RecordFirstFailure(
                StateFailure, Failure{Prism::Fault::Code::Blocked});
        }
        co_return UnacceptedResetObservation{
            DrainComplete,
            State->Streams.empty(),
            Stream->Activity()->IsRetired(),
            Stream->AwaitsTerminalClose(),
            WatchdogState->TimedOut.load(std::memory_order_acquire),
            RawDrained,
            StateFailure,
            WatchdogState->Completion.FirstFailure};
    }

    auto ConsumeAcceptedStream(
        std::shared_ptr<Prism::Mux::H2Mux::Http2Server> Server,
        std::shared_ptr<ChildObservation> Observation,
        std::shared_ptr<ChildReadGate> Gate) -> Net::awaitable<void>
    {
        auto Stream = co_await Server->AcceptStream();
        Observation->Accepted = static_cast<bool>(Stream);
        if (Stream) Observation->Stream = Stream;
        (void)Gate->Accepted.try_send(boost::system::error_code{});
        if (!Stream) co_return;
        co_await Gate->Release.async_receive(Net::use_awaitable);

        std::array<std::byte, 64> Buffer{};
        for (auto &Read : Observation->Reads)
        {
            Read = co_await Stream->ReadSome(Buffer);
            Observation->Data.insert(
                Observation->Data.end(), Buffer.begin(),
                Buffer.begin() + static_cast<std::ptrdiff_t>(Read.Bytes));
        }
        Observation->Closed = static_cast<bool>(Stream->Close());
        const auto Drained = co_await Stream->DrainTerminations();
        Observation->Closed = Observation->Closed && static_cast<bool>(Drained);
        // 测试结果只记录行为，不延长生产 stream 超过所属 io_context 的生命周期。
        Observation->Stream.reset();
    }

    struct ScenarioWatchdog final
    {
        explicit ScenarioWatchdog(Net::any_io_executor Executor)
            : Completion(std::move(Executor)) {}

        auto OnTimer(const boost::system::error_code &Error) -> void
        {
            if (Error)
            {
                Completion.RecordError(Error);
                if (Error == Net::error::operation_aborted)
                {
                    Completion.Complete();
                    return;
                }
            }
            else
            {
                TimedOut.store(true, std::memory_order_release);
                Completion.Record(Failure{Prism::Fault::Code::Timeout});
            }
            try
            {
                Server->Cancel();
            }
            catch (...)
            {
                Completion.Record(FailureFromException(std::current_exception()));
            }
            try
            {
                Server->Close();
            }
            catch (...)
            {
                Completion.Record(FailureFromException(std::current_exception()));
            }
            if (Child->Stream)
            {
                try
                {
                    const auto Closed = Child->Stream->Close();
                    Child->ForcedCloseAccepted = static_cast<bool>(Closed);
                    if (!Closed) Completion.Record(Closed.error());
                }
                catch (...)
                {
                    Completion.Record(FailureFromException(std::current_exception()));
                }
            }
            (void)Gate->Release.try_send(boost::system::error_code{});
            Raw->ReleaseNextRead();
            Completion.Complete();
        }

        std::shared_ptr<Prism::Mux::H2Mux::Http2Server> Server;
        std::shared_ptr<TerminalTransmission> Raw;
        std::shared_ptr<ChildObservation> Child;
        std::shared_ptr<ChildReadGate> Gate;
        std::atomic<bool> TimedOut{false};
        WatchdogCompletion Completion;
    };

    auto RunScenario(
        Net::any_io_executor Executor,
        ScenarioInput Input)
        -> Net::awaitable<ScenarioResult>
    {
        auto Raw = std::make_shared<TerminalTransmission>(
            Executor, std::move(Input.Wire),
            TerminalReadPlan{Input.Terminal, Input.FirstReadBytes});
        auto Server = std::make_shared<Prism::Mux::H2Mux::Http2Server>(Raw, 2U);
        auto Child = std::make_shared<ChildObservation>();
        auto Gate = std::make_shared<ChildReadGate>(Executor);
        auto ChildDone = std::make_shared<TestSignal>(Executor, 1);
        auto RunDone = std::make_shared<TestSignal>(Executor, 1);
        auto RunResult = std::make_shared<RunObservation>();
        auto ChildFailure = std::make_shared<std::exception_ptr>();
        auto WatchdogState = std::make_shared<ScenarioWatchdog>(Executor);
        WatchdogState->Server = Server;
        WatchdogState->Raw = Raw;
        WatchdogState->Child = Child;
        WatchdogState->Gate = Gate;
        Net::steady_timer Watchdog(Executor);
        Watchdog.expires_after(std::chrono::seconds(5));
        Watchdog.async_wait([WatchdogState](
                                const boost::system::error_code &Error)
        { WatchdogState->OnTimer(Error); });
        Net::co_spawn(Executor, ConsumeAcceptedStream(Server, Child, Gate),
            [ChildDone, ChildFailure](std::exception_ptr Failure)
            {
                *ChildFailure = std::move(Failure);
                (void)ChildDone->try_send(boost::system::error_code{});
            });
        co_await Net::post(Executor, Net::use_awaitable);
        Net::co_spawn(Executor, Server->Run(),
            [RunDone, RunResult](std::exception_ptr Failure,
                std::expected<void, Prism::Fault::Failure> Outcome)
            {
                RunResult->Threw = static_cast<bool>(Failure);
                if (Failure) RunResult->Failure = {Prism::Fault::Code::IoError};
                else if (!Outcome) RunResult->Failure = Outcome.error();
                (void)RunDone->try_send(boost::system::error_code{});
            });
        co_await Gate->Accepted.async_receive(Net::use_awaitable);
        if (Raw->HasSplitRead()) Raw->ReleaseNextRead();
        co_await Raw->WaitForClose();
        (void)Gate->Release.try_send(boost::system::error_code{});

        co_await ChildDone->async_receive(Net::use_awaitable);
        co_await RunDone->async_receive(Net::use_awaitable);

        CancelWatchdog(Watchdog, WatchdogState->Completion);
        co_await WatchdogState->Completion.Done.async_receive(Net::use_awaitable);

        ScenarioResult Result;
        Result.RunFailure = RunResult->Failure;
        if (RunResult->Threw)
        {
            RecordFirstFailure(
                Result.RunFailure, Failure{Prism::Fault::Code::IoError});
        }
        if (*ChildFailure)
        {
            RecordFirstFailure(
                Result.RunFailure, Failure{Prism::Fault::Code::IoError});
        }
        Result.CleanupFailure = WatchdogState->Completion.FirstFailure;
        RecordFirstFailure(Result.RunFailure, Result.CleanupFailure);
        const auto ServerDrain = co_await Server->Drain();
        if (!ServerDrain)
        {
            // 根 Drain 必然带回连接/流首因；它属于被观察的 Run 终态，
            // 不是清理阶段新失败，否则 CleanupFailure 永远无法为零。
            RecordFirstFailure(Result.RunFailure, ServerDrain.error());
        }
        Result.TimedOut = WatchdogState->TimedOut.load(std::memory_order_acquire);
        Result.Child = std::move(*Child);
        Result.RawReadCalls = Raw->ReadCalls();
        Result.ServerRetired = Server->IsRetired();
        Result.RawClosed = !Raw->IsOpen();
        co_return Result;
    }

    auto RunWithWatchdog(
        const Prism::Fault::Failure Terminal,
        std::vector<std::byte> Wire,
        const std::size_t FirstReadBytes = (std::numeric_limits<std::size_t>::max)())
    {
        Net::io_context Io;
        std::exception_ptr Failure;
        ScenarioResult Result;
        Net::co_spawn(Io,
            RunScenario(Io.get_executor(), ScenarioInput{
                std::move(Wire), Terminal, FirstReadBytes}),
            [&Result, &Failure](std::exception_ptr Error, ScenarioResult Value)
            {
                Failure = std::move(Error);
                Result = std::move(Value);
            });
        Io.run();
        if (Failure) Result.RunFailure = {Prism::Fault::Code::IoError};
        return Result;
    }

    auto AssertTerminal(const Prism::IoResult &Read, const Prism::Fault::Failure Expected) -> void
    {
        EXPECT_EQ(Read.Bytes, 0U);
        EXPECT_EQ(Read.Failure.Code, Expected.Code);
        EXPECT_EQ(Prism::Fault::ToNative(Read.Failure), Prism::Fault::ToNative(Expected));
        if (Expected.Native) EXPECT_EQ(Read.Failure.Native, Expected.Native);
        if (Expected.Code == Prism::Fault::Code::ConnectionAborted)
            EXPECT_FALSE(Read.Failure.Native)
                << "code=" << static_cast<int>(Read.Failure.Code)
                << " native=" << Read.Failure.Native.value()
                << " category=" << Read.Failure.Native.category().name();
    }

    auto AssertScenario(
        const ScenarioResult &Actual,
        const ScenarioExpectation &Expected) -> void
    {
        EXPECT_TRUE(Actual.Child.Accepted);
        if (Actual.TimedOut) EXPECT_TRUE(Actual.Child.ForcedCloseAccepted);
        EXPECT_EQ(Actual.Child.Data.size(), Expected.Data.size());
        if (Actual.Child.Data.size() == Expected.Data.size())
        {
            EXPECT_TRUE(std::equal(Expected.Data.begin(), Expected.Data.end(), Actual.Child.Data.begin()));
        }
        EXPECT_TRUE(Actual.Child.Closed);
        EXPECT_EQ(Actual.RawReadCalls, Expected.RawReadCalls);
        EXPECT_TRUE(Actual.ServerRetired);
        EXPECT_TRUE(Actual.RawClosed);
        EXPECT_TRUE(Actual.CleanupFailure.Succeeded())
            << "cleanup code=" << static_cast<int>(Actual.CleanupFailure.Code)
            << " native=" << Actual.CleanupFailure.Native.value()
            << " category=" << Actual.CleanupFailure.Native.category().name();
        if (Expected.RunSuccess) EXPECT_FALSE(Actual.RunFailure.Failed());
        else
        {
            EXPECT_EQ(Actual.RunFailure.Code, Expected.RunTerminal.Code);
            EXPECT_EQ(Actual.RunFailure.Native, Expected.RunTerminal.Native);
        }
        const auto FirstTerminal = Expected.Data.empty() ? 0U : 1U;
        if (!Expected.Data.empty())
        {
            EXPECT_EQ(Actual.Child.Reads[0].Bytes, Expected.Data.size());
            EXPECT_FALSE(Actual.Child.Reads[0].Failure.Failed());
        }
        for (auto Index = FirstTerminal; Index < Actual.Child.Reads.size(); ++Index)
        {
            AssertTerminal(Actual.Child.Reads[Index], Expected.StreamTerminal);
        }
    }
}

TEST(H2MuxReadTerminal, CompleteDataPrecedesPeerEof)
{
    constexpr std::array Payload{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    std::vector<std::byte> Wire;
    ASSERT_TRUE(BuildClientWire(Payload, false, Wire));
    const Prism::Fault::Failure Terminal{Prism::Fault::Code::Eof};
    const auto Actual = RunWithWatchdog(Terminal, std::move(Wire));
    EXPECT_FALSE(Actual.TimedOut);
    AssertScenario(Actual, ScenarioExpectation{
        std::span<const std::byte>(Payload), Terminal, Terminal, true});
}

TEST(H2MuxReadTerminal, CompleteDataPrecedesNativeReset)
{
    constexpr std::array Payload{std::byte{5}, std::byte{6}, std::byte{7}};
    std::vector<std::byte> Wire;
    ASSERT_TRUE(BuildClientWire(Payload, false, Wire));
    const auto Terminal = Prism::Fault::FromNative(
        std::make_error_code(std::errc::connection_reset));
    const auto Actual = RunWithWatchdog(Terminal, std::move(Wire));
    EXPECT_FALSE(Actual.TimedOut);
    AssertScenario(Actual, ScenarioExpectation{
        std::span<const std::byte>(Payload), Terminal, Terminal, false});
}

TEST(H2MuxReadTerminal, PartialDataIsNotDispatchedBeforeNativeReset)
{
    constexpr std::array Payload{std::byte{9}, std::byte{8}, std::byte{7}, std::byte{6}};
    std::vector<std::byte> Wire;
    ASSERT_TRUE(BuildClientWire(Payload, false, Wire));
    ASSERT_FALSE(Wire.empty());
    Wire.pop_back();
    const auto Terminal = Prism::Fault::FromNative(
        std::make_error_code(std::errc::connection_reset));
    const auto Actual = RunWithWatchdog(Terminal, std::move(Wire));
    EXPECT_FALSE(Actual.TimedOut);
    AssertScenario(Actual, ScenarioExpectation{{}, Terminal, Terminal, false});
}

TEST(H2MuxReadTerminal, CompleteDataStreamEofPrecedesRootNativeReset)
{
    constexpr std::array Payload{std::byte{4}, std::byte{3}, std::byte{2}};
    std::vector<std::byte> Wire;
    ASSERT_TRUE(BuildClientWire(Payload, true, Wire));
    const Prism::Fault::Failure StreamTerminal{Prism::Fault::Code::Eof};
    const auto RootTerminal = Prism::Fault::FromNative(
        std::make_error_code(std::errc::connection_reset));
    const auto Actual = RunWithWatchdog(RootTerminal, std::move(Wire));
    EXPECT_FALSE(Actual.TimedOut);
    AssertScenario(Actual, ScenarioExpectation{
        std::span<const std::byte>(Payload), StreamTerminal, RootTerminal, false});
}

TEST(H2MuxReadTerminal, PeerNoErrorResetIsStickyConnectionAbortedAfterRawEof)
{
    constexpr std::array Payload{std::byte{0xA1}, std::byte{0xA2}, std::byte{0xA3}};
    auto Reset = BuildClientResetWire(Payload, Prism::Http2::ErrorNoError);
    ASSERT_TRUE(Reset.has_value());
    const Prism::Fault::Failure StreamTerminal{Prism::Fault::Code::ConnectionAborted};
    const Prism::Fault::Failure RawTerminal{Prism::Fault::Code::Eof};
    const auto Actual = RunWithWatchdog(
        RawTerminal, std::move(Reset->Wire), Reset->PrefixBytes);
    EXPECT_FALSE(Actual.TimedOut);
    AssertScenario(Actual, ScenarioExpectation{
        {}, StreamTerminal, RawTerminal, true, 2U});
}

TEST(H2MuxReadTerminal, PeerCancelResetIsStickyConnectionAbortedAfterRawEof)
{
    constexpr std::array Payload{std::byte{0xB1}, std::byte{0xB2}, std::byte{0xB3}};
    auto Reset = BuildClientResetWire(Payload, Prism::Http2::ErrorCancel);
    ASSERT_TRUE(Reset.has_value());
    const Prism::Fault::Failure StreamTerminal{Prism::Fault::Code::ConnectionAborted};
    const Prism::Fault::Failure RawTerminal{Prism::Fault::Code::Eof};
    const auto Actual = RunWithWatchdog(
        RawTerminal, std::move(Reset->Wire), Reset->PrefixBytes);
    EXPECT_FALSE(Actual.TimedOut);
    AssertScenario(Actual, ScenarioExpectation{
        {}, StreamTerminal, RawTerminal, true, 2U});
}

TEST(H2MuxReadTerminal, UnacceptedNoErrorResetClosesReceiptAndDrains)
{
    Net::io_context Io;
    std::exception_ptr Exception;
    UnacceptedResetObservation Observation;
    Net::co_spawn(Io, RunUnacceptedReset(Io.get_executor()),
        [&Exception, &Observation](std::exception_ptr Error, UnacceptedResetObservation Value)
        {
            Exception = std::move(Error);
            Observation = Value;
        });
    Io.run();

    EXPECT_FALSE(Exception);
    EXPECT_TRUE(Observation.DrainComplete);
    EXPECT_TRUE(Observation.StreamRemoved);
    EXPECT_TRUE(Observation.ActivityRetired);
    EXPECT_FALSE(Observation.AwaitingTerminalClose);
    EXPECT_FALSE(Observation.TimedOut);
    EXPECT_TRUE(Observation.RawDrained);
    EXPECT_TRUE(Observation.StateFailure.Succeeded());
    EXPECT_TRUE(Observation.CleanupFailure.Succeeded());
}
