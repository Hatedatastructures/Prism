/** @file H2MuxWriteShutdownTest.cpp @brief 验证虚拟流半关闭完成与 HTTP/2 END_STREAM Flush 对齐。 */
#include <gtest/gtest.h>

#include <boost/asio/co_composed.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Protocols/Http2/Detail/Frame.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Mux/H2Mux/Http2State.hpp>
#include <Prism/Protocols/Mux/H2Mux/Http2Stream.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;
    using Failure = Prism::Fault::Failure;
    using Result = std::expected<void, Failure>;
    using Channel = Net::experimental::channel<void(boost::system::error_code)>;
    using State = Prism::Mux::H2Mux::Http2State;
    using Stream = Prism::Mux::H2Mux::Http2Stream;

    struct EndStreamWriteGate final
    {
        EndStreamWriteGate(Net::any_io_executor Executor, Failure FailureValue)
            : Entered(Executor, 1), Release(Executor, 1), InjectedFailure(FailureValue)
        {
        }

        auto ReleaseWrite() -> void
        {
            (void)Release.try_send(boost::system::error_code{});
        }

        Channel Entered;
        Channel Release;
        Failure InjectedFailure;
        bool WriteEntered{false};
        bool EndStreamFlushed{false};
        std::size_t EndStreamAttempts{0};
        std::size_t RawWriteCalls{0};
    };

    class GatedWriteTransmission final : public Prism::Transmission
    {
    public:
        GatedWriteTransmission(
            Prism::SharedTransmission InnerValue,
            std::shared_ptr<EndStreamWriteGate> GateValue)
            : Prism::Transmission(InnerValue->Executor()), Inner_(std::move(InnerValue)),
              Gate_(std::move(GateValue))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Inner_->Executor();
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Inner_->ReadSome(Buffer, std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate(WriteInput{
                std::static_pointer_cast<GatedWriteTransmission>(
                    Prism::Transmission::shared_from_this()), Buffer}, std::move(Handler));
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Inner_->WriteShutdown(std::move(Handler));
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return Inner_->Close();
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return Inner_->Cancel();
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Inner_->IsOpen();
        }

    private:
        struct WriteInput final
        {
            std::shared_ptr<GatedWriteTransmission> Owner;
            std::span<const std::byte> Buffer;
        };

        struct WriteWork final
        {
            template<class StateValue>
            auto operator()(StateValue Operation, WriteInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                const auto Written = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Written};
            }
        };

        template<class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(WriteWork{}, Executor()),
                Handler, std::move(Value));
        }

        [[nodiscard]] static auto ContainsEndStream(std::span<const std::byte> Buffer) -> bool
        {
            std::size_t Offset = 0;
            while (Buffer.size() - Offset >= Prism::Http2::Detail::FrameHeaderSize)
            {
                const auto Frame = Buffer.subspan(Offset);
                const auto Header = Prism::Http2::Detail::ParseFrameHeader(Frame);
                if (!Header || Header->Length > Frame.size() - Prism::Http2::Detail::FrameHeaderSize)
                    return false;
                if (Header->Type == Prism::Http2::Detail::FrameType::Data &&
                    (Header->Flags & Prism::Http2::Detail::FlagEndStream) != 0U &&
                    Header->StreamId > 0)
                    return true;
                Offset += Prism::Http2::Detail::FrameHeaderSize + Header->Length;
            }
            return false;
        }

        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            ++Gate_->RawWriteCalls;
            const auto EndStream = ContainsEndStream(Buffer);
            if (EndStream)
            {
                ++Gate_->EndStreamAttempts;
            }
            if (EndStream && !Gate_->WriteEntered)
            {
                Gate_->WriteEntered = true;
                (void)Gate_->Entered.try_send(boost::system::error_code{});
                boost::system::error_code WaitError;
                co_await Gate_->Release.async_receive(
                    Net::redirect_error(Net::use_awaitable, WaitError));
                if (WaitError)
                {
                    co_return Prism::IoResult{
                        0, Prism::Fault::FromNative(static_cast<std::error_code>(WaitError))};
                }
                if (Gate_->InjectedFailure.Failed())
                    co_return Prism::IoResult{0, Gate_->InjectedFailure};
            }
            const auto Written = co_await Inner_->WriteSome(Buffer);
            if (EndStream && Written.Failure.Succeeded() && Written.Bytes == Buffer.size())
                Gate_->EndStreamFlushed = true;
            co_return Written;
        }

        Prism::SharedTransmission Inner_;
        std::shared_ptr<EndStreamWriteGate> Gate_;
    };

    struct PreparedStream final
    {
        std::shared_ptr<State> Root;
        std::shared_ptr<Stream> Child;
        Prism::SharedTransmission Raw;
        Prism::SharedTransmission Client;
        std::shared_ptr<Prism::Http2::Session> ClientSession;
    };

    auto ConfigureSession(const std::shared_ptr<State> &Root) -> void
    {
        const auto WeakRoot = std::weak_ptr<State>(Root);
        Root->Session->OnHeaders = [WeakRoot](
            const std::int32_t Id, const Prism::Http2::HeaderList &Headers, const bool EndStream)
        {
            if (const auto Value = WeakRoot.lock()) Value->OnHeaders(Id, Headers, EndStream);
        };
        Root->Session->OnData = [WeakRoot](
            const std::int32_t Id, const std::span<const std::byte> Data)
        {
            if (const auto Value = WeakRoot.lock()) Value->OnData(Id, Data);
        };
        Root->Session->OnStreamClose = [WeakRoot](
            const Prism::Http2::StreamReceiveClosure &Closure)
        {
            if (const auto Value = WeakRoot.lock()) Value->OnRemoteClose(Closure);
        };
    }

    [[nodiscard]] auto PrepareStream(
        Net::io_context &Io,
        const std::shared_ptr<EndStreamWriteGate> &Gate)
        -> Net::awaitable<std::expected<PreparedStream, Failure>>
    {
        auto [ServerRaw, ClientRaw] = Prism::MakeMemoryPair(Io.get_executor());
        auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
        auto Raw = std::make_shared<GatedWriteTransmission>(
            std::make_shared<Prism::MemoryStream>(std::move(ServerRaw)), Gate);
        auto Root = std::make_shared<State>(Raw, 1U);
        Root->Session = std::make_shared<Prism::Http2::Session>(Root->Strand, true);
        ConfigureSession(Root);
        auto ClientSession = std::make_shared<Prism::Http2::Session>(Client->Executor(), false);
        ClientSession->SendSettings();
        const auto Opened = ClientSession->OpenStream(
            Prism::Http2::HeaderList{{":method", "CONNECT"}, {":authority", "shutdown.test:443"}}, false);
        if (!Opened) co_return std::unexpected(Opened.error());
        std::vector<std::byte> Request;
        if (!ClientSession->Collect(Request))
            co_return std::unexpected(Failure{Prism::Fault::Code::ProtocolError});
        co_await Net::dispatch(Root->Strand, Net::use_awaitable);
        Root->Session->SendSettings();
        std::error_code FeedError;
        if (!Root->Session->Feed(Request, FeedError) || FeedError)
        {
            co_return std::unexpected(FeedError
                ? Prism::Fault::FromNative(FeedError)
                : Failure{Prism::Fault::Code::ProtocolError});
        }
        Root->ApplyRefusedStreams();
        if (Root->Incoming.empty())
            co_return std::unexpected(Failure{Prism::Fault::Code::ProtocolError});
        auto Child = Root->Incoming.front();
        Root->Incoming.pop_front();
        Child->MarkIncomingPending(false);
        const auto Pump = Root->StartRetirementPump();
        if (!Pump) co_return std::unexpected(Pump.error());
        co_return PreparedStream{
            std::move(Root), std::move(Child), std::move(Raw), std::move(Client),
            std::move(ClientSession)};
    }

    struct ShutdownObservation final
    {
        explicit ShutdownObservation(Net::any_io_executor Executor) : Done(Executor, 1) {}

        auto Complete(Result Value) -> void
        {
            Outcome = std::move(Value);
            ++CompletionCount;
            Completed = true;
            (void)Done.try_send(boost::system::error_code{});
        }

        bool Completed{false};
        std::size_t CompletionCount{0};
        Result Outcome;
        Channel Done;
    };

    struct ShutdownCompletion final
    {
        std::shared_ptr<ShutdownObservation> Observation;

        auto operator()(std::exception_ptr Exception, Result Value) const -> void
        {
            if (Exception)
                Observation->Complete(std::unexpected(Failure{Prism::Fault::Code::IoError}));
            else
                Observation->Complete(std::move(Value));
        }
    };

    struct DirectShutdownCompletion final
    {
        std::shared_ptr<ShutdownObservation> Observation;

        auto operator()(Prism::IoResult Value) const -> void
        {
            if (Value.Failure.Failed())
                Observation->Complete(std::unexpected(Value.Failure));
            else
                Observation->Complete(Result{});
        }
    };

    struct ShutdownScenario final
    {
        ShutdownScenario(Net::io_context &IoValue, Failure FailureValue)
            : Io(IoValue), Gate(std::make_shared<EndStreamWriteGate>(Io.get_executor(), FailureValue)),
              Timer(Io.get_executor()), Observation(std::make_shared<ShutdownObservation>(Io.get_executor()))
        {
        }

        Net::io_context &Io;
        std::shared_ptr<EndStreamWriteGate> Gate;
        Net::steady_timer Timer;
        std::shared_ptr<ShutdownObservation> Observation;
        Result RepeatedOutcome;
        std::shared_ptr<State> Root;
        std::shared_ptr<Stream> Child;
        Prism::SharedTransmission Raw;
        Prism::SharedTransmission Client;
        std::shared_ptr<Prism::Http2::Session> ClientSession;
        Failure SetupFailure;
        Failure PeerReadFailure;
        bool TimedOut{false};
        bool GateReached{false};
        bool CompletedBeforeRelease{false};
        bool RepeatedCompleted{false};
        bool PeerFeedSucceeded{false};
        bool PeerEndStream{false};
        std::size_t PeerReadBytes{0};
        std::size_t RawWriteCallsBeforeRetry{0};
        std::size_t RawWriteCallsAfterRetry{0};
        bool CleanupComplete{false};
    };

    struct ForceShutdownRelease final
    {
        std::shared_ptr<ShutdownScenario> Scenario;

        auto operator()(const boost::system::error_code &Error) const -> void
        {
            if (Error == Net::error::operation_aborted) return;
            Scenario->TimedOut = true;
            Scenario->Gate->ReleaseWrite();
            Scenario->Gate->Entered.close();
            (void)Scenario->Observation->Done.try_send(boost::system::error_code{});
            if (Scenario->Root)
            {
                const auto Root = Scenario->Root;
                const auto Child = Scenario->Child;
                const auto Client = Scenario->Client;
                Net::dispatch(Root->Strand, [Root, Child, Client]
                {
                    Root->Close();
                    if (Child) (void)Child->Close();
                    if (Client) (void)Client->Close();
                });
            }
        }
    };

    auto ReadPeerFrames(const std::shared_ptr<ShutdownScenario> &Scenario)
        -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> Buffer{};
        const auto Read = co_await Scenario->Client->ReadSome(Buffer);
        Scenario->PeerReadBytes = Read.Bytes;
        Scenario->PeerReadFailure = Read.Failure;
        if (Read.Failure.Failed() || Read.Bytes == 0U || Read.Bytes > Buffer.size()) co_return;
        Scenario->ClientSession->OnStreamClose = [Scenario](
            const Prism::Http2::StreamReceiveClosure &Closure)
        {
            if (Closure.Kind == Prism::Http2::StreamReceiveClosureKind::EndStream &&
                Closure.StreamId == Scenario->Child->StreamId())
                Scenario->PeerEndStream = true;
        };
        std::error_code FeedError;
        Scenario->PeerFeedSucceeded = Scenario->ClientSession->Feed(
            std::span<const std::byte>(Buffer).first(Read.Bytes), FeedError) && !FeedError;
    }

    auto Cleanup(const std::shared_ptr<ShutdownScenario> &Scenario) -> Net::awaitable<void>
    {
        if (!Scenario->Root || !Scenario->Child || !Scenario->Client) co_return;
        Scenario->Gate->ReleaseWrite();
        co_await Net::dispatch(Scenario->Root->Strand, Net::use_awaitable);
        Scenario->Root->Close();
        const auto ChildClose = Scenario->Child->Close();
        const auto ClientClose = Scenario->Client->Close();
        co_await Net::dispatch(Scenario->Root->Strand, Net::use_awaitable);
        const auto ChildActivity = co_await Scenario->Child->Activity()->Drain();
        const auto ChildControls = co_await Scenario->Child->DrainTerminations();
        const auto Tasks = co_await Scenario->Root->Tasks->Drain();
        const auto Streams = co_await Scenario->Root->DrainStreams();
        const auto Raw = co_await Scenario->Raw->Activity()->Drain();
        const auto Client = co_await Scenario->Client->Activity()->Drain();
        Scenario->CleanupComplete = ChildClose && ClientClose && ChildActivity &&
            ChildControls && Tasks && Streams && Raw && Client && Scenario->Root->Streams.empty();
    }

    auto RunShutdownScenario(const std::shared_ptr<ShutdownScenario> &Scenario)
        -> Net::awaitable<void>
    {
        Scenario->Timer.expires_after(std::chrono::seconds(5));
        Scenario->Timer.async_wait(ForceShutdownRelease{Scenario});
        auto Prepared = co_await PrepareStream(Scenario->Io, Scenario->Gate);
        if (!Prepared)
        {
            Scenario->SetupFailure = Prepared.error();
            Scenario->Timer.cancel();
            co_return;
        }
        Scenario->Root = std::move(Prepared->Root);
        Scenario->Child = std::move(Prepared->Child);
        Scenario->Raw = std::move(Prepared->Raw);
        Scenario->Client = std::move(Prepared->Client);
        Scenario->ClientSession = std::move(Prepared->ClientSession);
        Net::co_spawn(Scenario->Child->Executor(), Scenario->Child->WriteShutdown(),
            ShutdownCompletion{Scenario->Observation});
        boost::system::error_code GateError;
        co_await Scenario->Gate->Entered.async_receive(
            Net::redirect_error(Net::use_awaitable, GateError));
        Scenario->GateReached = !GateError;
        Scenario->CompletedBeforeRelease = Scenario->Observation->Completed;
        Scenario->Gate->ReleaseWrite();
        boost::system::error_code CompletionError;
        co_await Scenario->Observation->Done.async_receive(
            Net::redirect_error(Net::use_awaitable, CompletionError));
        if (Scenario->Observation->Completed)
        {
            Scenario->RawWriteCallsBeforeRetry = Scenario->Gate->RawWriteCalls;
            Scenario->RepeatedOutcome = co_await Scenario->Child->WriteShutdown();
            Scenario->RepeatedCompleted = true;
            Scenario->RawWriteCallsAfterRetry = Scenario->Gate->RawWriteCalls;
        }
        if (Scenario->Observation->Completed && Scenario->Observation->Outcome &&
            Scenario->Gate->EndStreamFlushed)
            co_await ReadPeerFrames(Scenario);
        co_await Cleanup(Scenario);
        Scenario->Timer.cancel();
    }

    struct CloseBeforeControlScenario final
    {
        explicit CloseBeforeControlScenario(Net::io_context &IoValue)
            : Io(IoValue), Gate(std::make_shared<EndStreamWriteGate>(Io.get_executor(), Failure{})),
              Timer(Io.get_executor()), Observation(std::make_shared<ShutdownObservation>(Io.get_executor()))
        {
        }

        Net::io_context &Io;
        std::shared_ptr<EndStreamWriteGate> Gate;
        Net::steady_timer Timer;
        std::shared_ptr<ShutdownObservation> Observation;
        std::shared_ptr<State> Root;
        std::shared_ptr<Stream> Child;
        Prism::SharedTransmission Raw;
        Prism::SharedTransmission Client;
        bool TimedOut{false};
        bool CallbackCompleted{false};
        bool CleanupComplete{false};
    };

    struct ForceCloseBeforeControl final
    {
        std::shared_ptr<CloseBeforeControlScenario> Scenario;

        auto operator()(const boost::system::error_code &Error) const -> void
        {
            if (Error == Net::error::operation_aborted) return;
            Scenario->TimedOut = true;
            Scenario->Gate->ReleaseWrite();
            Scenario->Gate->Entered.close();
            (void)Scenario->Observation->Done.try_send(boost::system::error_code{});
            if (Scenario->Root)
            {
                const auto Root = Scenario->Root;
                const auto Child = Scenario->Child;
                const auto Client = Scenario->Client;
                Net::dispatch(Root->Strand, [Root, Child, Client]
                {
                    Root->Close();
                    if (Child) (void)Child->Close();
                    if (Client) (void)Client->Close();
                });
            }
        }
    };

    auto RunCloseBeforeControlScenario(const std::shared_ptr<CloseBeforeControlScenario> &Scenario)
        -> Net::awaitable<void>
    {
        Scenario->Timer.expires_after(std::chrono::seconds(5));
        Scenario->Timer.async_wait(ForceCloseBeforeControl{Scenario});
        auto Prepared = co_await PrepareStream(Scenario->Io, Scenario->Gate);
        if (!Prepared)
        {
            Scenario->Timer.cancel();
            co_return;
        }
        Scenario->Root = std::move(Prepared->Root);
        Scenario->Child = std::move(Prepared->Child);
        Scenario->Raw = std::move(Prepared->Raw);
        Scenario->Client = std::move(Prepared->Client);
        co_await Net::dispatch(Scenario->Root->Strand, Net::use_awaitable);
        Scenario->Child->StartWriteShutdown(DirectShutdownCompletion{Scenario->Observation});
        Scenario->Root->Close();
        boost::system::error_code CompletionError;
        co_await Scenario->Observation->Done.async_receive(
            Net::redirect_error(Net::use_awaitable, CompletionError));
        Scenario->CallbackCompleted = Scenario->Observation->Completed;
        auto CleanupScenario = std::make_shared<ShutdownScenario>(Scenario->Io, Failure{});
        CleanupScenario->Root = Scenario->Root;
        CleanupScenario->Child = Scenario->Child;
        CleanupScenario->Raw = Scenario->Raw;
        CleanupScenario->Client = Scenario->Client;
        CleanupScenario->Gate = Scenario->Gate;
        co_await Cleanup(CleanupScenario);
        Scenario->CleanupComplete = CleanupScenario->CleanupComplete;
        Scenario->Timer.cancel();
    }
}

TEST(H2MuxWriteShutdown, CompletesAfterEndStreamFlush)
{
    Net::io_context Io;
    auto Scenario = std::make_shared<ShutdownScenario>(Io, Failure{});
    Net::co_spawn(Io, RunShutdownScenario(Scenario), Net::detached);
    Io.run();

    EXPECT_FALSE(Scenario->TimedOut);
    EXPECT_FALSE(Scenario->SetupFailure.Failed());
    EXPECT_TRUE(Scenario->GateReached);
    EXPECT_FALSE(Scenario->CompletedBeforeRelease);
    EXPECT_TRUE(Scenario->Observation->Completed);
    EXPECT_EQ(Scenario->Observation->CompletionCount, 1U);
    EXPECT_TRUE(Scenario->Observation->Outcome);
    EXPECT_TRUE(Scenario->RepeatedCompleted);
    EXPECT_TRUE(Scenario->RepeatedOutcome);
    EXPECT_EQ(Scenario->Gate->EndStreamAttempts, 1U);
    EXPECT_EQ(Scenario->RawWriteCallsBeforeRetry, Scenario->RawWriteCallsAfterRetry);
    EXPECT_TRUE(Scenario->Gate->WriteEntered);
    EXPECT_TRUE(Scenario->Gate->EndStreamFlushed);
    EXPECT_FALSE(Scenario->PeerReadFailure.Failed());
    EXPECT_GT(Scenario->PeerReadBytes, 0U);
    EXPECT_TRUE(Scenario->PeerFeedSucceeded);
    EXPECT_TRUE(Scenario->PeerEndStream);
    EXPECT_TRUE(Scenario->CleanupComplete);
}

TEST(H2MuxWriteShutdown, PreservesFlushFailure)
{
    Net::io_context Io;
    const Failure Expected{
        Prism::Fault::Code::IoError, std::make_error_code(std::errc::connection_reset)};
    auto Scenario = std::make_shared<ShutdownScenario>(Io, Expected);
    Net::co_spawn(Io, RunShutdownScenario(Scenario), Net::detached);
    Io.run();

    EXPECT_FALSE(Scenario->TimedOut);
    EXPECT_FALSE(Scenario->SetupFailure.Failed());
    EXPECT_TRUE(Scenario->GateReached);
    EXPECT_FALSE(Scenario->CompletedBeforeRelease);
    EXPECT_TRUE(Scenario->Observation->Completed);
    EXPECT_EQ(Scenario->Observation->CompletionCount, 1U);
    ASSERT_FALSE(Scenario->Observation->Outcome);
    EXPECT_EQ(Scenario->Observation->Outcome.error().Code, Expected.Code);
    EXPECT_EQ(Scenario->Observation->Outcome.error().Native, Expected.Native);
    EXPECT_TRUE(Scenario->RepeatedCompleted);
    ASSERT_FALSE(Scenario->RepeatedOutcome);
    EXPECT_EQ(Scenario->RepeatedOutcome.error().Code, Expected.Code);
    EXPECT_EQ(Scenario->RepeatedOutcome.error().Native, Expected.Native);
    EXPECT_EQ(Scenario->Gate->EndStreamAttempts, 1U);
    EXPECT_EQ(Scenario->RawWriteCallsBeforeRetry, Scenario->RawWriteCallsAfterRetry);
    EXPECT_FALSE(Scenario->Gate->EndStreamFlushed);
    EXPECT_TRUE(Scenario->CleanupComplete);
}

TEST(H2MuxWriteShutdown, ReportsCloseWhenControlNeverFlushes)
{
    Net::io_context Io;
    auto Scenario = std::make_shared<CloseBeforeControlScenario>(Io);
    Net::co_spawn(Io, RunCloseBeforeControlScenario(Scenario), Net::detached);
    Io.run();

    EXPECT_FALSE(Scenario->TimedOut);
    EXPECT_TRUE(Scenario->CallbackCompleted);
    EXPECT_EQ(Scenario->Observation->CompletionCount, 1U);
    ASSERT_FALSE(Scenario->Observation->Outcome);
    EXPECT_EQ(Scenario->Observation->Outcome.error().Code, Prism::Fault::Code::Canceled);
    EXPECT_FALSE(Scenario->Gate->WriteEntered);
    EXPECT_TRUE(Scenario->CleanupComplete);
}
