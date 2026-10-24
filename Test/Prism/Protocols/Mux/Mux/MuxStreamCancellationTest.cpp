/** @file MuxStreamCancellationTest.cpp @brief StreamTransmission 保留显式取消终态。 */
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Lifecycle/TaskRegistry.hpp>
#include <Prism/Protocols/Mux/Detail/Stream/StreamState.hpp>
#include <Prism/Protocols/Mux/Stream.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>

#include <gtest/gtest.h>

namespace Prism::Mux
{
    struct StreamHandleReadPendingTestAccess final
    {
        [[nodiscard]] static auto IsPending(const StreamHandle<> &Handle) noexcept -> bool
        {
            return Handle.ReadPending_;
        }

        [[nodiscard]] static auto CancelGeneration(const StreamHandle<> &Handle) noexcept
            -> std::uint64_t
        {
            return Handle.CancelGeneration_;
        }
    };
}

namespace
{
    namespace Net = boost::asio;
    namespace Mux = Prism::Mux;

    class CancellationSession final : public Mux::SessionIface
    {
    public:
        explicit CancellationSession(Net::any_io_executor Executor)
            : Executor_(std::move(Executor)), Tasks_(std::make_shared<Prism::Lifecycle::TaskRegistry>(Executor_))
        {
        }

        auto PushData(std::uint32_t, std::span<const std::uint8_t>)
            -> Net::awaitable<Prism::ProtocolEc> override
        {
            co_return Prism::ProtocolEc{};
        }

        auto SendFin(std::uint32_t) -> Net::awaitable<void> override
        {
            co_return;
        }

        auto SendRst(std::uint32_t) -> Net::awaitable<void> override
        {
            co_return;
        }

        auto RemoveStream(std::uint32_t) -> void override
        {
            Open_ = false;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Open_;
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto Tasks() const noexcept
            -> std::shared_ptr<Prism::Lifecycle::TaskRegistry> override
        {
            return Tasks_;
        }

        auto OnStreamRxConsumed(std::uint32_t, std::size_t) noexcept -> void override
        {
        }

    private:
        Net::any_io_executor Executor_;
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> Tasks_;
        bool Open_{true};
    };

    struct ReadObservation final
    {
        using DoneChannel = Net::experimental::channel<void(boost::system::error_code)>;

        explicit ReadObservation(Net::any_io_executor Executor)
            : Done(std::make_shared<DoneChannel>(std::move(Executor), 1U))
        {
        }

        std::shared_ptr<DoneChannel> Done;
        std::optional<Prism::IoResult> Result;
        std::exception_ptr Exception;
    };

    struct ReadCompletion final
    {
        std::shared_ptr<ReadObservation> Observation;

        auto operator()(std::exception_ptr Exception, Prism::IoResult Result) const -> void
        {
            Observation->Exception = std::move(Exception);
            Observation->Result = Result;
            (void)Observation->Done->try_send(boost::system::error_code{});
        }
    };

    auto WaitForReadPending(
        const std::shared_ptr<Mux::StreamHandle<>> &Handle,
        Net::any_io_executor Executor) -> Net::awaitable<bool>
    {
        for (std::size_t Attempt = 0U; Attempt < 64U; ++Attempt)
        {
            if (Mux::StreamHandleReadPendingTestAccess::IsPending(*Handle))
            {
                co_return true;
            }
            co_await Net::post(Executor, Net::use_awaitable);
        }
        co_return Mux::StreamHandleReadPendingTestAccess::IsPending(*Handle);
    }

    auto WaitForCancelDispatch(
        const std::shared_ptr<Mux::StreamHandle<>> &Handle,
        Net::any_io_executor Executor,
        const std::uint64_t PreviousGeneration) -> Net::awaitable<bool>
    {
        for (std::size_t Attempt = 0U; Attempt < 64U; ++Attempt)
        {
            if (Mux::StreamHandleReadPendingTestAccess::CancelGeneration(*Handle) !=
                PreviousGeneration)
            {
                co_return true;
            }
            co_await Net::post(Executor, Net::use_awaitable);
        }
        co_return Mux::StreamHandleReadPendingTestAccess::CancelGeneration(*Handle) !=
                  PreviousGeneration;
    }

    auto WaitForReadCompletion(
        const std::shared_ptr<ReadObservation> &Observation,
        const std::shared_ptr<Mux::StreamHandle<>> &Handle,
        Net::any_io_executor Executor) -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Watchdog(Executor);
        Watchdog.expires_after(std::chrono::seconds(5));
        const auto Completion = co_await (
            Observation->Done->async_receive(Net::use_awaitable) ||
            Watchdog.async_wait(Net::use_awaitable));
        if (Completion.index() == 0U)
        {
            co_return true;
        }
        Handle->CloseOnExecutor();
        boost::system::error_code DoneError;
        co_await Observation->Done->async_receive(
            Net::redirect_error(Net::use_awaitable, DoneError));
        co_return false;
    }

    auto RunExplicitCancel(Net::any_io_executor Executor) -> Net::awaitable<void>
    {
        const auto StreamExecutor = Net::make_strand(Executor);
        co_await Net::dispatch(StreamExecutor, Net::use_awaitable);
        auto Session = std::make_shared<CancellationSession>(StreamExecutor);
        auto Handle = std::make_shared<Mux::StreamHandle<>>(
            Mux::StreamOptions{.Id = 1U}, Session);
        auto Stream = std::make_shared<Mux::StreamTransmission>(Handle);
        auto Observation = std::make_shared<ReadObservation>(StreamExecutor);
        std::array<std::byte, 8> Buffer{};
        Net::co_spawn(StreamExecutor, Stream->ReadSome(Buffer), ReadCompletion{Observation});
        const auto Pending = co_await WaitForReadPending(Handle, StreamExecutor);
        EXPECT_TRUE(Pending);

        if (Pending)
        {
            const auto Canceled = Stream->Cancel();
            EXPECT_TRUE(Canceled);
        }
        else
        {
            Handle->CloseOnExecutor();
        }
        const auto Completed = co_await WaitForReadCompletion(
            Observation, Handle, StreamExecutor);
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(Observation->Exception);
        EXPECT_TRUE(Observation->Result.has_value());
        if (Observation->Result)
        {
            EXPECT_EQ(Observation->Result->Bytes, 0U);
            EXPECT_EQ(Observation->Result->Failure.Code, Prism::Fault::Code::Canceled);
        }
        EXPECT_TRUE(Stream->IsOpen());

        Handle->SetPeerEof();
        const auto PeerEof = co_await Stream->ReadSome(Buffer);
        EXPECT_EQ(PeerEof.Bytes, 0U);
        EXPECT_EQ(PeerEof.Failure.Code, Prism::Fault::Code::Eof);

        const auto Closed = Stream->Close();
        EXPECT_TRUE(Closed);
        const auto ActivityDrained = co_await Stream->Activity()->Drain();
        EXPECT_TRUE(ActivityDrained);
        const auto StreamDrained = co_await Stream->DrainTerminations();
        EXPECT_TRUE(StreamDrained);
        const auto TasksDrained = co_await Session->Tasks()->Drain();
        EXPECT_TRUE(TasksDrained);
        EXPECT_EQ(Session->Tasks()->Stats().Active, 0U);
    }

    auto RunCancelWithoutPendingRead(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        const auto StreamExecutor = Net::make_strand(Executor);
        co_await Net::dispatch(StreamExecutor, Net::use_awaitable);
        auto Session = std::make_shared<CancellationSession>(StreamExecutor);
        auto Handle = std::make_shared<Mux::StreamHandle<>>(
            Mux::StreamOptions{.Id = 2U}, Session);
        auto Stream = std::make_shared<Mux::StreamTransmission>(Handle);
        const std::array<std::uint8_t, 3> Payload{0x31U, 0x32U, 0x33U};
        std::array<std::byte, 3> Buffer{};

        const auto CancelGeneration =
            Mux::StreamHandleReadPendingTestAccess::CancelGeneration(*Handle);
        const auto Cancelled = Stream->Cancel();
        EXPECT_TRUE(Cancelled);
        const auto CancelDispatched = co_await WaitForCancelDispatch(
            Handle, StreamExecutor, CancelGeneration);
        EXPECT_TRUE(CancelDispatched);
        EXPECT_FALSE(Mux::StreamHandleReadPendingTestAccess::IsPending(*Handle));
        EXPECT_TRUE(Handle->PushRx(Payload));

        const auto Read = co_await Stream->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, Payload.size());
        EXPECT_TRUE(Read.Failure.Succeeded());
        for (std::size_t Index = 0U; Index < Payload.size(); ++Index)
        {
            EXPECT_EQ(Buffer[Index], static_cast<std::byte>(Payload[Index]));
        }
        EXPECT_EQ(Handle->QueuedRxBytes(), 0U);

        Handle->SetPeerEof();
        const auto PeerEof = co_await Stream->ReadSome(Buffer);
        EXPECT_EQ(PeerEof.Bytes, 0U);
        EXPECT_EQ(PeerEof.Failure.Code, Prism::Fault::Code::Eof);
        const auto RepeatedPeerEof = co_await Stream->ReadSome(Buffer);
        EXPECT_EQ(RepeatedPeerEof.Bytes, 0U);
        EXPECT_EQ(RepeatedPeerEof.Failure.Code, Prism::Fault::Code::Eof);

        const auto Closed = Stream->Close();
        EXPECT_TRUE(Closed);
        const auto ActivityDrained = co_await Stream->Activity()->Drain();
        EXPECT_TRUE(ActivityDrained);
        const auto StreamDrained = co_await Stream->DrainTerminations();
        EXPECT_TRUE(StreamDrained);
        const auto TasksDrained = co_await Session->Tasks()->Drain();
        EXPECT_TRUE(TasksDrained);
        EXPECT_EQ(Session->Tasks()->Stats().Active, 0U);
    }

    auto RunCancelPreservesConcurrentPeerFailure(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        const auto StreamExecutor = Net::make_strand(Executor);
        co_await Net::dispatch(StreamExecutor, Net::use_awaitable);
        auto Session = std::make_shared<CancellationSession>(StreamExecutor);
        auto Handle = std::make_shared<Mux::StreamHandle<>>(
            Mux::StreamOptions{.Id = 3U}, Session);
        auto Stream = std::make_shared<Mux::StreamTransmission>(Handle);
        auto Observation = std::make_shared<ReadObservation>(StreamExecutor);
        std::array<std::byte, 8> Buffer{};
        Net::co_spawn(StreamExecutor, Stream->ReadSome(Buffer), ReadCompletion{Observation});

        const auto Pending = co_await WaitForReadPending(Handle, StreamExecutor);
        EXPECT_TRUE(Pending);
        const auto Native = std::make_error_code(std::errc::connection_reset);
        const auto PeerFailure = Prism::Fault::FromNative(Native);
        if (Pending)
        {
            Handle->SetPeerFailure(PeerFailure);
            Handle->Cancel();
        }
        else
        {
            Handle->CloseOnExecutor();
        }

        const auto Completed = co_await WaitForReadCompletion(
            Observation, Handle, StreamExecutor);
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(Observation->Exception);
        EXPECT_TRUE(Observation->Result.has_value());
        if (Observation->Result)
        {
            EXPECT_EQ(Observation->Result->Bytes, 0U);
            EXPECT_EQ(Observation->Result->Failure.Code, PeerFailure.Code);
            EXPECT_EQ(Observation->Result->Failure.Native, Native);
        }

        const auto RepeatedFailure = co_await Stream->ReadSome(Buffer);
        EXPECT_EQ(RepeatedFailure.Bytes, 0U);
        EXPECT_EQ(RepeatedFailure.Failure.Code, PeerFailure.Code);
        EXPECT_EQ(RepeatedFailure.Failure.Native, Native);

        const auto Closed = Stream->Close();
        EXPECT_TRUE(Closed);
        const auto ActivityDrained = co_await Stream->Activity()->Drain();
        EXPECT_TRUE(ActivityDrained);
        const auto StreamDrained = co_await Stream->DrainTerminations();
        EXPECT_TRUE(StreamDrained);
        const auto TasksDrained = co_await Session->Tasks()->Drain();
        EXPECT_TRUE(TasksDrained);
        EXPECT_EQ(Session->Tasks()->Stats().Active, 0U);
    }

    auto RunPendingCancelPreservesQueuedPayload(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        const auto StreamExecutor = Net::make_strand(Executor);
        co_await Net::dispatch(StreamExecutor, Net::use_awaitable);
        auto Session = std::make_shared<CancellationSession>(StreamExecutor);
        auto Handle = std::make_shared<Mux::StreamHandle<>>(
            Mux::StreamOptions{.Id = 5U}, Session);
        auto Stream = std::make_shared<Mux::StreamTransmission>(Handle);
        auto Observation = std::make_shared<ReadObservation>(StreamExecutor);
        const std::array<std::uint8_t, 4> Payload{0x51U, 0x52U, 0x53U, 0x54U};
        std::array<std::byte, 8> ReadBuffer{};
        std::array<std::byte, 4> PayloadBuffer{};
        Net::co_spawn(StreamExecutor, Stream->ReadSome(ReadBuffer), ReadCompletion{Observation});

        const auto Pending = co_await WaitForReadPending(Handle, StreamExecutor);
        EXPECT_TRUE(Pending);
        if (Pending)
        {
            EXPECT_TRUE(Handle->PushRx(Payload));
            Handle->Cancel();
        }
        else
        {
            Handle->CloseOnExecutor();
        }
        const auto ReadCompleted = co_await WaitForReadCompletion(
            Observation, Handle, StreamExecutor);
        EXPECT_TRUE(ReadCompleted);
        EXPECT_FALSE(Observation->Exception);
        EXPECT_TRUE(Observation->Result.has_value());
        if (Observation->Result)
        {
            EXPECT_EQ(Observation->Result->Bytes, 0U);
            EXPECT_EQ(Observation->Result->Failure.Code, Prism::Fault::Code::Canceled);
        }
        EXPECT_EQ(Handle->QueuedRxBytes(), Pending ? Payload.size() : 0U);

        if (Pending && Observation->Result && Stream->IsOpen())
        {
            const auto Read = co_await Stream->ReadSome(PayloadBuffer);
            EXPECT_EQ(Read.Bytes, Payload.size());
            EXPECT_TRUE(Read.Failure.Succeeded());
            for (std::size_t Index = 0U; Index < Payload.size(); ++Index)
            {
                EXPECT_EQ(PayloadBuffer[Index], static_cast<std::byte>(Payload[Index]));
            }
            EXPECT_EQ(Handle->QueuedRxBytes(), 0U);

            const auto Native = std::make_error_code(std::errc::connection_reset);
            const auto PeerFailure = Prism::Fault::FromNative(Native);
            Handle->SetPeerFailure(PeerFailure);
            const auto Terminal = co_await Stream->ReadSome(PayloadBuffer);
            EXPECT_EQ(Terminal.Bytes, 0U);
            EXPECT_EQ(Terminal.Failure.Code, PeerFailure.Code);
            EXPECT_EQ(Terminal.Failure.Native, Native);
            const auto RepeatedTerminal = co_await Stream->ReadSome(PayloadBuffer);
            EXPECT_EQ(RepeatedTerminal.Bytes, 0U);
            EXPECT_EQ(RepeatedTerminal.Failure.Code, PeerFailure.Code);
            EXPECT_EQ(RepeatedTerminal.Failure.Native, Native);
        }

        const auto Closed = Stream->Close();
        EXPECT_TRUE(Closed);
        const auto ActivityDrained = co_await Stream->Activity()->Drain();
        EXPECT_TRUE(ActivityDrained);
        const auto StreamDrained = co_await Stream->DrainTerminations();
        EXPECT_TRUE(StreamDrained);
        const auto TasksDrained = co_await Session->Tasks()->Drain();
        EXPECT_TRUE(TasksDrained);
        EXPECT_EQ(Session->Tasks()->Stats().Active, 0U);
    }

    auto RunCancellationScenario(Net::io_context &Io) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunExplicitCancel(Io.get_executor()),
            [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
        Io.run();
        if (Exception) std::rethrow_exception(Exception);
    }
}

TEST(MuxStreamCancellation, ExplicitCancelReturnsCanceledAndPreservesPeerEof)
{
    Net::io_context Io;
    RunCancellationScenario(Io);
}

TEST(MuxStreamCancellation, CancelWithoutPendingReadPreservesQueuedPeerData)
{
    Net::io_context Io;
    std::exception_ptr Exception;
    Net::co_spawn(Io, RunCancelWithoutPendingRead(Io.get_executor()),
        [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
    Io.run();
    if (Exception) std::rethrow_exception(Exception);
}

TEST(MuxStreamCancellation, PendingCancelPreservesConcurrentPeerFailure)
{
    Net::io_context Io;
    std::exception_ptr Exception;
    Net::co_spawn(Io, RunCancelPreservesConcurrentPeerFailure(Io.get_executor()),
        [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
    Io.run();
    if (Exception) std::rethrow_exception(Exception);
}

TEST(MuxStreamCancellation, PendingCancelPreservesQueuedPayloadBeforePeerFailure)
{
    Net::io_context Io;
    std::exception_ptr Exception;
    Net::co_spawn(Io, RunPendingCancelPreservesQueuedPayload(Io.get_executor()),
        [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
    Io.run();
    if (Exception) std::rethrow_exception(Exception);
}
