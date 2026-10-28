/** @file CancelExecutorTest.cpp @brief 跨执行器取消遵守流所有者线程。 */
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Lifecycle/Task/Registry.hpp>
#include <Prism/Protocols/Mux/Stream/State.hpp>
#include <Prism/Protocols/Mux/Stream.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <semaphore>
#include <span>
#include <system_error>
#include <thread>
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
    using SignalChannel = Net::experimental::channel<void(boost::system::error_code)>;

    class CancellationSession final : public Mux::SessionIface
    {
    public:
        explicit CancellationSession(Net::any_io_executor Executor)
            : Executor_(std::move(Executor)),
              Tasks_(std::make_shared<Prism::Lifecycle::TaskRegistry>(Executor_))
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

    struct PendingReadGate final
    {
        Net::io_context *OwnerContext{nullptr};
        Net::any_io_executor OwnerExecutor;
        std::shared_ptr<Mux::StreamHandle<>> Handle;
        std::size_t Attempts{0U};
        std::atomic_bool Pending{false};
    };

    struct PublicOwnerGate final
    {
        Net::any_io_executor CallerExecutor;
        std::shared_ptr<PendingReadGate> ReadGate;
        std::shared_ptr<SignalChannel> Entered;
        std::binary_semaphore Release{0};
    };

    class PublicOwnerGateRelease final
    {
    public:
        auto Bind(std::shared_ptr<PublicOwnerGate> Gate) -> void
        {
            Gate_ = std::move(Gate);
        }

        ~PublicOwnerGateRelease()
        {
            Release();
        }

        auto Release() noexcept -> void
        {
            if (Gate_ && !Released_)
            {
                Released_ = true;
                Gate_->Release.release();
            }
        }

    private:
        std::shared_ptr<PublicOwnerGate> Gate_;
        bool Released_{false};
    };

    /** @brief 确认读已挂起后停止 owner loop，给外部 caller 留下稳定的观察窗口。 */
    auto CheckPendingRead(const std::shared_ptr<PendingReadGate> &Gate) -> void
    {
        ++Gate->Attempts;
        const auto Pending = Mux::StreamHandleReadPendingTestAccess::IsPending(*Gate->Handle);
        if (Pending || Gate->Attempts >= 64U)
        {
            Gate->Pending.store(Pending, std::memory_order_release);
            Gate->OwnerContext->stop();
            return;
        }
        Net::post(Gate->OwnerExecutor, [Gate] { CheckPendingRead(Gate); });
    }

    /** @brief 保持 owner strand handler 未返回，同时允许外部控制命令成功入队。 */
    auto CheckPendingReadAndBlock(const std::shared_ptr<PublicOwnerGate> &Gate) -> void
    {
        auto &ReadGate = *Gate->ReadGate;
        ++ReadGate.Attempts;
        const auto Pending = Mux::StreamHandleReadPendingTestAccess::IsPending(*ReadGate.Handle);
        if (Pending || ReadGate.Attempts >= 64U)
        {
            ReadGate.Pending.store(Pending, std::memory_order_release);
            const auto Entered = Gate->Entered;
            Net::post(Gate->CallerExecutor, [Entered]
            { (void)Entered->try_send(boost::system::error_code{}); });
            Gate->Release.acquire();
            return;
        }
        Net::post(ReadGate.OwnerExecutor, [Gate] { CheckPendingReadAndBlock(Gate); });
    }

    /** @brief 显式运行并暂停独立 owner io_context，避免取消投递与观察互相竞速。 */
    class OwnerContextRunner final
    {
    public:
        using StoppedChannel = SignalChannel;

        OwnerContextRunner(Net::io_context &Context, Net::any_io_executor SignalExecutor)
            : Context_(&Context), SignalExecutor_(std::move(SignalExecutor))
        {
        }

        ~OwnerContextRunner()
        {
            StopAndJoin();
        }

        auto Start() -> void
        {
            Stopped_ = std::make_shared<StoppedChannel>(SignalExecutor_, 1U);
            Thread_ = std::thread([this] { Run(); });
        }

        auto Join() -> void
        {
            if (Thread_.joinable()) Thread_.join();
        }

        auto RestartContext() -> void
        {
            Join();
            Context_->restart();
            Exception_ = nullptr;
        }

        auto StopAndJoin() -> void
        {
            Context_->stop();
            Join();
        }

        [[nodiscard]] auto Stopped() const -> std::shared_ptr<StoppedChannel>
        {
            return Stopped_;
        }

        [[nodiscard]] auto Exception() const -> std::exception_ptr
        {
            return Exception_;
        }

    private:
        auto Run() -> void
        {
            try
            {
                Context_->run();
            }
            catch (...)
            {
                Exception_ = std::current_exception();
                Context_->stop();
            }
            const auto Signal = Stopped_;
            Net::post(SignalExecutor_, [Signal]
            { (void)Signal->try_send(boost::system::error_code{}); });
        }

        Net::io_context *Context_;
        Net::any_io_executor SignalExecutor_;
        std::shared_ptr<StoppedChannel> Stopped_;
        std::thread Thread_;
        std::exception_ptr Exception_;
    };

    struct CrossStrandCleanupOutcome final
    {
        std::optional<Prism::IoResult> Read;
        std::optional<Prism::IoResult> PeerEof;
        std::uint64_t CancelGeneration{0U};
        bool StreamOpenAfterRead{false};
        bool CloseAccepted{false};
        bool ActivityDrained{false};
        bool TerminationsDrained{false};
        bool TasksDrained{false};
        std::size_t ActiveTasks{0U};
        std::exception_ptr Exception;
    };

    struct CrossStrandCleanupRequest final
    {
        bool Pending{false};
        std::shared_ptr<ReadObservation> Read;
        std::shared_ptr<Mux::StreamHandle<>> Handle;
        std::shared_ptr<Mux::StreamTransmission> Stream;
        std::shared_ptr<CancellationSession> Session;
        std::shared_ptr<CrossStrandCleanupOutcome> Outcome;
    };

    enum class CancelEntry { PublicControl, DirectOnCancel };

    struct CallerCancelResult final
    {
        std::uint64_t PreviousGeneration{0U};
        bool CallerCompleted{false};
    };

    template <class CallerExecutor, class StreamExecutor>
    struct CallerCancelRequest final
    {
        std::shared_ptr<Mux::StreamTransmission> Stream;
        std::shared_ptr<Mux::StreamHandle<>> Handle;
        CallerExecutor CallerExecutorValue;
        StreamExecutor StreamExecutorValue;
        CancelEntry Entry{CancelEntry::PublicControl};
    };

    template <class CallerExecutor, class StreamExecutor>
    auto CancelFromCaller(CallerCancelRequest<CallerExecutor, StreamExecutor> Request)
        -> CallerCancelResult
    {
        const auto PreviousGeneration =
            Mux::StreamHandleReadPendingTestAccess::CancelGeneration(*Request.Handle);
        EXPECT_TRUE(Request.CallerExecutorValue.running_in_this_thread());
        EXPECT_FALSE(Request.StreamExecutorValue.running_in_this_thread());
        using ControlResult = decltype(Request.Stream->Cancel());
        std::optional<ControlResult> CancelResult;
        std::exception_ptr CancelException;
        try
        {
            if (Request.Entry == CancelEntry::PublicControl)
            {
                CancelResult = Request.Stream->Cancel();
            }
            else
            {
                CancelResult = Request.Stream->OnCancel();
            }
        }
        catch (...)
        {
            CancelException = std::current_exception();
        }
        const auto CallerCompleted = !CancelException;
        EXPECT_TRUE(CallerCompleted);
        EXPECT_FALSE(CancelException);
        EXPECT_TRUE(CancelResult.has_value());
        if (CancelResult) EXPECT_TRUE(*CancelResult);
        const auto GenerationBeforeOwnerResumes =
            Mux::StreamHandleReadPendingTestAccess::CancelGeneration(*Request.Handle);
        EXPECT_EQ(GenerationBeforeOwnerResumes, PreviousGeneration);
        return {PreviousGeneration, CallerCompleted};
    }

    template <class CallerExecutor, class StreamExecutor>
    auto RunCancelFromCaller(CallerCancelRequest<CallerExecutor, StreamExecutor> Request)
        -> Net::awaitable<CallerCancelResult>
    {
        co_await Net::dispatch(Request.CallerExecutorValue, Net::use_awaitable);
        co_return CancelFromCaller(std::move(Request));
    }

    auto FinishCrossStrandCancel(CrossStrandCleanupRequest Request) -> Net::awaitable<void>
    {
        co_await Net::dispatch(Request.Handle->Executor(), Net::use_awaitable);
        if (!Request.Pending) Request.Handle->CloseOnExecutor();

        boost::system::error_code ReadError;
        co_await Request.Read->Done->async_receive(
            Net::redirect_error(Net::use_awaitable, ReadError));
        Request.Outcome->Read = Request.Read->Result;
        Request.Outcome->CancelGeneration =
            Mux::StreamHandleReadPendingTestAccess::CancelGeneration(*Request.Handle);
        Request.Outcome->StreamOpenAfterRead = Request.Stream->IsOpen();

        if (Request.Pending)
        {
            std::array<std::byte, 8> Buffer{};
            Request.Handle->SetPeerEof();
            Request.Outcome->PeerEof = co_await Request.Stream->ReadSome(Buffer);
        }

        const auto Closed = Request.Stream->Close();
        Request.Outcome->CloseAccepted = static_cast<bool>(Closed);
        if (Closed)
        {
            const auto ActivityDrained = co_await Request.Stream->Activity()->Drain();
            Request.Outcome->ActivityDrained = static_cast<bool>(ActivityDrained);
            const auto TerminationsDrained = co_await Request.Stream->DrainTerminations();
            Request.Outcome->TerminationsDrained = static_cast<bool>(TerminationsDrained);
        }
        const auto TasksDrained = co_await Request.Session->Tasks()->Drain();
        Request.Outcome->TasksDrained = static_cast<bool>(TasksDrained);
        Request.Outcome->ActiveTasks = Request.Session->Tasks()->Stats().Active;
    }

    auto WaitForSignalOrTimeout(
        std::shared_ptr<SignalChannel> Signal,
        Net::any_io_executor Executor) -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Watchdog(Executor);
        Watchdog.expires_after(std::chrono::seconds(5));
        const auto Result = co_await (
            Signal->async_receive(Net::use_awaitable) ||
            Watchdog.async_wait(Net::use_awaitable));
        co_return Result.index() == 0U;
    }

    auto RunCrossStrandCancel(Net::any_io_executor Executor, CancelEntry Entry)
        -> Net::awaitable<void>
    {
        const auto CallerExecutor = Net::make_strand(Executor);
        co_await Net::dispatch(CallerExecutor, Net::use_awaitable);

        Net::io_context OwnerContext;
        const auto StreamExecutor = Net::make_strand(OwnerContext.get_executor());
        auto Session = std::make_shared<CancellationSession>(StreamExecutor);
        auto Handle = std::make_shared<Mux::StreamHandle<>>(
            Mux::StreamOptions{.Id = 4U}, Session);
        auto Stream = std::make_shared<Mux::StreamTransmission>(Handle);
        auto Read = std::make_shared<ReadObservation>(StreamExecutor);
        std::array<std::byte, 8> Buffer{};
        auto PendingGate = std::make_shared<PendingReadGate>();
        PendingGate->OwnerContext = &OwnerContext;
        PendingGate->OwnerExecutor = StreamExecutor;
        PendingGate->Handle = Handle;
        Net::co_spawn(StreamExecutor, Stream->ReadSome(Buffer), ReadCompletion{Read});

        OwnerContextRunner OwnerRunner(OwnerContext, CallerExecutor);
        std::shared_ptr<PublicOwnerGate> PublicGate;
        PublicOwnerGateRelease PublicGateRelease;
        if (Entry == CancelEntry::PublicControl)
        {
            PublicGate = std::make_shared<PublicOwnerGate>();
            PublicGate->CallerExecutor = CallerExecutor;
            PublicGate->ReadGate = PendingGate;
            PublicGate->Entered = std::make_shared<SignalChannel>(CallerExecutor, 1U);
            PublicGateRelease.Bind(PublicGate);
            Net::post(StreamExecutor, [PublicGate] { CheckPendingReadAndBlock(PublicGate); });
        }
        else
        {
            Net::post(StreamExecutor, [PendingGate] { CheckPendingRead(PendingGate); });
        }
        OwnerRunner.Start();
        const auto StartupSignal = Entry == CancelEntry::PublicControl
                                       ? PublicGate->Entered
                                       : OwnerRunner.Stopped();
        const auto OwnerReady = co_await WaitForSignalOrTimeout(
            StartupSignal, CallerExecutor);
        if (!OwnerReady)
        {
            PublicGateRelease.Release();
            OwnerRunner.StopAndJoin();
            EXPECT_TRUE(OwnerReady);
            co_return;
        }
        if (Entry == CancelEntry::DirectOnCancel)
        {
            OwnerRunner.Join();
            EXPECT_FALSE(OwnerRunner.Exception());
        }

        const auto Pending = PendingGate->Pending.load(std::memory_order_acquire);
        EXPECT_TRUE(Pending);
        EXPECT_EQ(OwnerContext.stopped(), Entry == CancelEntry::DirectOnCancel);
        // 等待组合器可能在父上下文恢复；显式切回调用方 strand，验证跨 strand 控制。
        co_await Net::dispatch(CallerExecutor, Net::use_awaitable);
        const auto CancelAttempt = co_await Net::co_spawn(
            CallerExecutor,
            RunCancelFromCaller(CallerCancelRequest{
                Stream, Handle, CallerExecutor, StreamExecutor, Entry}),
            Net::use_awaitable);

        if (Entry == CancelEntry::DirectOnCancel) OwnerRunner.RestartContext();
        auto Cleanup = std::make_shared<CrossStrandCleanupOutcome>();
        Net::co_spawn(
            StreamExecutor,
            FinishCrossStrandCancel(CrossStrandCleanupRequest{
                Pending, Read, Handle, Stream, Session, Cleanup}),
            [Cleanup](std::exception_ptr Exception)
            {
                Cleanup->Exception = std::move(Exception);
            });
        if (Entry == CancelEntry::DirectOnCancel)
        {
            OwnerRunner.Start();
        }
        else
        {
            PublicGateRelease.Release();
        }

        const auto Finished = co_await WaitForSignalOrTimeout(
            OwnerRunner.Stopped(), CallerExecutor);
        if (!Finished)
        {
            OwnerRunner.StopAndJoin();
            EXPECT_TRUE(Finished);
            co_return;
        }
        OwnerRunner.Join();
        EXPECT_FALSE(OwnerRunner.Exception());
        EXPECT_FALSE(Cleanup->Exception);
        EXPECT_TRUE(CancelAttempt.CallerCompleted);
        const auto CancelDispatched =
            Cleanup->CancelGeneration != CancelAttempt.PreviousGeneration;
        EXPECT_TRUE(CancelDispatched);
        EXPECT_EQ(Cleanup->CancelGeneration, CancelAttempt.PreviousGeneration + 1U);
        EXPECT_TRUE(Cleanup->StreamOpenAfterRead);
        EXPECT_TRUE(Cleanup->Read.has_value());
        if (Cleanup->Read)
        {
            EXPECT_EQ(Cleanup->Read->Bytes, 0U);
            EXPECT_EQ(Cleanup->Read->Failure.Code, Prism::Fault::Code::Canceled);
        }
        EXPECT_TRUE(Cleanup->PeerEof.has_value());
        if (Cleanup->PeerEof)
        {
            EXPECT_EQ(Cleanup->PeerEof->Bytes, 0U);
            EXPECT_EQ(Cleanup->PeerEof->Failure.Code, Prism::Fault::Code::Eof);
        }
        EXPECT_TRUE(Cleanup->CloseAccepted);
        EXPECT_TRUE(Cleanup->ActivityDrained);
        EXPECT_TRUE(Cleanup->TerminationsDrained);
        EXPECT_TRUE(Cleanup->TasksDrained);
        EXPECT_EQ(Cleanup->ActiveTasks, 0U);
    }

    auto RunCrossStrandScenario(Net::io_context &Io, CancelEntry Entry) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunCrossStrandCancel(Io.get_executor(), Entry),
            [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
        Io.run();
        if (Exception) std::rethrow_exception(Exception);
    }
}

TEST(MuxStreamCancellation, PublicCancelFromOtherStrandReachesPendingRead)
{
    Net::io_context Io;
    RunCrossStrandScenario(Io, CancelEntry::PublicControl);
}

TEST(MuxStreamCancellation, DirectOnCancelFromOtherExecutorDefersOwnerMutation)
{
    Net::io_context Io;
    RunCrossStrandScenario(Io, CancelEntry::DirectOnCancel);
}
