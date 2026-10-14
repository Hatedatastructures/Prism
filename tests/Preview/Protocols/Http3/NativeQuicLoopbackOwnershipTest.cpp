/**
 * @file NativeQuicLoopbackOwnershipTest.cpp
 * @brief 原生 QUIC 接收流与共享 socket 所有权测试。
 */
#include "NativeQuicLoopbackSupport.hpp"
#include <TestSupport/Preview/QuicStreamProviderActivity.hpp>
#include <Preview/Protocols/Quic/ConnectionLifecycle.hpp>

namespace
{
    struct StopSendingRequest final
    {
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Started;
        Preview::Quic::SharedStreamProvider PeerStream;
        Net::any_io_executor Executor;
    };

    /** @brief 等写开始后延迟关闭 peer stream，触发对端 STOP_SENDING。 */
    auto StopSendingAfterWriteStarted(StopSendingRequest Request) -> Net::awaitable<bool>
    {
        boost::system::error_code StartError;
        co_await Request.Started->async_receive(
            Net::redirect_error(Net::use_awaitable, StartError));
        if (StartError) co_return false;
        Net::steady_timer Delay(Request.Executor);
        Delay.expires_after(std::chrono::milliseconds(10));
        co_await Delay.async_wait(Net::use_awaitable);
        Request.PeerStream->Close();
        co_return true;
    }

    /** @brief 返回指定 typed 半关闭失败的隔离 QUIC provider。 */
    class ShutdownFailureProvider final : public Preview::Quic::StreamProvider
    {
    public:
        ShutdownFailureProvider(
            Net::any_io_executor Executor,
            Preview::Fault::Failure Failure)
            : Executor_(std::move(Executor)), Failure_(std::move(Failure)),
              Activity_(std::make_shared<Preview::Testing::Quic::StreamProviderActivity>(Executor_))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto Read(
            std::span<std::byte>,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            const auto Operation = Activity_->BeginOperation();
            ErrorCode.clear();
            if (!Operation)
            {
                ErrorCode = std::make_error_code(std::errc::operation_canceled);
                co_return 0U;
            }
            co_return 0U;
        }

        [[nodiscard]] auto Write(
            std::span<const std::byte>,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            const auto Operation = Activity_->BeginOperation();
            ErrorCode.clear();
            if (!Operation)
            {
                ErrorCode = std::make_error_code(std::errc::operation_canceled);
                co_return 0U;
            }
            co_return 0U;
        }

        [[nodiscard]] auto Close() -> Preview::Quic::StreamProvider::ControlResult override
        {
            Closed_ = true;
            Activity_->CompleteClose();
            return {};
        }

        [[nodiscard]] auto ShutdownWrite()
            -> Net::awaitable<ShutdownResult> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            co_return std::unexpected(Failure_);
        }

        [[nodiscard]] auto WaitForWriteAcknowledgement()
            -> Net::awaitable<ShutdownResult> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            co_return std::unexpected(Failure_);
        }

        [[nodiscard]] auto StreamId() const noexcept -> std::int64_t override
        {
            return 1;
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return Closed_;
        }

    private:
        Net::any_io_executor Executor_;
        Preview::Fault::Failure Failure_;
        std::shared_ptr<Preview::Testing::Quic::StreamProviderActivity> Activity_;
        bool Closed_{false};
    };

    /** @brief 无协议子资源的 QUIC lifecycle probe，用于 executor 拒绝后重试关闭。 */
    class RetryCloseLifecycle final : public Preview::Protocols::QuicConnectionLifecycle
    {
    public:
        explicit RetryCloseLifecycle(Preview::Protocols::QuicConnectionPreparation Input)
            : QuicConnectionLifecycle(std::move(Input))
        {
        }

        [[nodiscard]] auto CloseCalls() const noexcept -> std::size_t
        {
            return CloseCalls_;
        }

    private:
        auto CloseProtocol() -> void override
        {
            ++CloseCalls_;
        }

        [[nodiscard]] auto DrainProtocol()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        std::size_t CloseCalls_{0};
    };

    /** @brief 保留 typed 半关闭结果与异步异常。 */
    struct ShutdownWriteCompletion final
    {
        std::optional<Preview::Quic::StreamProvider::ShutdownResult> Result{};
        std::exception_ptr Exception{};
    };

    /** @brief 驱动并取回 native stream 的 ShutdownWrite 回执。 */
    auto RunShutdownWrite(
        const Preview::Quic::SharedStreamProvider &Provider,
        Net::io_context &Context) -> ShutdownWriteCompletion
    {
        ShutdownWriteCompletion Completion;
        Net::co_spawn(
            Context, Provider->ShutdownWrite(),
            [&Completion](
                std::exception_ptr Error,
                Preview::Quic::StreamProvider::ShutdownResult Result)
            {
                Completion.Exception = std::move(Error);
                Completion.Result = std::move(Result);
            });
        Context.restart();
        Context.run();
        return Completion;
    }

    auto RunPeerResetRead(NativeLoopbackPeers &Peers) -> Net::awaitable<void>
    {
        Peers.Server->Start();
        Peers.Client->Start();
        const auto Handshake = co_await (
            Peers.Client->WaitHandshake() && Peers.Server->WaitHandshake());
        EXPECT_TRUE(std::get<0>(Handshake));
        EXPECT_TRUE(std::get<1>(Handshake));
        if (!std::get<0>(Handshake) || !std::get<1>(Handshake))
        {
            Peers.Client->Close();
            Peers.Server->Close();
            co_return;
        }
        const auto [ClientStream, ServerStream] = co_await (
            Peers.Client->OpenBidirectionalStream() && Peers.Server->AcceptBidirectionalStream());
        EXPECT_TRUE(ClientStream);
        EXPECT_TRUE(ServerStream);
        if (!ClientStream || !ServerStream)
        {
            Peers.Client->Close();
            Peers.Server->Close();
            co_return;
        }
        std::array<std::byte, 1> Buffer{};
        std::error_code ReadError;
        auto Reset = [ClientStream]() -> Net::awaitable<bool>
        {
            ClientStream->Close();
            co_return true;
        };
        const auto [ReadCount, ResetSent] = co_await (
            ServerStream->Read(Buffer, ReadError) && Reset());
        EXPECT_TRUE(ResetSent);
        EXPECT_EQ(ReadCount, 0U);
        EXPECT_EQ(ReadError, std::make_error_code(std::errc::connection_reset));
        Peers.Client->Close();
        Peers.Server->Close();
    }

    auto RunCreditWaitStopSending(
        NativeLoopbackPeers &Peers,
        Net::io_context &Io) -> Net::awaitable<void>
    {
        Peers.Server->Start();
        Peers.Client->Start();
        const auto Handshake = co_await (
            Peers.Client->WaitHandshake() && Peers.Server->WaitHandshake());
        EXPECT_TRUE(std::get<0>(Handshake));
        EXPECT_TRUE(std::get<1>(Handshake));
        if (!std::get<0>(Handshake) || !std::get<1>(Handshake))
        {
            Peers.Client->Close();
            Peers.Server->Close();
            co_return;
        }
        const auto [ClientStream, ServerStream] = co_await (
            Peers.Client->OpenBidirectionalStream() && Peers.Server->AcceptBidirectionalStream());
        EXPECT_TRUE(ClientStream);
        EXPECT_TRUE(ServerStream);
        if (!ClientStream || !ServerStream)
        {
            Peers.Client->Close();
            Peers.Server->Close();
            co_return;
        }

        std::vector<std::byte> Message(128U * 1024U, std::byte{0x5A});
        auto Started = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
            Io.get_executor(), 1);
        auto Writer = [&]() -> Net::awaitable<std::pair<std::size_t, std::error_code>>
        {
            (void)Started->try_send(boost::system::error_code{});
            std::error_code WriteError;
            const auto Written = co_await ClientStream->Write(Message, WriteError);
            co_return std::pair{Written, WriteError};
        };
        const auto [WriteResult, StopCompleted] = co_await (
            Writer() && StopSendingAfterWriteStarted({Started, ServerStream, Io.get_executor()}));
        EXPECT_TRUE(StopCompleted);
        EXPECT_LT(WriteResult.first, Message.size());
        EXPECT_EQ(WriteResult.second, std::make_error_code(std::errc::broken_pipe));
        Peers.Client->Close();
        Peers.Server->Close();
    }
    /** @brief 验证单流物理回执不等待仍活动的连接收发循环。 */
    auto RunStreamActivityRetiresWhileConnectionRemainsLive(
        NativeLoopbackPeers &Peers) -> Net::awaitable<void>
    {
        Peers.Server->Start();
        Peers.Client->Start();
        const auto Handshake = co_await (
            Peers.Client->WaitHandshake() && Peers.Server->WaitHandshake());
        EXPECT_TRUE(std::get<0>(Handshake));
        EXPECT_TRUE(std::get<1>(Handshake));
        if (!std::get<0>(Handshake) || !std::get<1>(Handshake))
        {
            Peers.Client->Close();
            Peers.Server->Close();
            co_return;
        }

        const auto [ClientStream, ServerStream] = co_await (
            Peers.Client->OpenBidirectionalStream() &&
            Peers.Server->AcceptBidirectionalStream());
        EXPECT_TRUE(ClientStream);
        EXPECT_TRUE(ServerStream);
        if (!ClientStream || !ServerStream)
        {
            Peers.Client->Close();
            Peers.Server->Close();
            co_return;
        }
        const auto ClientAdapter = std::make_shared<Preview::Quic::StreamAdapter>(
            ClientStream->Executor(), ClientStream);
        const auto ClientActivity = ClientAdapter->Activity();
        const auto ServerActivity = ServerStream->Activity();
        EXPECT_TRUE(ClientActivity);
        EXPECT_TRUE(ServerActivity);
        if (!ClientActivity || !ServerActivity)
        {
            Peers.Client->Close();
            Peers.Server->Close();
            co_return;
        }

        const auto ClientClose = ClientAdapter->Close();
        EXPECT_TRUE(ClientClose);
        if (!ClientClose)
        {
            Peers.Client->Close();
            Peers.Server->Close();
            co_return;
        }
        const auto [ClientDrain, ServerDrain] = co_await (
            ClientActivity->Drain() && ServerActivity->Drain());
        EXPECT_TRUE(ClientDrain);
        EXPECT_TRUE(ServerDrain);
        EXPECT_TRUE(ClientActivity->IsRetired());
        EXPECT_TRUE(ServerActivity->IsRetired());
        if (!ClientDrain || !ServerDrain)
        {
            Peers.Client->Close();
            Peers.Server->Close();
            co_return;
        }

        const auto [NextClientStream, NextServerStream] = co_await (
            Peers.Client->OpenBidirectionalStream() &&
            Peers.Server->AcceptBidirectionalStream());
        EXPECT_TRUE(NextClientStream);
        EXPECT_TRUE(NextServerStream);
        if (!NextClientStream || !NextServerStream)
        {
            Peers.Client->Close();
            Peers.Server->Close();
            co_return;
        }
        const auto NextClientClose = NextClientStream->Close();
        const auto NextServerClose = NextServerStream->Close();
        EXPECT_TRUE(NextClientClose);
        EXPECT_TRUE(NextServerClose);
        if (!NextClientClose || !NextServerClose)
        {
            Peers.Client->Close();
            Peers.Server->Close();
            co_return;
        }
        const auto [NextClientDrain, NextServerDrain] = co_await (
            NextClientStream->Activity()->Drain() &&
            NextServerStream->Activity()->Drain());
        EXPECT_TRUE(NextClientDrain);
        EXPECT_TRUE(NextServerDrain);

        Peers.Client->Close();
        Peers.Server->Close();
        const auto ServerDrainResult = co_await Peers.Server->Drain();
        EXPECT_TRUE(ServerDrainResult);
    }
}

TEST(NativeQuicLoopback, StreamAdapterPreservesTypedShutdownFailure)
{
    Net::io_context Ioc;
    const std::error_code NativeError(73, std::system_category());
    const Preview::Fault::Failure Failure{Preview::Fault::Code::IoError, NativeError};
    auto Provider = std::make_shared<ShutdownFailureProvider>(Ioc.get_executor(), Failure);
    auto Adapter = std::make_shared<Preview::Quic::StreamAdapter>(Ioc.get_executor(), Provider);
    std::optional<Preview::Transmission::ControlResult> Result;
    std::exception_ptr Exception;

    Net::co_spawn(
        Ioc, Adapter->WriteShutdown(),
        [&Result, &Exception](
            std::exception_ptr Error,
            Preview::Transmission::ControlResult Value)
        {
            Exception = std::move(Error);
            Result = std::move(Value);
        });
    Ioc.run();

    ASSERT_TRUE(Result.has_value());
    EXPECT_FALSE(Exception);
    ASSERT_FALSE(*Result);
    EXPECT_EQ(Result->error().Code, Failure.Code);
    EXPECT_EQ(Result->error().Native, NativeError);
    EXPECT_FALSE(Provider->IsClosed());
    EXPECT_TRUE(Adapter->Close());
}

TEST(NativeQuicLoopback, DatagramCancelPinsConnectionUntilQueuedOwnerUnwinds)
{
    auto Context = Preview::Executor::ContextOwner::Create();
    std::weak_ptr<Preview::Executor::ContextOwner> WeakContext = Context;
    auto Socket = std::make_shared<Net::ip::udp::socket>(Context->Io);
    Preview::Quic::ClientOptions Options;
    Options.Executor = Context->Io.get_executor();
    Options.Socket = Socket;
    auto Native = std::make_shared<Preview::Quic::Detail::NativeConnection>(Options);
    auto Datagram = Native->DatagramProvider();
    ASSERT_TRUE(Datagram);

    Datagram->Cancel();
    Native.reset();
    Datagram.reset();
    Context.reset();
    auto RetainedContext = WeakContext.lock();
    ASSERT_TRUE(RetainedContext);
    EXPECT_GT(RetainedContext->Io.run(), 0U);
    RetainedContext.reset();
    EXPECT_TRUE(WeakContext.expired());
}

TEST(NativeQuicLoopback, ShutdownAwaitablePinsProviderBeforeFirstSchedule)
{
    auto Context = Preview::Executor::ContextOwner::Create();
    std::weak_ptr<Preview::Executor::ContextOwner> WeakContext = Context;
    auto Socket = std::make_shared<Net::ip::udp::socket>(Context->Io);
    Preview::Quic::ClientOptions Options;
    Options.Executor = Context->Io.get_executor();
    Options.Socket = Socket;
    auto Native = std::make_shared<Preview::Quic::Detail::NativeConnection>(Options);
    auto State = std::make_shared<Preview::Quic::Detail::StreamState>(Options.Executor, 7);
    auto Provider = std::make_shared<Preview::Quic::Detail::NativeStream>(Native, State);
    auto Shutdown = Provider->ShutdownWrite();

    Native.reset();
    Provider.reset();
    State.reset();
    Context.reset();
    auto RetainedContext = WeakContext.lock();
    ASSERT_TRUE(RetainedContext);

    std::optional<Preview::Quic::StreamProvider::ShutdownResult> Result;
    std::exception_ptr Exception;
    Net::co_spawn(
        RetainedContext->Io, std::move(Shutdown),
        [&Result, &Exception](
            std::exception_ptr Error,
            Preview::Quic::StreamProvider::ShutdownResult Value)
        {
            Exception = std::move(Error);
            Result = std::move(Value);
        });
    RetainedContext->Io.run();

    ASSERT_TRUE(Result.has_value());
    EXPECT_FALSE(Exception);
    EXPECT_FALSE(*Result);
    RetainedContext.reset();
    EXPECT_TRUE(WeakContext.expired());
}
TEST(NativeQuicLoopback, LifecycleCloseRequestRetriesAfterExecutorRestart)
{
    auto Context = Preview::Executor::ContextOwner::Create();
    Preview::Protocols::QuicConnectionPreparation Preparation;
    Preparation.Listener.Executor = Context->Io.get_executor();
    auto Lifecycle = std::make_shared<RetryCloseLifecycle>(std::move(Preparation));

    Context->Io.stop();
    const auto Rejected = Lifecycle->RequestClose();
    ASSERT_FALSE(Rejected);
    EXPECT_EQ(Rejected.error().Code, Preview::Fault::Code::Blocked);
    EXPECT_EQ(Lifecycle->CloseCalls(), 0U);

    Context->Io.restart();
    const auto Retried = Lifecycle->RequestClose();
    ASSERT_TRUE(Retried);
    EXPECT_TRUE(Lifecycle->RequestClose());

    std::optional<std::expected<void, Preview::Fault::Failure>> DrainResult;
    std::exception_ptr Exception;
    Net::co_spawn(
        Context->Io, Lifecycle->Drain(),
        [&DrainResult, &Exception](
            std::exception_ptr Error,
            std::expected<void, Preview::Fault::Failure> Result)
        {
            Exception = std::move(Error);
            DrainResult = std::move(Result);
        });
    Context->Io.run();

    ASSERT_TRUE(DrainResult.has_value());
    EXPECT_FALSE(Exception);
    EXPECT_TRUE(*DrainResult);
    EXPECT_EQ(Lifecycle->CloseCalls(), 1U);
}

TEST(NativeQuicLoopback, PeerResetUnblocksReadWithoutFakingFin)
{
    Net::io_context Io;
    NativeLoopbackPeers Peers(Io);
    const auto ClosePeers = [&Peers]
    {
        Peers.Client->Close();
        Peers.Server->Close();
    };
    RunLoopback(Io, RunPeerResetRead(Peers),
        LoopbackLifecycle{ClosePeers, ClosePeers, std::chrono::seconds(5)});
}

TEST(NativeQuicLoopback, StreamActivityRetiresBeforeConnectionLoop)
{
    Net::io_context Io;
    NativeLoopbackPeers Peers(Io);
    const auto ClosePeers = [&Peers]
    {
        Peers.Client->Close();
        Peers.Server->Close();
    };
    RunLoopback(Io, RunStreamActivityRetiresWhileConnectionRemainsLive(Peers),
        LoopbackLifecycle{ClosePeers, ClosePeers, std::chrono::seconds(5)});
}
TEST(NativeQuicLoopback, PeerStopSendingWakesCreditBlockedWrite)
{
    Net::io_context Io;
    NativeLoopbackPeers Peers(Io);
    const auto ClosePeers = [&Peers]
    {
        Peers.Client->Close();
        Peers.Server->Close();
    };
    RunLoopback(Io, RunCreditWaitStopSending(Peers, Io),
        LoopbackLifecycle{ClosePeers, ClosePeers, std::chrono::seconds(5)});
}


TEST(NativeQuicLoopback, BareAcceptedStreamRetainsChannelExecutorAfterNativeRelease)
    {
        auto Context=Preview::Executor::ContextOwner::Create();
        std::weak_ptr<Preview::Executor::ContextOwner> WeakContext=Context;
        Preview::Quic::SharedStreamProvider Survivor;
        {
            NativeLoopbackPeers Peers(Context->Io);
            RunLoopback(Context->Io,RetainAcceptedStream(Peers,Survivor),
                LoopbackLifecycle{
                    [&Peers]{Peers.Client->Close();Peers.Server->Close();},
                    [] {}, std::chrono::seconds(5)});
        }
        ASSERT_TRUE(Survivor);
        EXPECT_TRUE(Survivor->IsClosed());
        ASSERT_GT(Context.use_count(), 1);

        const auto ExpectedFailure = Preview::Fault::FromNative(
            Preview::Quic::Detail::ToStdError(Preview::Error::BrokenPipe));
        Survivor->Close();
        const auto FirstShutdown = RunShutdownWrite(Survivor, Context->Io);
        ASSERT_TRUE(FirstShutdown.Result.has_value());
        EXPECT_FALSE(FirstShutdown.Exception);
        ASSERT_FALSE(*FirstShutdown.Result);
        EXPECT_EQ(FirstShutdown.Result->error().Code, ExpectedFailure.Code);
        EXPECT_EQ(FirstShutdown.Result->error().Native, ExpectedFailure.Native);
        Context->Io.restart();
        EXPECT_EQ(Context->Io.run(), 0U);

        Context.reset();
        EXPECT_FALSE(WeakContext.expired());
        Survivor->Close();
        auto RetainedContext = WeakContext.lock();
        ASSERT_TRUE(RetainedContext);
        const auto FinalShutdown = RunShutdownWrite(Survivor, RetainedContext->Io);
        ASSERT_TRUE(FinalShutdown.Result.has_value());
        EXPECT_FALSE(FinalShutdown.Exception);
        ASSERT_FALSE(*FinalShutdown.Result);
        EXPECT_EQ(FinalShutdown.Result->error().Code, ExpectedFailure.Code);
        EXPECT_EQ(FinalShutdown.Result->error().Native, ExpectedFailure.Native);
        RetainedContext.reset();
        Survivor.reset();
        EXPECT_TRUE(WeakContext.expired());
    }

    TEST(NativeQuicLoopback, SharedSocketSecondServerCannotCloseFirstSocket)
    {
        Net::io_context Ioc;
        auto ServerTls=std::make_shared<Ssl::context>(Ssl::context::tlsv13_server);
        auto ServerSocket = std::make_shared<Net::ip::udp::socket>(
            Ioc, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));

        const auto Options = Preview::Quic::ServerOptions{
            Ioc.get_executor(), ServerSocket, ServerTls,
            Preview::Testing::Quic::MakeSender(ServerSocket)};
        auto First = std::make_shared<Preview::Quic::Server>(Options);
        auto Second = std::make_shared<Preview::Quic::Server>(Options);

        RunLoopback(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                First->Start();
                Second->Start();
                Second->Close();
                EXPECT_TRUE(ServerSocket->is_open());
                First->Close();
                co_return;
            },
            LoopbackLifecycle{
            [First, Second]()
            {
                First->Close();
                Second->Close();
            }, [] {}, std::chrono::seconds(5)});
    }

