/**
 * @file XhttpErrorCloseMatrix.cpp
 * @brief XHTTP 传输关闭、完成与终态错误测试。
 */
#include <Prism/Protocols/Xhttp/Detail/StreamClient.hpp>

#include "XhttpErrorMatrixSupport.hpp"

#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Xhttp/Detail/AcceptedTransport.hpp>
#include <Prism/Protocols/Xhttp/Detail/FactoryRetirement.hpp>
#include <Prism/Transport/Detail/IoActivity.hpp>
#include <Prism/Transport/MemoryStream.hpp>

    struct FactoryRetirementRunResult final
    {
        Prism::Fault::Failure WriteFailure;
        Prism::Fault::Failure RetirementFailure;
        std::exception_ptr Exception;
    };

    struct FactoryRetirementCompletion final
    {
        std::shared_ptr<FactoryRetirementRunResult> Result;

        auto operator()(
            std::exception_ptr Exception,
            Prism::Fault::Failure Failure) const -> void
        {
            Result->Exception = std::move(Exception);
            Result->RetirementFailure = Failure;
        }
    };

    struct FailingWireSink final
    {
        Prism::Fault::Failure Failure;

        auto operator()(ConstBytes) const -> Net::awaitable<Xhttp::Detail::WireWriter::WriteResult>
        {
            co_return std::unexpected(Failure);
        }
    };

    auto RunFactoryRetirementAfterWriteFailure(
        const std::shared_ptr<Xhttp::Detail::ClientState> &State,
        const std::shared_ptr<Xhttp::Detail::FactoryRetirement<Xhttp::Detail::ClientState>> &Retirement,
        const std::shared_ptr<FactoryRetirementRunResult> &Result)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        const std::array<Byte, 1> Payload{Byte{0x31}};
        const auto Written = co_await State->Wire->Write(Payload);
        if (!Written)
            Result->WriteFailure = Written.error();
        State->DriverStarted = true;
        (void)State->DriverDone->try_send(
            boost::system::error_code{}, Result->WriteFailure);
        co_return co_await Retirement->Retire({});
    }

    struct RetirementReceiptProbe final
    {
        bool MayComplete{false};
        std::size_t Calls{0};
        Prism::Fault::Failure Failure;
        std::shared_ptr<Prism::Contract::CarrierActivity> InnerActivity;

        auto CloseAndDrain() -> Net::awaitable<Xhttp::Detail::FactoryRetirementReceipt>
        {
            ++Calls;
            if (MayComplete)
            {
                if (InnerActivity)
                {
                    const auto Drained = co_await InnerActivity->Drain();
                    if (!Drained && Failure.Succeeded()) Failure = Drained.error();
                    if (!InnerActivity->IsRetired())
                    {
                        auto IncompleteFailure = Failure;
                        if (IncompleteFailure.Succeeded())
                            IncompleteFailure = {Prism::Fault::Code::Blocked};
                        co_return Xhttp::Detail::FactoryRetirementReceipt{
                            false, IncompleteFailure};
                    }
                }
                co_return Xhttp::Detail::FactoryRetirementReceipt{true, Failure};
            }
            co_return Xhttp::Detail::FactoryRetirementReceipt{
                false, {Prism::Fault::Code::Blocked}};
        }
    };

    auto RunIncompleteFactoryRetirement(
        const std::shared_ptr<Xhttp::Detail::FactoryRetirement<RetirementReceiptProbe>> &Retirement)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        co_return co_await Retirement->Retire({});
    }

    TEST(XhttpErrorMatrix, FactoryRetirementReportsDrainedWriteFailureAndReleasesOwner)
    {
        const auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        const auto Context = Prism::Executor::ContextOwner::Create(Storage);
        const auto Native = std::make_error_code(std::errc::broken_pipe);
        const auto Failure = Prism::Fault::FromNative(Native);
        const auto State = std::make_shared<Xhttp::Detail::ClientState>();
        State->Wire = std::make_shared<Xhttp::Detail::WireWriter>(
            Context->Io.get_executor(),
            Xhttp::Detail::WireWriter::Sink{FailingWireSink{Failure}});
        State->DriverDone = std::make_shared<Xhttp::Detail::DriverCompletionChannel>(
            Context->Io.get_executor(), 1);
        const auto Retirement = Xhttp::Detail::FactoryRetirement<Xhttp::Detail::ClientState>::Prepare(
            Context->Io.get_executor());
        Retirement->Attach(State);
        const auto Result = std::make_shared<FactoryRetirementRunResult>();

        Context->Io.restart();
        Net::co_spawn(
            Context->Io,
            RunFactoryRetirementAfterWriteFailure(State, Retirement, Result),
            FactoryRetirementCompletion{Result});
        Context->Io.run();

        ASSERT_FALSE(Result->Exception);
        EXPECT_EQ(Result->WriteFailure.Native, Native);
        EXPECT_EQ(Result->RetirementFailure.Native, Native);
        EXPECT_TRUE(Retirement->IsRetired());
        EXPECT_TRUE(State->Wire->IsRetired());
        EXPECT_EQ(Storage->Pending(), 0U);
    }

    struct AcceptedRetirementResult final
    {
        Prism::Fault::Failure CloseFailure;
        Prism::Fault::Failure DrainFailure;
        bool Retired{false};
    };

    auto DrainAcceptedTransport(
        const std::shared_ptr<Xhttp::Detail::AcceptedTransport<RetirementReceiptProbe>> &Transport,
        const std::shared_ptr<AcceptedRetirementResult> &Result) -> Net::awaitable<void>
    {
        const auto Closed = Transport->Close();
        if (!Closed) Result->CloseFailure = Closed.error();
        const auto Drained = co_await Transport->Activity()->Drain();
        if (!Drained) Result->DrainFailure = Drained.error();
        Result->Retired = Transport->Activity()->IsRetired();
    }

    TEST(XhttpErrorMatrix, FactoryRetirementRetainsOwnerUntilDriverReceiptCompletes)
    {
        const auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        const auto Context = Prism::Executor::ContextOwner::Create(Storage);
        const auto State = std::make_shared<RetirementReceiptProbe>();
        const auto Retirement =
            Xhttp::Detail::FactoryRetirement<RetirementReceiptProbe>::Prepare(
                Context->Io.get_executor());
        Retirement->Attach(State);
        const auto Result = std::make_shared<FactoryRetirementRunResult>();

        Context->Io.restart();
        Net::co_spawn(
            Context->Io,
            RunIncompleteFactoryRetirement(Retirement),
            FactoryRetirementCompletion{Result});
        Context->Io.run();

        ASSERT_FALSE(Result->Exception);
        EXPECT_EQ(Result->RetirementFailure.Code, Prism::Fault::Code::Blocked);
        EXPECT_FALSE(Retirement->IsRetired());
        EXPECT_EQ(Storage->Pending(), 1U);
        EXPECT_EQ(State->Calls, 2U);

        State->MayComplete = true;
        Context->Io.restart();
        Storage->Retry();
        Context->Io.run();

        EXPECT_TRUE(Retirement->IsRetired());
        EXPECT_EQ(Storage->Pending(), 0U);
        EXPECT_EQ(State->Calls, 3U);
    }

    TEST(XhttpErrorMatrix, AcceptedActivityReportsNativeFailureAfterPhysicalRetirement)
    {
        const auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        const auto Context = Prism::Executor::ContextOwner::Create(Storage);
        const auto Native = std::make_error_code(std::errc::broken_pipe);
        const auto State = std::make_shared<RetirementReceiptProbe>();
        State->MayComplete = true;
        State->Failure = Prism::Fault::FromNative(Native);
        const auto Retirement =
            Xhttp::Detail::FactoryRetirement<RetirementReceiptProbe>::Prepare(
                Context->Io.get_executor());
        Retirement->Attach(State);
        auto Pair = Prism::MakeMemoryPair(Context->Io.get_executor());
        auto Inner = std::make_shared<Prism::MemoryStream>(std::move(Pair.first));
        State->InnerActivity = Inner->Activity();
        const auto Accepted = std::make_shared<
            Xhttp::Detail::AcceptedTransport<RetirementReceiptProbe>>(
                Retirement, Inner);
        const auto Result = std::make_shared<AcceptedRetirementResult>();

        RunCoroutine(Context->Io, DrainAcceptedTransport(Accepted, Result));

        EXPECT_FALSE(Result->CloseFailure.Failed());
        EXPECT_EQ(Result->DrainFailure.Native, Native);
        EXPECT_TRUE(Result->Retired);
        EXPECT_TRUE(Retirement->IsRetired());
        EXPECT_EQ(Storage->Pending(), 0U);
    }

    struct StreamQueueDrainResult final
    {
        bool WriteAccepted{false};
        bool Retired{false};
        Prism::Fault::Failure Failure;
    };

    struct SplitServerControlResult final
    {
        boost::system::error_code ChannelError;
        Prism::Fault::Failure Failure;
        bool Accepted{true};
    };

    auto ReceiveSplitServerControlFailure(
        const std::shared_ptr<Xhttp::Detail::SplitServerState> &State,
        const std::shared_ptr<SplitServerControlResult> &Result) -> Net::awaitable<void>
    {
        auto [Failure, Accepted] = co_await State->Ready->async_receive(
            Net::redirect_error(Net::use_awaitable, Result->ChannelError));
        Result->Failure = Failure;
        Result->Accepted = Accepted;
    }

    TEST(XhttpErrorMatrix, SplitServerControlFailureRejectsAdmission)
    {
        Net::io_context IoContext;
        const auto State = std::make_shared<Xhttp::Detail::SplitServerState>();
        State->Ready = std::make_shared<Xhttp::Detail::SplitReadyChannel>(
            IoContext.get_executor(), 1);
        const Prism::Fault::Failure Failure{Prism::Fault::Code::ProtocolError};
        Xhttp::Detail::FailSplitServerControl(State, Failure);
        const auto Result = std::make_shared<SplitServerControlResult>();

        RunCoroutine(IoContext, ReceiveSplitServerControlFailure(State, Result));

        EXPECT_FALSE(Result->ChannelError);
        EXPECT_EQ(Result->Failure.Code, Prism::Fault::Code::ProtocolError);
        EXPECT_FALSE(Result->Accepted);
        EXPECT_EQ(State->DriverFailure.Code, Prism::Fault::Code::ProtocolError);
        EXPECT_EQ(State->CloseFailure.Code, Prism::Fault::Code::ProtocolError);
    }

    TEST(XhttpErrorMatrix, StreamWriteQueueDrainReleasesPendingPayload)
    {
        Net::io_context IoContext;
        auto Queue = std::make_shared<Xhttp::Detail::Detail::StreamWriteQueue>(
            IoContext.get_executor(),
            Xhttp::Detail::Detail::StreamWriteQueue::WriteCallback{NoopWriter{}},
            Xhttp::Detail::Detail::StreamWriteQueue::FinishCallback{});
        auto Result = std::make_shared<StreamQueueDrainResult>();

        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
        {
            const std::array<Byte, 2> Payload{Byte{0x41}, Byte{0x42}};
            const auto Written = co_await Queue->Write(Payload);
            Result->WriteAccepted = Written && *Written == Payload.size();
            Queue->Close();
            const auto Drained = co_await Queue->Drain();
            if (!Drained) Result->Failure = Drained.error();
            Result->Retired = Queue->IsRetired();
        }());

        EXPECT_TRUE(Result->WriteAccepted);
        EXPECT_FALSE(Result->Failure.Failed());
        EXPECT_TRUE(Result->Retired);
    }

    struct SplitWriteCompletion final
    {
        explicit SplitWriteCompletion(Net::any_io_executor Executor)
            : Done(std::move(Executor), 1)
        {
        }

        CompletionSignal Done;
        std::error_code Error;
        std::size_t Bytes{0};
        std::exception_ptr Failure;
    };

    template <typename Awaitable>
    auto RunCoroutineUntilCompletion(Net::io_context &IoContext, Awaitable Coroutine) -> void
    {
        IoContext.restart();
        std::exception_ptr Exception;
        Net::co_spawn(
            IoContext, std::move(Coroutine),
            [&IoContext, &Exception](std::exception_ptr Error)
            {
                Exception = std::move(Error);
                IoContext.stop();
            });
        IoContext.run();
        if (Exception) std::rethrow_exception(Exception);
    }

    /** @brief 在挂起读取期间关闭 transport，并等待读取完成。 */
    auto CloseDuringPendingRead(
        Net::io_context &IoContext,
        const SharedTransport &Transport,
        const std::shared_ptr<ReadResult> &Result) -> Net::awaitable<void>
    {
        const auto ReadFinished = std::make_shared<CompletionSignal>(IoContext.get_executor(), 1);
        const auto ReadException = std::make_shared<std::exception_ptr>();
        Net::co_spawn(
            IoContext,
            ReadOnce(Transport, Result, 1),
            [ReadFinished, ReadException](std::exception_ptr Exception)
            {
                *ReadException = std::move(Exception);
                (void)ReadFinished->try_send(boost::system::error_code{});
            });
        const auto Activity = std::dynamic_pointer_cast<Prism::Transport::Detail::IoActivity>(
            Transport->Activity());
        while (Activity && Activity->IsIdle() && !Result->Completed)
        {
            co_await Net::post(IoContext, Net::use_awaitable);
        }
        Result->Admitted = Activity && !Activity->IsIdle();
        if (Result->Admitted)
        {
            co_await Net::post(IoContext, Net::use_awaitable);
        }
        const auto Closed = Transport->Close();
        EXPECT_TRUE(Closed);
        co_await ReadFinished->async_receive(Net::use_awaitable);
        if (*ReadException) std::rethrow_exception(*ReadException);
    }

    struct SplitTerminalErrorRequest final
    {
        Net::io_context &IoContext;
        std::shared_ptr<BlockingSplitWriteState> State;
        std::shared_ptr<Xhttp::Detail::SplitTransport> Transport;
        std::array<Byte, 2> First;
        std::array<Byte, 2> Second;
        std::shared_ptr<SplitWriteCompletion> FirstResult;
        std::shared_ptr<SplitWriteCompletion> SecondResult;
    };

    /** @brief 对两个在途写入发布首次终态错误并等候真实 completion。 */
    auto RunSplitTerminalError(SplitTerminalErrorRequest Request) -> Net::awaitable<void>
    {
        Net::co_spawn(
            Request.IoContext,
            Request.Transport->WriteSome(Request.First),
            [FirstResult = Request.FirstResult](std::exception_ptr Failure, Prism::IoResult Result)
            {
                FirstResult->Failure = std::move(Failure);
                FirstResult->Error = Prism::Fault::ToNative(Result.Failure);
                FirstResult->Bytes = Result.Bytes;
                (void)FirstResult->Done.try_send(boost::system::error_code{});
            });
        co_await Request.State->Started->async_receive(Net::use_awaitable);
        Net::co_spawn(
            Request.IoContext,
            Request.Transport->WriteSome(Request.Second),
            [SecondResult = Request.SecondResult](std::exception_ptr Failure, Prism::IoResult Result)
            {
                SecondResult->Failure = std::move(Failure);
                SecondResult->Error = Prism::Fault::ToNative(Result.Failure);
                SecondResult->Bytes = Result.Bytes;
                (void)SecondResult->Done.try_send(boost::system::error_code{});
            });
        co_await Net::post(Request.IoContext, Net::use_awaitable);
        Request.Transport->NotifyError(std::make_error_code(std::errc::protocol_error));
        co_await Request.SecondResult->Done.async_receive(Net::use_awaitable);
        (void)Request.State->Release->try_send(boost::system::error_code{});
        co_await Request.FirstResult->Done.async_receive(Net::use_awaitable);
    }

    /** @brief 写错误后等待挂起读取按既有 not-connected 语义完成。 */
    auto RunTransportWriteFailure(
        Net::io_context &IoContext,
        const SharedTransport &Transport,
        const std::shared_ptr<ReadResult> &Result) -> Net::awaitable<void>
    {
        auto Read = Net::co_spawn(
            IoContext, ReadOnce(Transport, Result, 1), Net::use_awaitable);
        co_await Net::post(IoContext, Net::use_awaitable);
        std::error_code ErrorCode;
        const std::array<Byte, 1> Payload{Byte{0x01}};
        const auto Write = co_await Transport->WriteSome(Payload);
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
        EXPECT_EQ(Write.Bytes, 0U);
        EXPECT_EQ(ErrorCode, std::make_error_code(std::errc::broken_pipe));
        co_await std::move(Read);
    }

    /** @brief 分别验证 HTTP/2 END_STREAM 与 RST 以及 Split 首个终态错误。 */
    auto RunH2EndStreamAndReset(
        Net::io_context &IoContext,
        const std::shared_ptr<Xhttp::Detail::ClientState> &Headers,
        const std::shared_ptr<Xhttp::Detail::ClientState> &Reset) -> Net::awaitable<void>
    {
        const Prism::Http2::HeaderList Response{{":status", "200"},
                                                   {"content-type", "text/event-stream"}};
        Xhttp::Detail::HandleClientHeaders(
            std::weak_ptr<Xhttp::Detail::ClientState>(Headers),
            Xhttp::Detail::ClientHeadersEvent{7, Response, true});
        std::array<Byte, 1> Buffer{};
        std::error_code EndError;
        const auto EndRead = co_await Headers->Transport->ReadSome(Buffer);
        EndError = Prism::Fault::ToNative(EndRead.Failure);
        EXPECT_EQ(EndRead.Bytes, 0U);
        EXPECT_FALSE(EndError);
        boost::system::error_code ResponseError;
        const auto [AcceptedFailure, Accepted] = co_await Headers->Response->async_receive(
            Net::redirect_error(Net::use_awaitable, ResponseError));
        EXPECT_FALSE(ResponseError);
        EXPECT_FALSE(AcceptedFailure.Failed());
        EXPECT_TRUE(Accepted);

        Xhttp::Detail::HandleClientClose(
            std::weak_ptr<Xhttp::Detail::ClientState>(Reset),
            Prism::Http2::StreamReceiveClosure{
                7, Prism::Http2::StreamReceiveClosureKind::Reset, 1U});
        std::error_code ResetError;
        const auto ResetRead = co_await Reset->Transport->ReadSome(Buffer);
        ResetError = Prism::Fault::ToNative(ResetRead.Failure);
        EXPECT_EQ(ResetRead.Bytes, 0U);
        EXPECT_EQ(ResetError, std::make_error_code(std::errc::protocol_error));

        const auto Split = std::make_shared<Xhttp::Detail::SplitTransport>(
            IoContext.get_executor(), Xhttp::Detail::SplitTransport::WriteCb(DiscardWire),
            Xhttp::Detail::SplitTransport::CloseCb{});
        Split->NotifyError(std::make_error_code(std::errc::protocol_error));
        Split->NotifyEof();
        std::error_code SplitError;
        const auto SplitRead = co_await Split->ReadSome(Buffer);
        SplitError = Prism::Fault::ToNative(SplitRead.Failure);
        EXPECT_EQ(SplitRead.Bytes, 0U);
        EXPECT_EQ(SplitError, std::make_error_code(std::errc::protocol_error));
        co_await CloseAndDrainTransmission(
            std::static_pointer_cast<Prism::Transmission>(Split));

        const auto Buffered = std::make_shared<Xhttp::Detail::SplitTransport>(
            IoContext.get_executor(), Xhttp::Detail::SplitTransport::WriteCb(DiscardWire),
            Xhttp::Detail::SplitTransport::CloseCb{});
        const std::array<Byte, 1> BufferedPayload{Byte{0x7F}};
        Buffered->Push(BufferedPayload);
        Buffered->NotifyError(std::make_error_code(std::errc::protocol_error));
        std::error_code BufferedError;
        const auto BufferedRead = co_await Buffered->ReadSome(Buffer);
        BufferedError = Prism::Fault::ToNative(BufferedRead.Failure);
        EXPECT_EQ(BufferedRead.Bytes, 0U);
        EXPECT_EQ(BufferedError, std::make_error_code(std::errc::protocol_error));
        co_await CloseAndDrainTransmission(
            std::static_pointer_cast<Prism::Transmission>(Buffered));
    }
TEST(XhttpErrorMatrix, TransportDataRoundtrip)
    {
        Net::io_context IoContext;
        const auto Transport = MakeTransport(IoContext.get_executor());
        const auto Result = std::make_shared<PayloadReadResult>();

        RunCoroutine(IoContext, DataRoundtripTask(Transport, Result));
        EXPECT_FALSE(Result->ErrorCode);
        EXPECT_EQ(AsStrView(ConstBytes{Result->Data}), "xhttp-Data");
        const auto Retirement = DrainTransport(IoContext, Transport);
        EXPECT_TRUE(Retirement.Failure.Succeeded());
        EXPECT_TRUE(Retirement.Retired);
    }

    TEST(XhttpErrorMatrix, TransportCloseWakesPendingReadAndOwner)
    {
        Net::io_context IoContext;
        const auto OwnerClosed = std::make_shared<bool>(false);
        const auto Transport = std::make_shared<Xhttp::Detail::XhttpTransport>(
            Xhttp::Detail::XhttpTransport::Options{
                .Executor = IoContext.get_executor(),
                .Write = Xhttp::Detail::XhttpTransport::WriteCb(NoopWriter{}),
                .CloseOwner = [OwnerClosed]() -> Prism::Fault::Failure
                { *OwnerClosed = true; return {}; }});
        const auto Result = std::make_shared<ReadResult>(1);

        RunCoroutine(IoContext, CloseDuringPendingRead(IoContext, Transport, Result));

        EXPECT_TRUE(Result->Admitted);
        EXPECT_EQ(Result->Count, 0U);
        EXPECT_EQ(Result->ErrorCode, std::make_error_code(std::errc::not_connected));
        EXPECT_TRUE(*OwnerClosed);
        const auto Retirement = DrainTransport(IoContext, Transport);
        EXPECT_TRUE(Retirement.Failure.Succeeded());
        EXPECT_TRUE(Retirement.Retired);
    }

    TEST(XhttpErrorMatrix, TransportClosePreservesFirstOwnerFailure)
    {
        Net::io_context IoContext;
        std::size_t CloseCalls = 0;
        const auto Transport = std::make_shared<Xhttp::Detail::XhttpTransport>(
            Xhttp::Detail::XhttpTransport::Options{
                .Executor = IoContext.get_executor(),
                .Write = Xhttp::Detail::XhttpTransport::WriteCb(NoopWriter{}),
                .CloseOwner = [&CloseCalls]() -> Prism::Fault::Failure
                {
                    ++CloseCalls;
                    throw std::runtime_error("first-close-failure");
                }});

        const auto CloseSubmitted = Transport->Close();
        EXPECT_TRUE(CloseSubmitted);
        const auto Retirement = std::make_shared<TransportRetirementResult>();
        RunCoroutineUntilCompletion(
            IoContext, CloseAndDrainTransportActivity(Transport, Retirement));
        EXPECT_EQ(CloseCalls, 1U);
        const auto CloseFailure = Transport->CloseFailure();
        EXPECT_EQ(CloseFailure.Code, Prism::Fault::Code::GenericError);

        const auto Closed = Transport->Close();
        EXPECT_FALSE(Closed);
        EXPECT_EQ(Closed.error().Code, Prism::Fault::Code::GenericError);
        EXPECT_EQ(CloseCalls, 1U);
        EXPECT_FALSE(Retirement->Retired);
        EXPECT_EQ(Retirement->Failure.Code, Prism::Fault::Code::GenericError);
    }

    TEST(XhttpErrorMatrix, SplitCloseOwnerAttemptsCancelWireAndEncryptedClose)
    {
        Net::io_context IoContext;
        Net::ssl::context SslContext(Net::ssl::context::tls_client);
        const auto Probe = std::make_shared<ThrowingRawProbe>();
        auto Raw = std::make_shared<ThrowingRaw>(IoContext.get_executor(), Probe);
        Prism::Transport::Connector Connector(Raw);
        auto Stream = std::make_shared<Prism::Transport::Encrypted::StreamType>(
            std::move(Connector), SslContext);
        auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8});
        auto Encrypted = std::make_shared<Prism::Transport::Encrypted>(
            std::move(Stream), std::move(Bytes));
        auto State = std::make_shared<Xhttp::Detail::SplitClientState>();
        State->Encrypted = Encrypted;
        State->Wire = std::make_shared<Xhttp::Detail::WireWriter>(
            IoContext.get_executor(), Xhttp::Detail::WireWriter::Sink(DiscardWire));

        const auto CloseFailure = Xhttp::Detail::SplitClientCloseHandler{State}();
        EXPECT_TRUE(CloseFailure.Succeeded());
        const auto EncryptedRetirement = std::make_shared<TransportRetirementResult>();
        RunCoroutineUntilCompletion(
            IoContext,
            DrainRawActivity(
                std::static_pointer_cast<Prism::Transmission>(Encrypted), EncryptedRetirement));
        EXPECT_EQ(Probe->CancelCalls, 1U);
        EXPECT_EQ(Probe->CloseCalls, 1U);
        EXPECT_EQ(EncryptedRetirement->Failure.Code, Prism::Fault::Code::Blocked);
        EXPECT_FALSE(EncryptedRetirement->Retired);
        EXPECT_TRUE(State->Wire->IsRetired());
    }

    TEST(XhttpErrorMatrix, SplitTerminalErrorWakesPendingWritesWithFirstError)
    {
        Net::io_context IoContext;
        const auto State = std::make_shared<BlockingSplitWriteState>();
        State->Release = std::make_shared<CompletionSignal>(IoContext.get_executor(), 1);
        State->Started = std::make_shared<CompletionSignal>(IoContext.get_executor(), 1);
        const auto Transport = std::make_shared<Xhttp::Detail::SplitTransport>(
            IoContext.get_executor(), Xhttp::Detail::SplitTransport::WriteCb{BlockingSplitWriter{State}},
            Xhttp::Detail::SplitTransport::CloseCb{});
        const std::array<Byte, 2> First{Byte{0x01}, Byte{0x02}};
        const std::array<Byte, 2> Second{Byte{0x03}, Byte{0x04}};


        const auto FirstResult = std::make_shared<SplitWriteCompletion>(IoContext.get_executor());
        const auto SecondResult = std::make_shared<SplitWriteCompletion>(IoContext.get_executor());
        RunCoroutine(IoContext, RunSplitTerminalError(SplitTerminalErrorRequest{IoContext, State, Transport, First, Second, FirstResult, SecondResult}));

        ASSERT_FALSE(FirstResult->Failure);
        ASSERT_FALSE(SecondResult->Failure);
        EXPECT_EQ(FirstResult->Bytes, First.size());
        EXPECT_EQ(SecondResult->Bytes, 0U);
        EXPECT_FALSE(FirstResult->Error);
        EXPECT_EQ(SecondResult->Error, std::make_error_code(std::errc::protocol_error));
        EXPECT_EQ(State->Calls, 1U);
        const auto Retirement = RetireRawTransport(
            IoContext, std::static_pointer_cast<Prism::Transmission>(Transport));
        EXPECT_TRUE(Retirement.Failure.Succeeded());
        EXPECT_TRUE(Retirement.Retired);
    }

    TEST(XhttpErrorMatrix, TransportWriteFailureWakesPendingRead)
    {
        Net::io_context IoContext;
        const auto Transport = std::make_shared<Xhttp::Detail::XhttpTransport>(
            Xhttp::Detail::XhttpTransport::Options{
                .Executor = IoContext.get_executor(),
                .Write = Xhttp::Detail::XhttpTransport::WriteCb(FailingWriter{})});
        Transport->BindStream(7);
        const auto Result = std::make_shared<ReadResult>(1);

        RunCoroutine(IoContext, RunTransportWriteFailure(IoContext, Transport, Result));

        EXPECT_EQ(Result->Count, 0U);
        EXPECT_EQ(Result->ErrorCode, std::make_error_code(std::errc::broken_pipe));
        const auto Retirement = DrainTransport(IoContext, Transport);
        EXPECT_TRUE(Retirement.Failure.Succeeded());
        EXPECT_TRUE(Retirement.Retired);
    }

    TEST(XhttpErrorMatrix, H2EndStreamAndResetRemainDistinct)
    {
        Net::io_context IoContext;
        const auto Headers = std::make_shared<Xhttp::Detail::ClientState>();
        Headers->Transport = MakeTransport(IoContext.get_executor());
        Headers->Transport->BindStream(7);
        Headers->Response = std::make_shared<Xhttp::Detail::ResponseChannel>(IoContext.get_executor(), 1);
        const auto Reset = std::make_shared<Xhttp::Detail::ClientState>();
        Reset->Transport = MakeTransport(IoContext.get_executor());
        Reset->Transport->BindStream(7);
        Reset->Response = std::make_shared<Xhttp::Detail::ResponseChannel>(IoContext.get_executor(), 1);

        RunCoroutine(IoContext, RunH2EndStreamAndReset(IoContext, Headers, Reset));
        const auto HeaderRetirement = DrainTransport(IoContext, Headers->Transport);
        const auto ResetRetirement = DrainTransport(IoContext, Reset->Transport);
        EXPECT_TRUE(HeaderRetirement.Failure.Succeeded());
        EXPECT_TRUE(HeaderRetirement.Retired);
        EXPECT_TRUE(ResetRetirement.Failure.Succeeded());
        EXPECT_TRUE(ResetRetirement.Retired);
    }

