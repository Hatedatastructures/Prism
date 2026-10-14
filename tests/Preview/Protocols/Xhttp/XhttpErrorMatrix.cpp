#include "XhttpErrorMatrixSupport.hpp"

    TEST(XhttpErrorMatrix, ConfigEnabledBoundary)
    {
        Xhttp::Config Config;
        EXPECT_TRUE(Config.Enabled());

        Xhttp::Config Empty;
        Empty.Path.clear();
        EXPECT_FALSE(Empty.Enabled());

        Xhttp::Config Custom;
        Custom.Path = "/custom";
        EXPECT_TRUE(Custom.Enabled());
    }
    TEST(XhttpErrorMatrix, TransportEofAndClose)
    {
        Net::io_context IoContext;
        const auto ClosedTransport = MakeTransport(IoContext.get_executor());
        const auto CloseResult = ClosedTransport->Close();
        EXPECT_TRUE(CloseResult);
        const auto ClosedResult = std::make_shared<ReadResult>(16);
        RunCoroutine(IoContext, ReadOnce(ClosedTransport, ClosedResult, 16));
        EXPECT_EQ(ClosedResult->Count, 0U);
        EXPECT_EQ(ClosedResult->ErrorCode, std::make_error_code(std::errc::not_connected));
        const auto ClosedRetirement = DrainTransport(IoContext, ClosedTransport);
        EXPECT_TRUE(ClosedRetirement.Failure.Succeeded());
        EXPECT_TRUE(ClosedRetirement.Retired);

        const auto EofTransport = MakeTransport(IoContext.get_executor());
        EofTransport->NotifyEof();
        const auto EofResult = std::make_shared<ReadResult>(16);
        RunCoroutine(IoContext, ReadOnce(EofTransport, EofResult, 16));
        EXPECT_EQ(EofResult->Count, 0U);
        EXPECT_FALSE(EofResult->ErrorCode);

        EofResult->ErrorCode.clear();
        RunCoroutine(IoContext, ReadOnce(EofTransport, EofResult, 16));
        EXPECT_EQ(EofResult->Count, 0U);
        EXPECT_EQ(EofResult->ErrorCode, Preview::make_error_code(PreviewError::UnexpectedEof));
        const auto EofRetirement = DrainTransport(IoContext, EofTransport);
        EXPECT_TRUE(EofRetirement.Failure.Succeeded());
        EXPECT_TRUE(EofRetirement.Retired);
    }
    auto RunSplitServerDownloadClosure(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        const auto State = std::make_shared<Xhttp::Detail::SplitServerState>();
        State->DownloadStream = 7;
        State->Transport = std::make_shared<Xhttp::Detail::SplitTransport>(
            IoContext.get_executor(), Xhttp::Detail::SplitTransport::WriteCb(DiscardWire),
            Xhttp::Detail::SplitTransport::CloseCb{});
        Xhttp::Detail::HandleSplitServerClose(
            State, Preview::Http2::StreamReceiveClosure{
                State->DownloadStream,
                Preview::Http2::StreamReceiveClosureKind::EndStream,
                Preview::Http2::ErrorNoError});

        const auto ReadResultValue = std::make_shared<ReadResult>(1);
        const auto ReadDone = std::make_shared<CompletionSignal>(IoContext.get_executor(), 1);
        auto ReadFailure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(
            IoContext,
            ReadOnce(State->Transport, ReadResultValue, 1),
            [ReadDone, ReadFailure](std::exception_ptr Failure)
            {
                *ReadFailure = std::move(Failure);
                (void)ReadDone->try_send(boost::system::error_code{});
            });
        co_await Net::post(IoContext, Net::use_awaitable);
        EXPECT_FALSE(ReadResultValue->Completed);

        const std::array<Byte, 1> Payload{Byte{0x4D}};
        State->Transport->Push(Payload);
        co_await ReadDone->async_receive(Net::use_awaitable);
        EXPECT_FALSE(*ReadFailure);
        EXPECT_TRUE(ReadResultValue->Completed);
        EXPECT_EQ(ReadResultValue->Count, 1U);
        EXPECT_FALSE(ReadResultValue->ErrorCode);
        EXPECT_EQ(ReadResultValue->Buffer[0], Payload[0]);
        const auto StateClosed = State->Transport->Close();
        EXPECT_TRUE(StateClosed);
        const auto StateActivity = State->Transport->Activity();
        const auto StateDrain = co_await StateActivity->Drain();
        EXPECT_TRUE(StateDrain);
        EXPECT_TRUE(StateActivity->IsRetired());

        const auto Reset = std::make_shared<Xhttp::Detail::SplitServerState>();
        Reset->DownloadStream = 7;
        Reset->Transport = std::make_shared<Xhttp::Detail::SplitTransport>(
            IoContext.get_executor(), Xhttp::Detail::SplitTransport::WriteCb(DiscardWire),
            Xhttp::Detail::SplitTransport::CloseCb{});
        Xhttp::Detail::HandleSplitServerClose(
            Reset, Preview::Http2::StreamReceiveClosure{
                Reset->DownloadStream,
                Preview::Http2::StreamReceiveClosureKind::Reset,
                1U});
        std::array<Byte, 1> Buffer{};
        std::error_code ResetError;
        const auto ResetRead = co_await Reset->Transport->ReadSome(Buffer);
        ResetError = Preview::Fault::ToNative(ResetRead.Failure);
        EXPECT_EQ(ResetRead.Bytes, 0U);
        EXPECT_EQ(ResetError, std::make_error_code(std::errc::protocol_error));
        const auto ResetClosed = Reset->Transport->Close();
        EXPECT_TRUE(ResetClosed);
        const auto ResetActivity = Reset->Transport->Activity();
        const auto ResetDrain = co_await ResetActivity->Drain();
        EXPECT_TRUE(ResetDrain);
        EXPECT_TRUE(ResetActivity->IsRetired());
    }

    TEST(XhttpErrorMatrix, SplitServerDownloadRequestEndPreservesReadAndRejectsRst)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunSplitServerDownloadClosure(IoContext));
    }
    TEST(XhttpErrorMatrix, TransportReadsPartialBlocks)
    {
        Net::io_context IoContext;
        const auto Transport = MakeTransport(IoContext.get_executor());
        const std::string Payload = "xhttp-partial-payload";
        Transport->Push(AsBytesSpan(std::string_view(Payload)));

        const auto Result = std::make_shared<ChunkedReadResult>();
        RunCoroutine(IoContext, ReadChunks(ChunkedReadRequest{
            Transport, Result, 4, Payload.size()}));
        EXPECT_FALSE(Result->ErrorCode);
        EXPECT_EQ(Result->Calls, 6U);
        EXPECT_EQ(AsStrView(ConstBytes{Result->Data}), Payload);
        const auto Retirement = DrainTransport(IoContext, Transport);
        EXPECT_TRUE(Retirement.Failure.Succeeded());
        EXPECT_TRUE(Retirement.Retired);
    }
    TEST(XhttpErrorMatrix, TransportWriteBufferedUntilBind)
    {
        Net::io_context IoContext;
        const auto State = std::make_shared<BufferedWriteState>();
        State->Completion = std::make_shared<CompletionSignal>(IoContext.get_executor(), 1);
        const auto Transport = std::make_shared<Xhttp::Detail::XhttpTransport>(
            Xhttp::Detail::XhttpTransport::Options{
                .Executor = IoContext.get_executor(),
                .Write = Xhttp::Detail::XhttpTransport::WriteCb(BufferedWriter{State})});

        const std::string Payload = "buffered";
        RunCoroutine(IoContext, BufferedWriteTask(Transport, State, Payload));
        EXPECT_EQ(State->StreamId, 7);
        EXPECT_EQ(State->Data, Payload);
        const auto Retirement = DrainTransport(IoContext, Transport);
        EXPECT_TRUE(Retirement.Failure.Succeeded());
        EXPECT_TRUE(Retirement.Retired);
    }

    TEST(XhttpErrorMatrix, TransportSerializesConcurrentWrites)
    {
        Net::io_context IoContext;
        const auto Probe = std::make_shared<WriteProbe>();
        const auto Transport = std::make_shared<Xhttp::Detail::XhttpTransport>(
            Xhttp::Detail::XhttpTransport::Options{
                .Executor = IoContext.get_executor(),
                .Write = MakeTransportProbe(IoContext.get_executor(), Probe)});
        Transport->BindStream(7);

        RunCoroutine(IoContext, RunConcurrentTransportWrites(Transport, Probe));
        EXPECT_FALSE(Probe->Failed);
        EXPECT_EQ(Probe->Completed, 2U);
        EXPECT_EQ(Probe->MaxActive, 1U);
        EXPECT_EQ(Probe->Order, "AB");
        const auto Retirement = DrainTransport(IoContext, Transport);
        EXPECT_TRUE(Retirement.Failure.Succeeded());
        EXPECT_TRUE(Retirement.Retired);
    }

    TEST(XhttpErrorMatrix, WireWriterSerializesPhysicalWrites)
    {
        Net::io_context IoContext;
        const auto Probe = std::make_shared<WriteProbe>();
        const auto Writer = std::make_shared<Xhttp::Detail::WireWriter>(
            IoContext.get_executor(), MakeWireProbe(IoContext.get_executor(), Probe));

        RunCoroutine(IoContext, RunConcurrentWireWrites(IoContext.get_executor(), Writer, Probe));
        EXPECT_FALSE(Probe->Failed);
        EXPECT_EQ(Probe->Completed, 2U);
        EXPECT_EQ(Probe->MaxActive, 1U);
        EXPECT_EQ(Probe->Order, "AB");
        const auto Retirement = RetireWireWriter(IoContext, Writer);
        EXPECT_TRUE(Retirement.Failure.Succeeded());
        EXPECT_TRUE(Retirement.Retired);
    }

    TEST(XhttpErrorMatrix, TransportWriteErrorCloses)
    {
        Net::io_context IoContext;
        const auto Transport = std::make_shared<Xhttp::Detail::XhttpTransport>(
            Xhttp::Detail::XhttpTransport::Options{
                .Executor = IoContext.get_executor(),
                .Write = Xhttp::Detail::XhttpTransport::WriteCb(FailingWriter{})});
        const auto Result = std::make_shared<WriteErrorResult>();

        RunCoroutine(IoContext, WriteErrorTask(Transport, Result));
        EXPECT_EQ(Result->FirstCount, 0U);
        EXPECT_EQ(Result->FirstError, std::make_error_code(std::errc::broken_pipe));
        EXPECT_EQ(Result->SecondCount, 0U);
        EXPECT_EQ(Result->SecondError, std::make_error_code(std::errc::not_connected));
        const auto Retirement = DrainTransport(IoContext, Transport);
        EXPECT_TRUE(Retirement.Failure.Succeeded());
        EXPECT_TRUE(Retirement.Retired);
    }

    TEST(XhttpErrorMatrix, TransportFinishHalfClosesWrites)
    {
        Net::io_context IoContext;
        const auto State = std::make_shared<FinishState>();
        const auto Transport = std::make_shared<Xhttp::Detail::XhttpTransport>(
            Xhttp::Detail::XhttpTransport::Options{
                .Executor = IoContext.get_executor(),
                .Write = Xhttp::Detail::XhttpTransport::WriteCb(NoopWriter{}),
                .Finish = Xhttp::Detail::XhttpTransport::FinishCb(FinishWriter{State})});
        const auto Result = std::make_shared<FinishResult>();

        RunCoroutine(IoContext, FinishTask(Transport, Result));
        EXPECT_TRUE(Result->Finished);
        EXPECT_EQ(State->StreamId, 7);
        EXPECT_EQ(State->Calls, 1U);
        EXPECT_EQ(Result->WriteCount, 0U);
        EXPECT_EQ(Result->WriteError, std::make_error_code(std::errc::not_connected));
        EXPECT_TRUE(Result->SecondFinishFailed);
        EXPECT_EQ(Result->SecondFinishError, std::make_error_code(std::errc::not_connected));
        const auto Retirement = DrainTransport(IoContext, Transport);
        EXPECT_TRUE(Retirement.Failure.Succeeded());
        EXPECT_TRUE(Retirement.Retired);
    }

    TEST(XhttpErrorMatrix, TransportChannelBackpressureCloses)
    {
        Net::io_context IoContext;
        const auto Transport = MakeTransport(IoContext.get_executor());
        const std::array<Byte, 1> Payload{Byte{0x01}};
        for (std::size_t Index = 0; Index < 65; ++Index)
        {
            Transport->Push(Payload);
        }

        const auto Result = std::make_shared<ReadResult>(1);
        RunCoroutine(IoContext, ReadOnce(Transport, Result, 1));
        EXPECT_EQ(Result->Count, 0U);
        EXPECT_EQ(Result->ErrorCode, std::make_error_code(std::errc::not_connected));
        const auto Retirement = DrainTransport(IoContext, Transport);
        EXPECT_TRUE(Retirement.Failure.Succeeded());
        EXPECT_TRUE(Retirement.Retired);
    }

    TEST(XhttpErrorMatrix, WireWriterRejectsShortWrite)
    {
        Net::io_context IoContext;
        const auto Raw = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        Raw->MaxWrite = 2;
        const auto Writer = std::make_shared<Xhttp::Detail::WireWriter>(
            IoContext.get_executor(), Xhttp::Detail::WireWriter::Sink(TransmissionSink{Raw}));
        const auto Result = std::make_shared<WireFailureResult>();

        RunCoroutine(IoContext, WireFailureTask(Writer, Result));
        EXPECT_TRUE(Result->FirstFailed);
        EXPECT_EQ(Result->FirstError.value(), std::make_error_code(std::errc::io_error).value());
        EXPECT_TRUE(Result->SecondFailed);
        EXPECT_EQ(Result->SecondError.value(), std::make_error_code(std::errc::not_connected).value());
        const auto WriterRetirement = RetireWireWriter(IoContext, Writer);
        const auto RawRetirement = RetireRawTransport(IoContext, Raw);
        EXPECT_TRUE(WriterRetirement.Failure.Succeeded());
        EXPECT_TRUE(WriterRetirement.Retired);
        EXPECT_TRUE(RawRetirement.Failure.Succeeded());
        EXPECT_TRUE(RawRetirement.Retired);
    }
    TEST(XhttpErrorMatrix, WireWriterRejectsOverreportedWrite)
    {
        Net::io_context IoContext;
        const auto Raw = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        Raw->OverreportWrite = true;
        const auto Writer = std::make_shared<Xhttp::Detail::WireWriter>(
            IoContext.get_executor(), Xhttp::Detail::WireWriter::Sink(TransmissionSink{Raw}));
        const auto Result = std::make_shared<WireFailureResult>();

        RunCoroutine(IoContext, WireFailureTask(Writer, Result));
        EXPECT_TRUE(Result->FirstFailed);
        EXPECT_EQ(Result->FirstError.value(), std::make_error_code(std::errc::io_error).value());
        EXPECT_TRUE(Result->SecondFailed);
        EXPECT_EQ(Result->SecondError.value(), std::make_error_code(std::errc::not_connected).value());
        const auto WriterRetirement = RetireWireWriter(IoContext, Writer);
        const auto RawRetirement = RetireRawTransport(IoContext, Raw);
        EXPECT_TRUE(WriterRetirement.Failure.Succeeded());
        EXPECT_TRUE(WriterRetirement.Retired);
        EXPECT_TRUE(RawRetirement.Failure.Succeeded());
        EXPECT_TRUE(RawRetirement.Retired);
    }
