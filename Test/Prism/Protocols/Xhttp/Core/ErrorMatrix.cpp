/**
 * @file ErrorMatrix.cpp
 * @brief XHTTP 传输与 HTTP/2 读取终态顺序测试。
 */

#include "ErrorMatrixSupport.hpp"

#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Xhttp/Detail/Split/Transport.hpp>
#include <Prism/Protocols/Xhttp/Detail/Stream/Transport.hpp>
#include <Prism/Protocols/Xhttp/Detail/Http2/ReadCompletion.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/any_io_executor.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace
{
    auto MakeSettingsWire(const std::size_t FrameBytes) -> std::vector<std::byte>
    {
        constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        std::vector<std::byte> Wire;
        Wire.reserve(Preface.size() + 9U);
        for (const auto Character : Preface)
        {
            Wire.push_back(static_cast<std::byte>(Character));
        }
        constexpr std::byte SettingsFrame[]{
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{4}, std::byte{0},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}};
        Wire.insert(Wire.end(), SettingsFrame,
                    SettingsFrame + static_cast<std::ptrdiff_t>(FrameBytes));
        return Wire;
    }

    auto ProcessReadCompletion(
        Prism::Http2::Session &Session,
        const std::vector<std::byte> &Wire,
        Prism::Fault::Failure Failure) -> Prism::Fault::Failure
    {
        const auto Step = Prism::Xhttp::Detail::ProcessHttp2ReadCompletion(
            Session, std::span<const std::byte>(Wire),
            Prism::IoResult{Wire.size(), std::move(Failure)});
        return Step.Failure;
    }

    struct CloseCallbackState final
    {
        bool Called{false};
    };

    struct CloseProbe final
    {
        std::shared_ptr<CloseCallbackState> State;

        auto operator()() const -> Prism::Fault::Failure
        {
            State->Called = true;
            return {};
        }
    };

    struct ReadCompletionState final
    {
        std::array<std::byte, 1> Buffer{};
        Prism::IoResult Result{};
        bool Completed{false};
    };

    struct ReadCompletionHandler final
    {
        std::shared_ptr<ReadCompletionState> State;

        auto operator()(Prism::IoResult Result) const -> void
        {
            State->Result = std::move(Result);
            State->Completed = true;
        }
    };

    template <typename TransportType>
    auto StartRead(
        const std::shared_ptr<TransportType> &Transport,
        const std::shared_ptr<ReadCompletionState> &State) -> void
    {
        Transport->ReadSome(
            std::span<std::byte>(State->Buffer), ReadCompletionHandler{State});
    }

    template <typename TransportType>
    auto FillTransportChannel(const std::shared_ptr<TransportType> &Transport) -> void
    {
        const std::array<std::byte, 1> Payload{std::byte{0x71}};
        for (std::size_t Index = 0; Index < 65U; ++Index)
        {
            Transport->Push(Payload);
        }
    }

    auto MakeSplitTransport(
        Net::any_io_executor Executor,
        Xhttp::Detail::SplitTransport::CloseCb Close) -> std::shared_ptr<Xhttp::Detail::SplitTransport>
    {
        return std::make_shared<Xhttp::Detail::SplitTransport>(
            std::move(Executor), Xhttp::Detail::SplitTransport::WriteCb(DiscardWire),
            std::move(Close));
    }

    struct ReadTerminalObservation final
    {
        ByteVector Data;
        std::array<std::size_t, 6> Counts{};
        std::array<Prism::Fault::Failure, 2> Terminal{};
    };

    template <typename TransportType>
    auto ReadQueuedDataAndRepeatTerminal(
        const std::shared_ptr<TransportType> &Transport,
        const std::shared_ptr<ReadTerminalObservation> &Observation) -> Net::awaitable<void>
    {
        std::array<Byte, 2> Buffer{};
        for (std::size_t Index = 0; Index < Observation->Counts.size(); ++Index)
        {
            const auto Part = co_await Transport->ReadSome(Buffer);
            EXPECT_LE(Part.Bytes, Buffer.size());
            if (Part.Bytes > Buffer.size()) co_return;
            Observation->Counts[Index] = Part.Bytes;
            Observation->Data.insert(
                Observation->Data.end(), Buffer.begin(),
                Buffer.begin() + static_cast<std::ptrdiff_t>(Part.Bytes));
            if (Index >= 4) Observation->Terminal[Index - 4] = Part.Failure;
            if (Index < 4) EXPECT_FALSE(Part.Failure.Failed());
        }
    }

    auto ExpectReadTerminal(
        const Prism::Fault::Failure &Actual,
        const Prism::Fault::Failure &Expected) -> void
    {
        if (Expected.Succeeded())
        {
            EXPECT_TRUE(Actual.Succeeded());
            EXPECT_FALSE(Actual.Native);
            return;
        }
        EXPECT_EQ(Actual.Code, Expected.Code);
        if (Expected.Code != Prism::Fault::Code::Eof)
            EXPECT_EQ(Actual.Native, Expected.Native);
    }

    template <typename TransportType>
    auto VerifyQueuedReadTerminal(
        Net::io_context &IoContext,
        const std::shared_ptr<TransportType> &Transport,
        const Prism::Fault::Failure ExpectedFailure) -> void
    {
        const std::array<Byte, 3> First{Byte{'a'}, Byte{'b'}, Byte{'c'}};
        const std::array<Byte, 4> Second{Byte{'d'}, Byte{'e'}, Byte{'f'}, Byte{'g'}};
        Transport->Push(First);
        Transport->Push(Second);
        Transport->NotifyReadTerminal(ExpectedFailure);
        const auto Observation = std::make_shared<ReadTerminalObservation>();
        RunCoroutine(IoContext, ReadQueuedDataAndRepeatTerminal(Transport, Observation));

        const std::array<Byte, 7> ExpectedData{
            Byte{'a'}, Byte{'b'}, Byte{'c'}, Byte{'d'}, Byte{'e'}, Byte{'f'}, Byte{'g'}};
        EXPECT_EQ(Observation->Data, ByteVector(ExpectedData.begin(), ExpectedData.end()));
        EXPECT_EQ(Observation->Counts, (std::array<std::size_t, 6>{2U, 1U, 2U, 2U, 0U, 0U}));
        for (const auto &Terminal : Observation->Terminal)
            ExpectReadTerminal(Terminal, ExpectedFailure);
        const auto Retired = RetireRawTransport(IoContext, Transport);
        EXPECT_TRUE(Retired.Failure.Succeeded());
        EXPECT_TRUE(Retired.Retired);
    }

    template <typename TransportType>
    auto VerifyHttp2DataTerminal(
        Net::io_context &IoContext,
        const std::shared_ptr<TransportType> &Transport,
        const Prism::Fault::Failure ExpectedFailure) -> void
    {
        Prism::Http2::Session Sender(IoContext.get_executor(), false);
        Prism::Http2::Session Receiver(IoContext.get_executor(), true);
        Sender.SendSettings();
        const auto Stream = Sender.OpenStream({{":method", "POST"}, {":path", "/"}}, false);
        ASSERT_TRUE(Stream);
        const std::array<Byte, 7> Payload{
            Byte{'a'}, Byte{'b'}, Byte{'c'}, Byte{'d'}, Byte{'e'}, Byte{'f'}, Byte{'g'}};
        ASSERT_EQ(Sender.SubmitData(*Stream, Payload, true), Prism::Http2::SubmitDataStatus::Accepted);
        std::vector<Byte> Wire;
        ASSERT_TRUE(Sender.Collect(Wire));
        Receiver.OnData = [Transport](std::int32_t, const std::span<const Byte> Data)
        {
            Transport->Push(Data);
        };
        const auto Step = Prism::Xhttp::Detail::ProcessHttp2ReadCompletion(
            Receiver, Wire, Prism::IoResult{Wire.size(), ExpectedFailure});
        ASSERT_TRUE(Step.ReadTerminal);
        ExpectReadTerminal(Step.Failure, ExpectedFailure);
        Transport->NotifyReadTerminal(Step.Failure);
        const auto Observation = std::make_shared<ReadTerminalObservation>();
        RunCoroutine(IoContext, ReadQueuedDataAndRepeatTerminal(Transport, Observation));

        EXPECT_EQ(Observation->Data, ByteVector(Payload.begin(), Payload.end()));
        for (const auto &Terminal : Observation->Terminal)
            ExpectReadTerminal(Terminal, ExpectedFailure);
        const auto Retired = RetireRawTransport(IoContext, Transport);
        EXPECT_TRUE(Retired.Failure.Succeeded());
        EXPECT_TRUE(Retired.Retired);
    }
}

TEST(XhttpErrorMatrix, ReadCompletionFeedsSettingsBeforeEof)
{
    Net::io_context IoContext;
    Prism::Http2::Session Session(IoContext.get_executor(), true);
    const auto Wire = MakeSettingsWire(9U);

    const auto Step = Prism::Xhttp::Detail::ProcessHttp2ReadCompletion(
        Session, Wire, Prism::IoResult{Wire.size(), {Prism::Fault::Code::Eof}});
    EXPECT_TRUE(Step.ReadTerminal);
    EXPECT_EQ(Step.Failure.Code, Prism::Fault::Code::Eof);

    std::vector<std::byte> Output;
    ASSERT_TRUE(Session.Collect(Output));
    ASSERT_EQ(Output.size(), 9U);
    EXPECT_EQ(std::to_integer<unsigned char>(Output[3]), 4U);
    EXPECT_EQ(std::to_integer<unsigned char>(Output[4]), 1U);
}

TEST(XhttpErrorMatrix, ReadCompletionFeedsSettingsBeforeNativeFailure)
{
    Net::io_context IoContext;
    Prism::Http2::Session Session(IoContext.get_executor(), true);
    const auto Wire = MakeSettingsWire(9U);
    const auto NativeError = std::make_error_code(std::errc::connection_reset);

    const auto Failure = ProcessReadCompletion(
        Session, Wire, Prism::Fault::FromNative(NativeError));
    EXPECT_EQ(Prism::Fault::ToNative(Failure), NativeError);

    std::vector<std::byte> Output;
    ASSERT_TRUE(Session.Collect(Output));
    ASSERT_EQ(Output.size(), 9U);
    EXPECT_EQ(std::to_integer<unsigned char>(Output[3]), 4U);
    EXPECT_EQ(std::to_integer<unsigned char>(Output[4]), 1U);
}

TEST(XhttpErrorMatrix, ReadCompletionFeedsPartialSettingsBeforeEof)
{
    Net::io_context IoContext;
    Prism::Http2::Session Session(IoContext.get_executor(), true);
    const auto Wire = MakeSettingsWire(4U);

    const auto Step = Prism::Xhttp::Detail::ProcessHttp2ReadCompletion(
        Session, Wire, Prism::IoResult{Wire.size(), {Prism::Fault::Code::Eof}});
    EXPECT_TRUE(Step.ReadTerminal);
    EXPECT_EQ(Step.Failure.Code, Prism::Fault::Code::Eof);

    const auto CompleteWire = MakeSettingsWire(9U);
    const auto Remainder = std::span<const std::byte>(CompleteWire).subspan(Wire.size());
    std::error_code FrameError;
    ASSERT_TRUE(Session.Feed(Remainder, FrameError)) << FrameError.message();
    EXPECT_FALSE(FrameError);

    std::vector<std::byte> Output;
    ASSERT_TRUE(Session.Collect(Output));
    ASSERT_EQ(Output.size(), 9U);
    EXPECT_EQ(std::to_integer<unsigned char>(Output[3]), 4U);
    EXPECT_EQ(std::to_integer<unsigned char>(Output[4]), 1U);
}

TEST(XhttpErrorMatrix, ReadCompletionDoesNotTreatZeroSuccessAsEof)
{
    Net::io_context IoContext;
    Prism::Http2::Session Session(IoContext.get_executor(), true);
    const auto Step = Prism::Xhttp::Detail::ProcessHttp2ReadCompletion(
        Session, std::span<const Byte>{}, Prism::IoResult{0U, {}});

    EXPECT_TRUE(Step.ReadTerminal);
    EXPECT_EQ(Step.Failure.Code, Prism::Fault::Code::WouldBlock);
}

TEST(XhttpErrorMatrix, ReadCompletionFeedFailurePrecedesNativeFailure)
{
    Net::io_context IoContext;
    Prism::Http2::Session Session(IoContext.get_executor(), true);
    auto Wire = MakeSettingsWire(9U);
    Wire[0] = std::byte{0x42};
    const auto NativeError = std::make_error_code(std::errc::connection_reset);

    const auto Failure = ProcessReadCompletion(
        Session, Wire, Prism::Fault::FromNative(NativeError));
    EXPECT_EQ(Prism::Fault::ToNative(Failure),
              Prism::make_error_code(Prism::Error::ProtocolError));
}

TEST(XhttpErrorMatrix, ReadCompletionRejectsBytesBeyondBuffer)
{
    Net::io_context IoContext;
    Prism::Http2::Session Session(IoContext.get_executor(), true);
    const std::array<std::byte, 1> Buffer{};

    const auto Failure = Prism::Xhttp::Detail::ProcessHttp2ReadCompletion(
        Session, std::span<const std::byte>(Buffer), Prism::IoResult{2U, {}});
    EXPECT_EQ(Failure.Failure.Code, Prism::Fault::Code::InvalidArgument);
    EXPECT_FALSE(Failure.ReadTerminal);
}

TEST(XhttpErrorMatrix, ReadCompletionMarksBytesBeforeNativeTerminal)
{
    Net::io_context IoContext;
    Prism::Http2::Session Session(IoContext.get_executor(), true);
    const auto Wire = MakeSettingsWire(9U);
    const auto Native = std::make_error_code(std::errc::connection_reset);

    const auto Step = Prism::Xhttp::Detail::ProcessHttp2ReadCompletion(
        Session, Wire, Prism::IoResult{Wire.size(), Prism::Fault::FromNative(Native)});

    EXPECT_TRUE(Step.ReadTerminal);
    EXPECT_EQ(Prism::Fault::ToNative(Step.Failure), Native);
}

TEST(XhttpErrorMatrix, ReadCompletionKeepsFeedFailureFailFast)
{
    Net::io_context IoContext;
    Prism::Http2::Session Session(IoContext.get_executor(), true);
    auto Wire = MakeSettingsWire(9U);
    Wire[0] = std::byte{0x42};
    const auto Native = std::make_error_code(std::errc::connection_reset);

    const auto Step = Prism::Xhttp::Detail::ProcessHttp2ReadCompletion(
        Session, Wire, Prism::IoResult{Wire.size(), Prism::Fault::FromNative(Native)});

    EXPECT_FALSE(Step.ReadTerminal);
    EXPECT_EQ(Prism::Fault::ToNative(Step.Failure),
              Prism::make_error_code(Prism::Error::ProtocolError));
}

TEST(XhttpErrorMatrix, StreamTransportDrainsAcceptedDataBeforeNativeReadFailure)
{
    Net::io_context IoContext;
    auto Transport = MakeTransport(IoContext.get_executor());
    VerifyQueuedReadTerminal(
        IoContext, Transport,
        Prism::Fault::FromNative(std::make_error_code(std::errc::connection_reset)));
}

TEST(XhttpErrorMatrix, StreamTransportDrainsAcceptedDataBeforeCanceledRead)
{
    Net::io_context IoContext;
    auto Transport = MakeTransport(IoContext.get_executor());
    VerifyQueuedReadTerminal(
        IoContext, Transport,
        Prism::Fault::FromNative(std::make_error_code(std::errc::operation_canceled)));
}

TEST(XhttpErrorMatrix, StreamTransportDrainsAcceptedDataBeforeReadEof)
{
    Net::io_context IoContext;
    VerifyHttp2DataTerminal(
        IoContext, MakeTransport(IoContext.get_executor()),
        Prism::Fault::Failure{Prism::Fault::Code::Eof});
}

TEST(XhttpErrorMatrix, SplitTransportDrainsAcceptedDataBeforeNativeReadFailure)
{
    Net::io_context IoContext;
    const auto Transport = MakeSplitTransport(IoContext.get_executor(), {});
    VerifyQueuedReadTerminal(
        IoContext, Transport,
        Prism::Fault::FromNative(std::make_error_code(std::errc::connection_reset)));
}

TEST(XhttpErrorMatrix, SplitTransportDrainsAcceptedDataBeforeCanceledRead)
{
    Net::io_context IoContext;
    const auto Transport = MakeSplitTransport(IoContext.get_executor(), {});
    VerifyQueuedReadTerminal(
        IoContext, Transport,
        Prism::Fault::FromNative(std::make_error_code(std::errc::operation_canceled)));
}

TEST(XhttpErrorMatrix, SplitTransportDrainsAcceptedDataBeforeReadEof)
{
    Net::io_context IoContext;
    VerifyHttp2DataTerminal(
        IoContext, MakeSplitTransport(IoContext.get_executor(), {}),
        Prism::Fault::Failure{Prism::Fault::Code::Eof});
}

TEST(XhttpErrorMatrix, StreamTransportQueuesSessionDataBeforeSameReadReset)
{
    Net::io_context IoContext;
    VerifyHttp2DataTerminal(
        IoContext, MakeTransport(IoContext.get_executor()),
        Prism::Fault::FromNative(std::make_error_code(std::errc::connection_reset)));
}

TEST(XhttpErrorMatrix, SplitTransportQueuesSessionDataBeforeSameReadReset)
{
    Net::io_context IoContext;
    VerifyHttp2DataTerminal(
        IoContext, MakeSplitTransport(IoContext.get_executor(), {}),
        Prism::Fault::FromNative(std::make_error_code(std::errc::connection_reset)));
}

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
        EXPECT_EQ(ClosedResult->ErrorCode,
                  Prism::Fault::make_error_code(Prism::Fault::Code::Canceled));
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
        EXPECT_EQ(EofResult->ErrorCode, Prism::make_error_code(PrismError::UnexpectedEof));
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
            State, Prism::Http2::StreamReceiveClosure{
                State->DownloadStream,
                Prism::Http2::StreamReceiveClosureKind::EndStream,
                Prism::Http2::ErrorNoError});

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
            Reset, Prism::Http2::StreamReceiveClosure{
                Reset->DownloadStream,
                Prism::Http2::StreamReceiveClosureKind::Reset,
                1U});
        std::array<Byte, 1> Buffer{};
        std::error_code ResetError;
        const auto ResetRead = co_await Reset->Transport->ReadSome(Buffer);
        ResetError = Prism::Fault::ToNative(ResetRead.Failure);
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
        const auto CloseState = std::make_shared<CloseCallbackState>();
        const auto Transport = std::make_shared<Xhttp::Detail::XhttpTransport>(
            Xhttp::Detail::XhttpTransport::Options{
                .Executor = IoContext.get_executor(),
                .Write = Xhttp::Detail::XhttpTransport::WriteCb(NoopWriter{}),
                .CloseOwner = Xhttp::Detail::XhttpTransport::CloseCb(CloseProbe{CloseState})});
        const std::array<Byte, 1> Payload{Byte{0x01}};
        for (std::size_t Index = 0; Index < 65; ++Index)
        {
            Transport->Push(Payload);
        }

        const auto Result = std::make_shared<ReadResult>(1);
        RunCoroutine(IoContext, ReadOnce(Transport, Result, 1));
        EXPECT_EQ(Result->Count, 0U);
        EXPECT_EQ(Result->ErrorCode,
                  Prism::Fault::make_error_code(Prism::Fault::Code::Canceled));
        const auto Retirement = DrainTransport(IoContext, Transport);
        EXPECT_TRUE(Retirement.Failure.Succeeded());
        EXPECT_TRUE(Retirement.Retired);
        EXPECT_TRUE(CloseState->Called);
        EXPECT_TRUE(Transport->CloseFailure().Succeeded());
    }

    TEST(XhttpErrorMatrix, StreamTransportOverflowReportsCloseRejectionBeforeQueuedData)
    {
        Net::io_context IoContext;
        const auto CloseState = std::make_shared<CloseCallbackState>();
        const auto Transport = std::make_shared<Xhttp::Detail::XhttpTransport>(
            Xhttp::Detail::XhttpTransport::Options{
                .Executor = IoContext.get_executor(),
                .Write = Xhttp::Detail::XhttpTransport::WriteCb(NoopWriter{}),
                .CloseOwner = Xhttp::Detail::XhttpTransport::CloseCb(
                    CloseProbe{CloseState})});
        const auto Read = std::make_shared<ReadCompletionState>();
        StartRead(Transport, Read);
        const auto Activity = Transport->Activity();
        Activity->Seal();

        FillTransportChannel(Transport);
        IoContext.run();

        ASSERT_TRUE(Read->Completed);
        EXPECT_EQ(Read->Result.Bytes, 0U);
        EXPECT_EQ(Prism::Fault::ToNative(Read->Result.Failure),
                  Prism::Fault::make_error_code(Prism::Fault::Code::Canceled));
        EXPECT_EQ(Transport->CloseFailure().Code, Prism::Fault::Code::Canceled);
        EXPECT_FALSE(CloseState->Called);
    }

    TEST(XhttpErrorMatrix, SplitTransportPushClosesAfterChannelBackpressure)
    {
        Net::io_context IoContext;
        const auto CloseState = std::make_shared<CloseCallbackState>();
        const auto Transport = MakeSplitTransport(
            IoContext.get_executor(), Xhttp::Detail::SplitTransport::CloseCb(CloseProbe{CloseState}));

        FillTransportChannel(Transport);
        IoContext.run();

        EXPECT_TRUE(CloseState->Called);
        EXPECT_TRUE(Transport->Activity()->IsRetired());
    }

    TEST(XhttpErrorMatrix, SplitTransportOverflowReportsCloseRejectionBeforeQueuedData)
    {
        Net::io_context IoContext;
        const auto CloseState = std::make_shared<CloseCallbackState>();
        const auto Transport = MakeSplitTransport(
            IoContext.get_executor(),
            Xhttp::Detail::SplitTransport::CloseCb(CloseProbe{CloseState}));
        const auto Read = std::make_shared<ReadCompletionState>();
        StartRead(Transport, Read);
        Transport->Activity()->Seal();

        FillTransportChannel(Transport);
        IoContext.run();

        ASSERT_TRUE(Read->Completed);
        EXPECT_EQ(Read->Result.Bytes, 0U);
        EXPECT_EQ(Prism::Fault::ToNative(Read->Result.Failure),
                  Prism::Fault::make_error_code(Prism::Fault::Code::Canceled));
        EXPECT_FALSE(CloseState->Called);
    }

    TEST(XhttpErrorMatrix, WireWriterRejectsShortWrite)
    {
        Net::io_context IoContext;
        const auto Raw = std::make_shared<Prism::PrismMockTransport>(IoContext.get_executor());
        Raw->MaxWrite = 2;
        const auto Writer = std::make_shared<Xhttp::Detail::WireWriter>(
            IoContext.get_executor(), Xhttp::Detail::WireWriter::Sink(TransmissionSink{Raw}));
        const auto Result = std::make_shared<WireFailureResult>();

        RunCoroutine(IoContext, WireFailureTask(Writer, Result));
        EXPECT_TRUE(Result->FirstFailed);
        EXPECT_EQ(Result->FirstError,
                  Prism::Fault::make_error_code(Prism::Fault::Code::IoError));
        EXPECT_TRUE(Result->SecondFailed);
        EXPECT_EQ(Result->SecondError.value(), std::make_error_code(std::errc::not_connected).value());
        const auto WriterRetirement = RetireWireWriter(IoContext, Writer);
        const auto RawRetirement = RetireRawTransport(IoContext, Raw);
        EXPECT_EQ(WriterRetirement.Failure.Code, Prism::Fault::Code::IoError);
        EXPECT_TRUE(WriterRetirement.Retired);
        EXPECT_TRUE(RawRetirement.Failure.Succeeded());
        EXPECT_TRUE(RawRetirement.Retired);
    }
    TEST(XhttpErrorMatrix, WireWriterRejectsOverreportedWrite)
    {
        Net::io_context IoContext;
        const auto Raw = std::make_shared<Prism::PrismMockTransport>(IoContext.get_executor());
        Raw->OverreportWrite = true;
        const auto Writer = std::make_shared<Xhttp::Detail::WireWriter>(
            IoContext.get_executor(), Xhttp::Detail::WireWriter::Sink(TransmissionSink{Raw}));
        const auto Result = std::make_shared<WireFailureResult>();

        RunCoroutine(IoContext, WireFailureTask(Writer, Result));
        EXPECT_TRUE(Result->FirstFailed);
        EXPECT_EQ(Result->FirstError,
                  Prism::Fault::make_error_code(Prism::Fault::Code::IoError));
        EXPECT_TRUE(Result->SecondFailed);
        EXPECT_EQ(Result->SecondError.value(), std::make_error_code(std::errc::not_connected).value());
        const auto WriterRetirement = RetireWireWriter(IoContext, Writer);
        const auto RawRetirement = RetireRawTransport(IoContext, Raw);
        EXPECT_EQ(WriterRetirement.Failure.Code, Prism::Fault::Code::IoError);
        EXPECT_TRUE(WriterRetirement.Retired);
        EXPECT_TRUE(RawRetirement.Failure.Succeeded());
        EXPECT_TRUE(RawRetirement.Retired);
    }
