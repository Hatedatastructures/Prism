/**
 * @file XhttpErrorMatrix.cpp
 * @brief XHTTP 错误矩阵与传输层边界测试
 * @details 覆盖：
 *          - Config 边界（空 Path 禁用 / 非空启用）
 *          - XhttpTransport：半包读取、EOF、关闭、写缓冲和数据往返
 *          - 写入错误码、写失败后的 close、Finish 半关闭
 *          - WireWriter：串行写入、短写与 over-report 拒绝
 * @note 测试协程均由调用方等待完成，不使用分离式任务或定时器轮询。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Protocols/Xhttp/Conn.hpp>
#include <Preview/Protocols/Xhttp/Types.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Xhttp = Preview::Xhttp;

    using Byte = std::byte;
    using ByteVector = std::vector<Byte>;
    using ConstBytes = std::span<const Byte>;
    using PreviewError = Preview::Error;
    using SharedTransport = std::shared_ptr<Xhttp::XhttpTransport>;
    using CompletionSignal = Net::experimental::channel<void(boost::system::error_code)>;

    using Preview::AsBytesSpan;
    using Preview::AsStrView;

    struct CoroutineCompletionHandler final
    {
        std::exception_ptr *Exception;
        Net::io_context *IoContext;

        auto operator()(std::exception_ptr ErrorValue) const -> void
        {
            *Exception = ErrorValue;
            IoContext->stop();
        }
    };

    template <typename Awaitable>
    auto RunCoroutine(Net::io_context &IoContext, Awaitable Coroutine) -> void
    {
        IoContext.restart();
        std::exception_ptr Exception;
        const CoroutineCompletionHandler CompletionHandler{&Exception, &IoContext};
        Net::co_spawn(IoContext, std::move(Coroutine), CompletionHandler);
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    struct ReadResult final
    {
        explicit ReadResult(const std::size_t BufferSize)
            : Buffer(BufferSize)
        {
        }

        ByteVector Buffer;
        std::size_t Count{0};
        std::error_code ErrorCode;
    };

    auto ReadOnce(const SharedTransport &Transport, const std::shared_ptr<ReadResult> &Result,
                  const std::size_t BufferLimit) -> Net::awaitable<void>
    {
        auto Buffer = AsBytesSpan(Result->Buffer);
        if (BufferLimit < Buffer.size())
        {
            Buffer = Buffer.first(BufferLimit);
        }
        Result->Count = co_await Transport->async_read_some(Buffer, Result->ErrorCode);
        co_return;
    }

    struct ChunkedReadResult final
    {
        ByteVector Data;
        std::error_code ErrorCode;
        std::size_t Calls{0};
    };

    auto ReadChunks(const SharedTransport &Transport, const std::shared_ptr<ChunkedReadResult> &Result,
                    const std::size_t ChunkSize, const std::size_t ExpectedSize) -> Net::awaitable<void>
    {
        ByteVector Buffer(ChunkSize);
        while (Result->Data.size() < ExpectedSize)
        {
            ++Result->Calls;
            Result->ErrorCode.clear();
            const auto Count = co_await Transport->async_read_some(AsBytesSpan(Buffer), Result->ErrorCode);
            if (Count > Buffer.size())
            {
                Result->ErrorCode = Preview::make_error_code(PreviewError::BrokenPipe);
                co_return;
            }
            if (Count > 0)
            {
                Result->Data.insert(Result->Data.end(), Buffer.begin(),
                                    Buffer.begin() + static_cast<std::ptrdiff_t>(Count));
            }
            if (Result->ErrorCode || Count == 0)
            {
                co_return;
            }
        }
        co_return;
    }

    struct PayloadReadResult final
    {
        ByteVector Data;
        std::error_code ErrorCode;
    };

    auto ReadPayloadOnce(const SharedTransport &Transport,
                         const std::shared_ptr<PayloadReadResult> &Result) -> Net::awaitable<void>
    {
        std::array<Byte, 64> Buffer{};
        const auto Count = co_await Transport->async_read_some(Buffer, Result->ErrorCode);
        if (Count > Buffer.size())
        {
            Result->ErrorCode = Preview::make_error_code(PreviewError::BrokenPipe);
            co_return;
        }
        if (Count > 0)
        {
            Result->Data.assign(Buffer.begin(),
                                Buffer.begin() + static_cast<std::ptrdiff_t>(Count));
        }
        co_return;
    }

    struct NoopWriter final
    {
        auto operator()(std::int32_t, ConstBytes) const -> Net::awaitable<void>
        {
            co_return;
        }
    };

    auto MakeTransport(Net::any_io_executor Executor) -> SharedTransport
    {
        return std::make_shared<Xhttp::XhttpTransport>(
            std::move(Executor), Xhttp::XhttpTransport::WriteCb(NoopWriter{}));
    }

    struct WriteProbe final
    {
        std::size_t Active{0};
        std::size_t MaxActive{0};
        std::size_t Completed{0};
        bool Failed{false};
        std::string Order;
        std::shared_ptr<CompletionSignal> Completion;
    };

    auto ProbeWrite(Net::any_io_executor Executor, const std::shared_ptr<WriteProbe> &Probe,
                    ConstBytes Data) -> Net::awaitable<void>
    {
        ++Probe->Active;
        Probe->MaxActive = (std::max)(Probe->MaxActive, Probe->Active);
        co_await Net::post(Executor, Net::use_awaitable);
        Probe->Order.append(AsStrView(Data));
        --Probe->Active;
        if (Probe->Completion)
        {
            (void)Probe->Completion->try_send(boost::system::error_code{});
        }
        co_return;
    }

    struct TransportProbeWriter final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<WriteProbe> Probe;

        auto operator()(std::int32_t, ConstBytes Data) const -> Net::awaitable<void>
        {
            co_await ProbeWrite(Executor, Probe, Data);
        }
    };

    struct WireProbeWriter final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<WriteProbe> Probe;

        auto operator()(ConstBytes Data) const -> Net::awaitable<void>
        {
            co_await ProbeWrite(Executor, Probe, Data);
        }
    };

    auto MakeTransportProbe(Net::any_io_executor Executor,
                            const std::shared_ptr<WriteProbe> &Probe)
        -> Xhttp::XhttpTransport::WriteCb
    {
        return Xhttp::XhttpTransport::WriteCb(TransportProbeWriter{std::move(Executor), Probe});
    }

    auto MakeWireProbe(Net::any_io_executor Executor, const std::shared_ptr<WriteProbe> &Probe)
        -> Xhttp::WireWriter::Sink
    {
        return Xhttp::WireWriter::Sink(WireProbeWriter{std::move(Executor), Probe});
    }

    auto TransportWriteTask(const SharedTransport &Transport, const std::shared_ptr<WriteProbe> &Probe,
                            ByteVector Data) -> Net::awaitable<void>
    {
        std::error_code ErrorCode;
        const ConstBytes DataSpan{Data.data(), Data.size()};
        const auto Count = co_await Transport->async_write_some(DataSpan, ErrorCode);
        if (ErrorCode || Count != Data.size())
        {
            Probe->Failed = true;
        }
        ++Probe->Completed;
        co_return;
    }

    auto WireWriteTask(const std::shared_ptr<Xhttp::WireWriter> &Writer,
                       const std::shared_ptr<WriteProbe> &Probe, ByteVector Data) -> Net::awaitable<void>
    {
        try
        {
            const ConstBytes DataSpan{Data.data(), Data.size()};
            co_await Writer->Write(DataSpan);
        }
        catch (...)
        {
            Probe->Failed = true;
        }
        ++Probe->Completed;
        co_return;
    }

    auto RunConcurrentTransportWrites(const SharedTransport &Transport,
                                      const std::shared_ptr<WriteProbe> &Probe) -> Net::awaitable<void>
    {
        const auto Executor = Transport->Executor();
        auto First = Net::co_spawn(
            Executor, TransportWriteTask(Transport, Probe, {Byte{0x41}}), Net::use_awaitable);
        auto Second = Net::co_spawn(
            Executor, TransportWriteTask(Transport, Probe, {Byte{0x42}}), Net::use_awaitable);
        using Net::experimental::awaitable_operators::operator&&;
        co_await (std::move(First) && std::move(Second));
    }

    auto RunConcurrentWireWrites(Net::any_io_executor Executor,
                                 const std::shared_ptr<Xhttp::WireWriter> &Writer,
                                 const std::shared_ptr<WriteProbe> &Probe) -> Net::awaitable<void>
    {
        auto First = Net::co_spawn(
            Executor, WireWriteTask(Writer, Probe, {Byte{0x41}}), Net::use_awaitable);
        auto Second = Net::co_spawn(
            Executor, WireWriteTask(Writer, Probe, {Byte{0x42}}), Net::use_awaitable);
        using Net::experimental::awaitable_operators::operator&&;
        co_await (std::move(First) && std::move(Second));
    }

    struct BufferedWriteState final
    {
        std::int32_t StreamId{-99};
        std::string Data;
        std::shared_ptr<CompletionSignal> Completion;
    };

    struct BufferedWriter final
    {
        std::shared_ptr<BufferedWriteState> State;

        auto operator()(const std::int32_t StreamId, ConstBytes Data) const -> Net::awaitable<void>
        {
            State->StreamId = StreamId;
            State->Data.assign(AsStrView(Data));
            if (State->Completion)
            {
                (void)State->Completion->try_send(boost::system::error_code{});
            }
            co_return;
        }
    };

    auto BufferedWriteTask(const SharedTransport &Transport,
                           const std::shared_ptr<BufferedWriteState> &State,
                           const std::string &Payload) -> Net::awaitable<void>
    {
        std::error_code ErrorCode;
        const auto Count = co_await Transport->async_write_some(AsBytesSpan(std::string_view(Payload)),
                                                                ErrorCode);
        EXPECT_EQ(Count, Payload.size());
        EXPECT_FALSE(ErrorCode);

        Transport->BindStream(7);
        boost::system::error_code SignalError;
        co_await State->Completion->async_receive(Net::redirect_error(Net::use_awaitable, SignalError));
        EXPECT_FALSE(SignalError);
        co_return;
    }

    struct FailingWriter final
    {
        auto operator()(std::int32_t, ConstBytes) const -> Net::awaitable<void>
        {
            throw std::system_error(std::make_error_code(std::errc::broken_pipe));
        }
    };

    struct WriteErrorResult final
    {
        std::size_t FirstCount{0};
        std::size_t SecondCount{0};
        std::error_code FirstError;
        std::error_code SecondError;
    };

    auto WriteErrorTask(const SharedTransport &Transport,
                        const std::shared_ptr<WriteErrorResult> &Result) -> Net::awaitable<void>
    {
        Transport->BindStream(7);
        const std::string Payload = "write-error";
        Result->FirstCount = co_await Transport->async_write_some(
            AsBytesSpan(std::string_view(Payload)), Result->FirstError);
        Result->SecondCount = co_await Transport->async_write_some(
            AsBytesSpan(std::string_view(Payload)), Result->SecondError);
        co_return;
    }

    struct FinishState final
    {
        std::int32_t StreamId{-1};
        std::size_t Calls{0};
    };

    struct FinishWriter final
    {
        std::shared_ptr<FinishState> State;

        auto operator()(const std::int32_t StreamId) const -> Net::awaitable<void>
        {
            State->StreamId = StreamId;
            ++State->Calls;
            co_return;
        }
    };

    struct FinishResult final
    {
        bool Finished{false};
        std::size_t WriteCount{0};
        std::error_code WriteError;
        bool SecondFinishFailed{false};
        std::error_code SecondFinishError;
    };

    auto FinishTask(const SharedTransport &Transport,
                    const std::shared_ptr<FinishResult> &Result) -> Net::awaitable<void>
    {
        Transport->BindStream(7);
        try
        {
            co_await Transport->Finish();
            Result->Finished = true;
        }
        catch (...)
        {
            co_return;
        }

        const std::string Payload = "after-finish";
        Result->WriteCount = co_await Transport->async_write_some(
            AsBytesSpan(std::string_view(Payload)), Result->WriteError);
        try
        {
            co_await Transport->Finish();
        }
        catch (const std::system_error &Exception)
        {
            Result->SecondFinishFailed = true;
            Result->SecondFinishError = Exception.code();
        }
        co_return;
    }

    struct TransmissionSink final
    {
        std::shared_ptr<Preview::PreviewMockTransport> Transport;

        auto operator()(ConstBytes Data) const -> Net::awaitable<void>
        {
            std::error_code ErrorCode;
            const auto Count = co_await Transport->async_write_some(Data, ErrorCode);
            if (ErrorCode)
            {
                throw std::system_error(ErrorCode);
            }
            if (Count != Data.size())
            {
                throw std::system_error(std::make_error_code(std::errc::io_error));
            }
            co_return;
        }
    };

    struct WireFailureResult final
    {
        bool FirstFailed{false};
        std::error_code FirstError;
        bool SecondFailed{false};
        std::error_code SecondError;
    };

    auto WireFailureTask(const std::shared_ptr<Xhttp::WireWriter> &Writer,
                         const std::shared_ptr<WireFailureResult> &Result) -> Net::awaitable<void>
    {
        const std::array<Byte, 4> Payload{Byte{0x01}, Byte{0x02}, Byte{0x03}, Byte{0x04}};
        const ConstBytes Data{Payload};
        try
        {
            co_await Writer->Write(Data);
        }
        catch (const std::system_error &Exception)
        {
            Result->FirstFailed = true;
            Result->FirstError = Exception.code();
        }
        try
        {
            co_await Writer->Write(Data);
        }
        catch (const std::system_error &Exception)
        {
            Result->SecondFailed = true;
            Result->SecondError = Exception.code();
        }
        co_return;
    }

    auto DataRoundtripTask(const SharedTransport &Transport,
                           const std::shared_ptr<PayloadReadResult> &Result) -> Net::awaitable<void>
    {
        auto Reader = Net::co_spawn(
            Transport->Executor(), ReadPayloadOnce(Transport, Result), Net::use_awaitable);
        const std::string Payload = "xhttp-Data";
        Transport->Push(AsBytesSpan(std::string_view(Payload)));
        co_await std::move(Reader);
        co_return;
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
        ClosedTransport->Close();
        const auto ClosedResult = std::make_shared<ReadResult>(16);
        RunCoroutine(IoContext, ReadOnce(ClosedTransport, ClosedResult, 16));
        EXPECT_EQ(ClosedResult->Count, 0U);
        EXPECT_EQ(ClosedResult->ErrorCode, std::make_error_code(std::errc::not_connected));

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
    }

    TEST(XhttpErrorMatrix, TransportReadsPartialBlocks)
    {
        Net::io_context IoContext;
        const auto Transport = MakeTransport(IoContext.get_executor());
        const std::string Payload = "xhttp-partial-payload";
        Transport->Push(AsBytesSpan(std::string_view(Payload)));

        const auto Result = std::make_shared<ChunkedReadResult>();
        RunCoroutine(IoContext, ReadChunks(Transport, Result, 4, Payload.size()));
        EXPECT_FALSE(Result->ErrorCode);
        EXPECT_EQ(Result->Calls, 6U);
        EXPECT_EQ(AsStrView(ConstBytes{Result->Data}), Payload);
    }

    TEST(XhttpErrorMatrix, TransportWriteBufferedUntilBind)
    {
        Net::io_context IoContext;
        const auto State = std::make_shared<BufferedWriteState>();
        State->Completion = std::make_shared<CompletionSignal>(IoContext.get_executor(), 1);
        const auto Transport = std::make_shared<Xhttp::XhttpTransport>(
            IoContext.get_executor(), Xhttp::XhttpTransport::WriteCb(BufferedWriter{State}));

        const std::string Payload = "buffered";
        RunCoroutine(IoContext, BufferedWriteTask(Transport, State, Payload));
        EXPECT_EQ(State->StreamId, 7);
        EXPECT_EQ(State->Data, Payload);
    }

    TEST(XhttpErrorMatrix, TransportSerializesConcurrentWrites)
    {
        Net::io_context IoContext;
        const auto Probe = std::make_shared<WriteProbe>();
        const auto Transport = std::make_shared<Xhttp::XhttpTransport>(
            IoContext.get_executor(), MakeTransportProbe(IoContext.get_executor(), Probe));
        Transport->BindStream(7);

        RunCoroutine(IoContext, RunConcurrentTransportWrites(Transport, Probe));
        EXPECT_FALSE(Probe->Failed);
        EXPECT_EQ(Probe->Completed, 2U);
        EXPECT_EQ(Probe->MaxActive, 1U);
        EXPECT_EQ(Probe->Order, "AB");
    }

    TEST(XhttpErrorMatrix, WireWriterSerializesPhysicalWrites)
    {
        Net::io_context IoContext;
        const auto Probe = std::make_shared<WriteProbe>();
        const auto Writer = std::make_shared<Xhttp::WireWriter>(
            IoContext.get_executor(), MakeWireProbe(IoContext.get_executor(), Probe));

        RunCoroutine(IoContext, RunConcurrentWireWrites(IoContext.get_executor(), Writer, Probe));
        EXPECT_FALSE(Probe->Failed);
        EXPECT_EQ(Probe->Completed, 2U);
        EXPECT_EQ(Probe->MaxActive, 1U);
        EXPECT_EQ(Probe->Order, "AB");
    }

    TEST(XhttpErrorMatrix, TransportWriteErrorCloses)
    {
        Net::io_context IoContext;
        const auto Transport = std::make_shared<Xhttp::XhttpTransport>(
            IoContext.get_executor(), Xhttp::XhttpTransport::WriteCb(FailingWriter{}));
        const auto Result = std::make_shared<WriteErrorResult>();

        RunCoroutine(IoContext, WriteErrorTask(Transport, Result));
        EXPECT_EQ(Result->FirstCount, 0U);
        EXPECT_EQ(Result->FirstError, std::make_error_code(std::errc::io_error));
        EXPECT_EQ(Result->SecondCount, 0U);
        EXPECT_EQ(Result->SecondError, std::make_error_code(std::errc::not_connected));
    }

    TEST(XhttpErrorMatrix, TransportFinishHalfClosesWrites)
    {
        Net::io_context IoContext;
        const auto State = std::make_shared<FinishState>();
        const auto Transport = std::make_shared<Xhttp::XhttpTransport>(
            IoContext.get_executor(), Xhttp::XhttpTransport::WriteCb(NoopWriter{}),
            Xhttp::XhttpTransport::FinishCb(FinishWriter{State}));
        const auto Result = std::make_shared<FinishResult>();

        RunCoroutine(IoContext, FinishTask(Transport, Result));
        EXPECT_TRUE(Result->Finished);
        EXPECT_EQ(State->StreamId, 7);
        EXPECT_EQ(State->Calls, 1U);
        EXPECT_EQ(Result->WriteCount, 0U);
        EXPECT_EQ(Result->WriteError, std::make_error_code(std::errc::not_connected));
        EXPECT_TRUE(Result->SecondFinishFailed);
        EXPECT_EQ(Result->SecondFinishError, std::make_error_code(std::errc::not_connected));
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
    }

    TEST(XhttpErrorMatrix, WireWriterRejectsShortWrite)
    {
        Net::io_context IoContext;
        const auto Raw = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        Raw->MaxWrite = 2;
        const auto Writer = std::make_shared<Xhttp::WireWriter>(
            IoContext.get_executor(), Xhttp::WireWriter::Sink(TransmissionSink{Raw}));
        const auto Result = std::make_shared<WireFailureResult>();

        RunCoroutine(IoContext, WireFailureTask(Writer, Result));
        EXPECT_TRUE(Result->FirstFailed);
        EXPECT_EQ(Result->FirstError.value(), std::make_error_code(std::errc::io_error).value());
        EXPECT_TRUE(Result->SecondFailed);
        EXPECT_EQ(Result->SecondError.value(), std::make_error_code(std::errc::not_connected).value());
    }

    TEST(XhttpErrorMatrix, WireWriterRejectsOverreportedWrite)
    {
        Net::io_context IoContext;
        const auto Raw = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        Raw->OverreportWrite = true;
        const auto Writer = std::make_shared<Xhttp::WireWriter>(
            IoContext.get_executor(), Xhttp::WireWriter::Sink(TransmissionSink{Raw}));
        const auto Result = std::make_shared<WireFailureResult>();

        RunCoroutine(IoContext, WireFailureTask(Writer, Result));
        EXPECT_TRUE(Result->FirstFailed);
        EXPECT_EQ(Result->FirstError.value(), std::make_error_code(std::errc::io_error).value());
        EXPECT_TRUE(Result->SecondFailed);
        EXPECT_EQ(Result->SecondError.value(), std::make_error_code(std::errc::not_connected).value());
    }

    TEST(XhttpErrorMatrix, TransportDataRoundtrip)
    {
        Net::io_context IoContext;
        const auto Transport = MakeTransport(IoContext.get_executor());
        const auto Result = std::make_shared<PayloadReadResult>();

        RunCoroutine(IoContext, DataRoundtripTask(Transport, Result));
        EXPECT_FALSE(Result->ErrorCode);
        EXPECT_EQ(AsStrView(ConstBytes{Result->Data}), "xhttp-Data");
    }

} // namespace
