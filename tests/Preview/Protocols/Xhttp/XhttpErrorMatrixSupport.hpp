#pragma once

/**
 * @file XhttpErrorMatrixSupport.hpp
 * @brief XHTTP 错误矩阵测试共享传输与协程辅助。
 * @details 覆盖：
 *          - Config 边界（空 Path 禁用 / 非空启用）
 *          - XhttpTransport：半包读取、EOF、关闭、写缓冲和数据往返
 *          - 写入错误码、写失败后的 close、Finish 半关闭
 *          - WireWriter：串行写入、短写与 over-report 拒绝
 * @note 测试协程均由调用方等待完成，不使用分离式任务或定时器轮询；本头不承载 TEST 宏。
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
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Contract/Io/CarrierActivity.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Protocols/Http2/Session.hpp>
#include <Preview/Protocols/Xhttp/Conn.hpp>
#include <Preview/Protocols/Xhttp/Detail/StreamTransport.hpp>
#include <Preview/Protocols/Xhttp/Detail/SplitClient.hpp>
#include <Preview/Protocols/Xhttp/Detail/SplitServer.hpp>
#include <Preview/Protocols/Xhttp/Types.hpp>
#include <Preview/Protocols/Xhttp/Detail/SplitTransport.hpp>
#include <Preview/Protocols/Xhttp/Detail/Wire.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Xhttp = Preview::Xhttp;

    using Byte = std::byte;
    using ByteVector = std::vector<Byte>;
    using ConstBytes = std::span<const Byte>;
    using PreviewError = Preview::Error;
    using SharedTransport = std::shared_ptr<Xhttp::Detail::XhttpTransport>;
    using SharedWireWriter = std::shared_ptr<Xhttp::Detail::WireWriter>;
    using CompletionSignal = Net::experimental::channel<void(boost::system::error_code)>;

    struct TransportRetirementResult final
    {
        Preview::Fault::Failure Failure;
        bool Retired{false};
    };

    using Preview::AsBytesSpan;
    using Preview::AsStrView;

    struct CoroutineCompletionHandler final
    {
        std::exception_ptr *Exception;

        auto operator()(std::exception_ptr ErrorValue) const -> void
        {
            *Exception = ErrorValue;
        }
    };

    template <typename Awaitable>
    auto RunCoroutine(Net::io_context &IoContext, Awaitable Coroutine) -> void
    {
        IoContext.restart();
        std::exception_ptr Exception;
        const CoroutineCompletionHandler CompletionHandler{&Exception};
        Net::co_spawn(IoContext, std::move(Coroutine), CompletionHandler);
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto CloseAndDrainTransportActivity(
        SharedTransport Transport,
        const std::shared_ptr<TransportRetirementResult> &Result) -> Net::awaitable<void>
    {
        const auto Closed = Transport->Close();
        if (!Closed) Result->Failure = Closed.error();
        const auto Activity = Transport->Activity();
        if (!Activity)
        {
            Result->Failure = {Preview::Fault::Code::InvalidArgument};
            co_return;
        }
        const auto Drained = co_await Activity->Drain();
        if (!Drained) Result->Failure = Drained.error();
        Result->Retired = Activity->IsRetired();
        if (!Result->Retired && Result->Failure.Succeeded())
            Result->Failure = {Preview::Fault::Code::Blocked};
    }

    [[nodiscard]] auto DrainTransport(
        Net::io_context &IoContext,
        SharedTransport Transport) -> TransportRetirementResult
    {
        const auto Result = std::make_shared<TransportRetirementResult>();
        RunCoroutine(IoContext, CloseAndDrainTransportActivity(Transport, Result));
        return *Result;
    }

    auto CloseAndDrainRawActivity(
        Preview::SharedTransmission Transport,
        const std::shared_ptr<TransportRetirementResult> &Result) -> Net::awaitable<void>
    {
        const auto Closed = Transport->Close();
        if (!Closed) Result->Failure = Closed.error();
        const auto Activity = Transport->Activity();
        if (!Activity)
        {
            Result->Failure = {Preview::Fault::Code::InvalidArgument};
            co_return;
        }
        const auto Drained = co_await Activity->Drain();
        if (!Drained && Result->Failure.Succeeded()) Result->Failure = Drained.error();
        Result->Retired = Activity->IsRetired();
        if (!Result->Retired && Result->Failure.Succeeded())
            Result->Failure = {Preview::Fault::Code::Blocked};
    }

    auto CloseAndDrainTransmission(Preview::SharedTransmission Transport)
        -> Net::awaitable<void>
    {
        const auto Closed = Transport->Close();
        EXPECT_TRUE(Closed);
        const auto Activity = Transport->Activity();
        EXPECT_TRUE(Activity);
        if (!Activity) co_return;
        const auto Drained = co_await Activity->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_TRUE(Activity->IsRetired());
    }

    [[nodiscard]] auto RetireRawTransport(
        Net::io_context &IoContext,
        Preview::SharedTransmission Transport) -> TransportRetirementResult
    {
        const auto Result = std::make_shared<TransportRetirementResult>();
        RunCoroutine(IoContext, CloseAndDrainRawActivity(Transport, Result));
        return *Result;
    }

    auto CloseAndDrainWireWriter(
        SharedWireWriter Writer,
        const std::shared_ptr<TransportRetirementResult> &Result) -> Net::awaitable<void>
    {
        Writer->Close();
        const auto Drained = co_await Writer->Drain();
        if (!Drained) Result->Failure = Drained.error();
        Result->Retired = Writer->IsRetired();
        if (!Result->Retired && Result->Failure.Succeeded())
            Result->Failure = {Preview::Fault::Code::Blocked};
    }

    [[nodiscard]] auto RetireWireWriter(
        Net::io_context &IoContext,
        SharedWireWriter Writer) -> TransportRetirementResult
    {
        const auto Result = std::make_shared<TransportRetirementResult>();
        RunCoroutine(IoContext, CloseAndDrainWireWriter(Writer, Result));
        return *Result;
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
        bool Completed{false};
    };

    template <typename TransportType>
    auto ReadOnce(const std::shared_ptr<TransportType> &Transport,
                  const std::shared_ptr<ReadResult> &Result,
                  const std::size_t BufferLimit) -> Net::awaitable<void>
    {
        auto Buffer = AsBytesSpan(Result->Buffer);
        if (BufferLimit < Buffer.size())
        {
            Buffer = Buffer.first(BufferLimit);
        }
        const auto Read = co_await Transport->ReadSome(Buffer);
        Result->ErrorCode = Preview::Fault::ToNative(Read.Failure);
        Result->Count = Read.Bytes;
        Result->Completed = true;
        co_return;
    }

    struct ChunkedReadResult final
    {
        ByteVector Data;
        std::error_code ErrorCode;
        std::size_t Calls{0};
    };

    struct ChunkedReadRequest final
    {
        SharedTransport Transport;
        std::shared_ptr<ChunkedReadResult> Result;
        std::size_t ChunkSize;
        std::size_t ExpectedSize;
    };

    auto ReadChunks(ChunkedReadRequest Request) -> Net::awaitable<void>
    {
        ByteVector Buffer(Request.ChunkSize);
        while (Request.Result->Data.size() < Request.ExpectedSize)
        {
            ++Request.Result->Calls;
            Request.Result->ErrorCode.clear();
            const auto Read = co_await Request.Transport->ReadSome(AsBytesSpan(Buffer));
            Request.Result->ErrorCode = Preview::Fault::ToNative(Read.Failure);
            const auto Count = Read.Bytes;
            if (Count > Buffer.size())
            {
                Request.Result->ErrorCode = Preview::make_error_code(PreviewError::BrokenPipe);
                co_return;
            }
            if (Count > 0)
            {
                Request.Result->Data.insert(Request.Result->Data.end(), Buffer.begin(),
                                            Buffer.begin() + static_cast<std::ptrdiff_t>(Count));
            }
            if (Request.Result->ErrorCode || Count == 0)
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
        const auto Read = co_await Transport->ReadSome(Buffer);
        Result->ErrorCode = Preview::Fault::ToNative(Read.Failure);
        const auto Count = Read.Bytes;
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

    using WireWriteResult = std::expected<void, Preview::Fault::Failure>;

    struct NoopWriter final
    {
        auto operator()(std::int32_t, ConstBytes) const -> Net::awaitable<WireWriteResult>
        {
            co_return WireWriteResult{};
        }
    };

    auto DiscardWire(ConstBytes) -> Net::awaitable<WireWriteResult>
    {
        co_return WireWriteResult{};
    }

    struct BlockingSplitWriteState final
    {
        std::shared_ptr<CompletionSignal> Release;
        std::shared_ptr<CompletionSignal> Started;
        std::size_t Calls{0};
    };

    struct BlockingSplitWriter final
    {
        std::shared_ptr<BlockingSplitWriteState> State;

        [[nodiscard]] auto operator()(std::span<const std::byte>) const
            -> Net::awaitable<WireWriteResult>
        {
            ++State->Calls;
            (void)State->Started->try_send(boost::system::error_code{});
            boost::system::error_code Error;
            co_await State->Release->async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
                co_return std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
            co_return WireWriteResult{};
        }
    };

    struct ThrowingRawProbe final
    {
        std::size_t CancelCalls{0};
        std::size_t CloseCalls{0};
    };

    class ThrowingRaw final : public Preview::Transmission
    {
    public:
        ThrowingRaw(Net::any_io_executor Executor, std::shared_ptr<ThrowingRawProbe> Probe)
            : Preview::Transmission(Executor), Executor_(std::move(Executor)), Probe_(std::move(Probe))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            const std::error_code ErrorCode = std::make_error_code(std::errc::not_connected);
            Preview::Transport::Detail::PostResult(
                std::move(Handler), Preview::IoResult{0, Preview::Fault::FromNative(ErrorCode)});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            const std::error_code ErrorCode = std::make_error_code(std::errc::not_connected);
            Preview::Transport::Detail::PostResult(
                std::move(Handler), Preview::IoResult{0, Preview::Fault::FromNative(ErrorCode)});
        }

        /** @brief 替身没有内层载体，显式兑现半关闭。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer())
            {
                Inner->WriteShutdown(std::move(Handler));
                return;
            }
            Preview::Transport::Detail::PostResult(std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            ++Probe_->CloseCalls;
            throw std::runtime_error("raw-close");
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            ++Probe_->CancelCalls;
            throw std::runtime_error("raw-cancel");
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return true;
        }

    private:
        Net::any_io_executor Executor_;
        std::shared_ptr<ThrowingRawProbe> Probe_;
    };

    auto MakeTransport(Net::any_io_executor Executor) -> SharedTransport
    {
        return std::make_shared<Xhttp::Detail::XhttpTransport>(
            Xhttp::Detail::XhttpTransport::Options{
                .Executor = std::move(Executor),
                .Write = Xhttp::Detail::XhttpTransport::WriteCb(NoopWriter{})});
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
                    ConstBytes Data) -> Net::awaitable<WireWriteResult>
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
        co_return WireWriteResult{};
    }

    struct TransportProbeWriter final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<WriteProbe> Probe;

        auto operator()(std::int32_t, ConstBytes Data) const
            -> Net::awaitable<WireWriteResult>
        {
            co_return co_await ProbeWrite(Executor, Probe, Data);
        }
    };

    struct WireProbeWriter final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<WriteProbe> Probe;

        auto operator()(ConstBytes Data) const -> Net::awaitable<WireWriteResult>
        {
            co_return co_await ProbeWrite(Executor, Probe, Data);
        }
    };

    auto MakeTransportProbe(Net::any_io_executor Executor,
                            const std::shared_ptr<WriteProbe> &Probe)
        -> Xhttp::Detail::XhttpTransport::WriteCb
    {
        return Xhttp::Detail::XhttpTransport::WriteCb(TransportProbeWriter{std::move(Executor), Probe});
    }

    auto MakeWireProbe(Net::any_io_executor Executor, const std::shared_ptr<WriteProbe> &Probe)
        -> Xhttp::Detail::WireWriter::Sink
    {
        return Xhttp::Detail::WireWriter::Sink(WireProbeWriter{std::move(Executor), Probe});
    }

    auto TransportWriteTask(const SharedTransport &Transport, const std::shared_ptr<WriteProbe> &Probe,
                            ByteVector Data) -> Net::awaitable<void>
    {
        std::error_code ErrorCode;
        const ConstBytes DataSpan{Data.data(), Data.size()};
        const auto Write = co_await Transport->WriteSome(DataSpan);
        ErrorCode = Preview::Fault::ToNative(Write.Failure);
        const auto Count = Write.Bytes;
        if (ErrorCode || Count != Data.size())
        {
            Probe->Failed = true;
        }
        ++Probe->Completed;
        co_return;
    }

    auto WireWriteTask(const std::shared_ptr<Xhttp::Detail::WireWriter> &Writer,
                       const std::shared_ptr<WriteProbe> &Probe, ByteVector Data) -> Net::awaitable<void>
    {
        const ConstBytes DataSpan{Data.data(), Data.size()};
        const auto Written = co_await Writer->Write(DataSpan);
        if (!Written) Probe->Failed = true;
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
                                 const std::shared_ptr<Xhttp::Detail::WireWriter> &Writer,
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

        auto operator()(const std::int32_t StreamId, ConstBytes Data) const
            -> Net::awaitable<WireWriteResult>
        {
            State->StreamId = StreamId;
            State->Data.assign(AsStrView(Data));
            if (State->Completion)
            {
                (void)State->Completion->try_send(boost::system::error_code{});
            }
            co_return WireWriteResult{};
        }
    };

    auto BufferedWriteTask(const SharedTransport &Transport,
                           const std::shared_ptr<BufferedWriteState> &State,
                           const std::string &Payload) -> Net::awaitable<void>
    {
        std::error_code ErrorCode;
        const auto Write = co_await Transport->WriteSome(AsBytesSpan(std::string_view(Payload)));
        ErrorCode = Preview::Fault::ToNative(Write.Failure);
        const auto Count = Write.Bytes;
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
        auto operator()(std::int32_t, ConstBytes) const -> Net::awaitable<WireWriteResult>
        {
            co_return std::unexpected(Preview::Fault::FromNative(
                std::make_error_code(std::errc::broken_pipe)));
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
        const auto First = co_await Transport->WriteSome(AsBytesSpan(std::string_view(Payload)));
        Result->FirstError = Preview::Fault::ToNative(First.Failure);
        Result->FirstCount = First.Bytes;
        const auto Second = co_await Transport->WriteSome(AsBytesSpan(std::string_view(Payload)));
        Result->SecondError = Preview::Fault::ToNative(Second.Failure);
        Result->SecondCount = Second.Bytes;
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

        auto operator()(const std::int32_t StreamId) const
            -> Net::awaitable<WireWriteResult>
        {
            State->StreamId = StreamId;
            ++State->Calls;
            co_return WireWriteResult{};
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
        const auto Finished = co_await Transport->Finish();
        if (!Finished) co_return;
        Result->Finished = true;

        const std::string Payload = "after-finish";
        const auto Write = co_await Transport->WriteSome(AsBytesSpan(std::string_view(Payload)));
        Result->WriteError = Preview::Fault::ToNative(Write.Failure);
        Result->WriteCount = Write.Bytes;
        const auto SecondFinish = co_await Transport->Finish();
        if (!SecondFinish)
        {
            Result->SecondFinishFailed = true;
            Result->SecondFinishError = Preview::Fault::ToNative(SecondFinish.error());
        }
        co_return;
    }

    struct TransmissionSink final
    {
        std::shared_ptr<Preview::PreviewMockTransport> Transport;

        auto operator()(ConstBytes Data) const -> Net::awaitable<WireWriteResult>
        {
            const auto Write = co_await Transport->WriteSome(Data);
            if (Write.Failure.Failed()) co_return std::unexpected(Write.Failure);
            if (Write.Bytes != Data.size())
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::IoError});
            co_return WireWriteResult{};
        }
    };

    struct WireFailureResult final
    {
        bool FirstFailed{false};
        std::error_code FirstError;
        bool SecondFailed{false};
        std::error_code SecondError;
    };

    auto WireFailureTask(const std::shared_ptr<Xhttp::Detail::WireWriter> &Writer,
                         const std::shared_ptr<WireFailureResult> &Result) -> Net::awaitable<void>
    {
        const std::array<Byte, 4> Payload{Byte{0x01}, Byte{0x02}, Byte{0x03}, Byte{0x04}};
        const ConstBytes Data{Payload};
        const auto First = co_await Writer->Write(Data);
        if (!First)
        {
            Result->FirstFailed = true;
            Result->FirstError = Preview::Fault::ToNative(First.error());
        }
        const auto Second = co_await Writer->Write(Data);
        if (!Second)
        {
            Result->SecondFailed = true;
            Result->SecondError = Preview::Fault::ToNative(Second.error());
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

} // namespace

