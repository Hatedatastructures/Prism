/**
 * @file HttpForwardResponseTest.cpp
 * @brief HTTP/1.1 源站响应 framing 与定界传输测试
 */

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Foundation/Utility/Http/ForwardResponseFields.hpp>
#include <Preview/Foundation/Utility/Http/ForwardResponseFraming.hpp>
#include <Preview/Protocols/Http1/ForwardResponseTransport.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include "HttpTestSupport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using Preview::Error;
    using Preview::SharedTransmission;
    using Preview::Http11::ForwardResponseFramingOptions;
    using Preview::Http11::ForwardResponseMethod;
    using Preview::Testing::Http11::CheckTransmissionClose;
    using Preview::Testing::Http11::CloseTransmission;
    using Preview::Testing::Http11::InspectControl;
    using Preview::Testing::Http11::InspectExactWrite;
    using Preview::Testing::Http11::RunOwnedCase;
    using Preview::Testing::Http11::RunCoroutine;
    using Preview::Testing::Http11::SpawnTask;
    using Preview::Testing::Http11::WaitForTask;

    struct ReadResult final
    {
        std::string Bytes;
        Preview::Fault::Failure Failure;
    };

    auto ReadUntilEnd(SharedTransmission Transport) -> Net::awaitable<ReadResult>;

    struct RunOptions final
    {
        ForwardResponseFramingOptions Framing;
        bool ShutdownSource{false};
        std::chrono::milliseconds SourceTimeout{100};
    };

    struct ResponseFixture final
    {
        std::shared_ptr<Preview::MemoryStream> Producer;
        std::shared_ptr<Preview::MemoryStream> Source;
        SharedTransmission Framed;
    };

    struct ResponseOperationRequest final
    {
        std::shared_ptr<Preview::MemoryStream> Producer;
        SharedTransmission Framed;
        std::string Wire;
        bool ShutdownSource;
        std::shared_ptr<ReadResult> Result;
    };

    /** @brief 驱动完整 response framing 读取并保存结果。 */
    auto RunResponseOperation(ResponseOperationRequest Request)
        -> Net::awaitable<void>
    {
        const auto Write = co_await Request.Producer->WriteExact(
            Preview::AsBytesSpan(Request.Wire));
        auto ErrorCode = InspectExactWrite(Write, Request.Wire.size()).Error;
        if (ErrorCode)
        {
            Request.Result->Failure = Preview::Fault::FromNative(ErrorCode);
            co_return;
        }
        if (Request.ShutdownSource)
        {
            const auto Shutdown = co_await Request.Producer->WriteShutdown();
            ErrorCode = InspectControl(Shutdown);
            if (ErrorCode)
            {
                Request.Result->Failure = Preview::Fault::FromNative(ErrorCode);
                co_return;
            }
        }
        *Request.Result = co_await ReadUntilEnd(Request.Framed);
    }

    struct FirstReadRequest final
    {
        std::shared_ptr<Preview::MemoryStream> Producer;
        SharedTransmission Framed;
        std::string Wire;
        std::shared_ptr<ReadResult> Result;
    };

    /** @brief 驱动单次 framed read 并保存首帧结果。 */
    auto RunFirstReadOperation(FirstReadRequest Request)
        -> Net::awaitable<void>
    {
        const auto Write = co_await Request.Producer->WriteExact(
            Preview::AsBytesSpan(Request.Wire));
        const auto ErrorCode = InspectExactWrite(Write, Request.Wire.size()).Error;
        if (ErrorCode)
        {
            Request.Result->Failure = Preview::Fault::FromNative(ErrorCode);
            co_return;
        }
        std::array<std::byte, 512> Buffer{};
        const auto Read = co_await Request.Framed->ReadSome(Buffer);
        if (Read.Bytes > Buffer.size())
        {
            Request.Result->Failure = Preview::Fault::FromNative(
                std::make_error_code(std::errc::protocol_error));
            co_return;
        }
        Request.Result->Bytes.assign(
            reinterpret_cast<const char *>(Buffer.data()), Read.Bytes);
        Request.Result->Failure = Read.Failure;
    }

    auto MakeFixture(Net::io_context &IoContext, const RunOptions &Options) -> ResponseFixture
    {
        auto [ProducerEnd, SourceEnd] = Preview::MakeMemoryPair(IoContext.get_executor());
        auto Producer = std::make_shared<Preview::MemoryStream>(std::move(ProducerEnd));
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(SourceEnd));
        Source->SetTimeout(Options.SourceTimeout);
        auto Framed = Preview::Http11::MakeForwardResponseTransport(
            {Source, Options.Framing});
        return {std::move(Producer), std::move(Source), std::move(Framed)};
    }

    auto ReadUntilEnd(SharedTransmission Transport) -> Net::awaitable<ReadResult>
    {
        ReadResult Result;
        std::array<std::byte, 32> Buffer{};
        while (true)
        {
            const auto Read = co_await Transport->ReadSome(Buffer);
            const auto Count = Read.Bytes;
            if (Count > Buffer.size())
            {
                Result.Failure = Preview::Fault::FromNative(
                    std::make_error_code(std::errc::protocol_error));
                co_return Result;
            }
            Result.Bytes.append(reinterpret_cast<const char *>(Buffer.data()), Count);
            if (Read.Failure.Failed())
            {
                Result.Failure = Read.Failure;
                co_return Result;
            }
            if (Count == 0U)
            {
                Result.Failure = {Preview::Fault::Code::WouldBlock};
                co_return Result;
            }
        }
    }

    auto RunResponse(std::string Wire, RunOptions Options) -> ReadResult
    {
        Net::io_context IoContext;
        auto Fixture = MakeFixture(IoContext, Options);
        auto Result = std::make_shared<ReadResult>();
        RunOwnedCase(IoContext, {Fixture.Framed, Fixture.Source, Fixture.Producer},
            RunResponseOperation(ResponseOperationRequest{
                Fixture.Producer, Fixture.Framed, std::move(Wire),
                Options.ShutdownSource, Result}));
        return *Result;
    }

    auto ReadFirst(std::string Wire, RunOptions Options) -> ReadResult
    {
        Net::io_context IoContext;
        auto Fixture = MakeFixture(IoContext, Options);
        auto Result = std::make_shared<ReadResult>();
        RunOwnedCase(IoContext, {Fixture.Framed, Fixture.Source, Fixture.Producer},
            RunFirstReadOperation(FirstReadRequest{
                Fixture.Producer, Fixture.Framed, std::move(Wire), Result}));
        return *Result;
    }

    auto IsProtocolError(const Preview::Fault::Failure &Failure, const Error Expected) -> bool
    {
        const auto Native = static_cast<std::error_code>(Expected);
        return Failure.Native == Native && Failure.Code == Preview::Fault::ToCode(Native);
    }

    struct CancelReadRequest final
    {
        Net::io_context &IoContext;
        std::shared_ptr<Preview::MemoryStream> Peer;
        SharedTransmission Framed;
        std::shared_ptr<std::size_t> ReadCount;
        std::shared_ptr<Preview::Fault::Failure> ReadError;
    };

    struct CancelReadTimerRequest final
    {
        std::shared_ptr<Net::steady_timer> Timer;
        SharedTransmission Framed;
    };

    /** @brief 到期后取消响应读取并检查控制命令结果。 */
    auto CancelReadTimer(CancelReadTimerRequest Request) -> Net::awaitable<void>
    {
        boost::system::error_code TimerError;
        co_await Request.Timer->async_wait(
            Net::redirect_error(Net::use_awaitable, TimerError));
        EXPECT_FALSE(TimerError);
        const auto Canceled = Request.Framed->Cancel();
        EXPECT_TRUE(Canceled);
    }

    /** @brief 由计时 owner 取消 pending response read。 */
    auto RunCancelRead(CancelReadRequest Request) -> Net::awaitable<void>
    {
        auto Timer = std::make_shared<Net::steady_timer>(Request.IoContext);
        Timer->expires_after(std::chrono::milliseconds{1});
        auto TimerTask = SpawnTask(Request.IoContext.get_executor(),
            CancelReadTimer(CancelReadTimerRequest{Timer, Request.Framed}));
        std::array<std::byte, 32> Buffer{};
        const auto Read = co_await Request.Framed->ReadSome(Buffer);
        *Request.ReadCount = Read.Bytes;
        if (Read.Bytes > Buffer.size())
        {
            *Request.ReadError = Preview::Fault::FromNative(
                std::make_error_code(std::errc::protocol_error));
        }
        else
        {
            *Request.ReadError = Read.Failure;
        }
        co_await WaitForTask(std::move(TimerTask));
    }

    struct ShutdownWriteRequest final
    {
        std::shared_ptr<Preview::MemoryStream> Peer;
        SharedTransmission Framed;
        std::shared_ptr<std::string> Received;
    };

    /** @brief 验证写入委托与下游 shutdown 的完整关闭顺序。 */
    auto RunShutdownAndWrite(ShutdownWriteRequest Request)
        -> Net::awaitable<void>
    {
        const std::string Payload = "write-through";
        const auto Write = co_await Request.Framed->WriteExact(Preview::AsBytesSpan(Payload));
        auto ErrorCode = InspectExactWrite(Write, Payload.size()).Error;
        std::array<std::byte, 32> Buffer{};
        const auto Read = co_await Request.Peer->ReadSome(Buffer);
        const auto Count = Read.Bytes;
        if (Count <= Buffer.size())
        {
            Request.Received->assign(reinterpret_cast<const char *>(Buffer.data()), Count);
        }
        else
        {
            ErrorCode = std::make_error_code(std::errc::protocol_error);
        }
        if (!ErrorCode && Read.Failure.Failed())
        {
            ADD_FAILURE() << Preview::Fault::ToNative(Read.Failure).message();
        }
        const auto Shutdown = co_await Request.Framed->WriteShutdown();
        if (!ErrorCode)
        {
            ErrorCode = InspectControl(Shutdown);
        }
        const auto EofResult = co_await Request.Peer->ReadSome(Buffer);
        const auto Eof = EofResult.Bytes;
        EXPECT_EQ(Eof, 0U);
        EXPECT_EQ(EofResult.Failure.Code, Preview::Fault::Code::Eof);
        EXPECT_FALSE(EofResult.Failure.Native);
        EXPECT_FALSE(ErrorCode);
    }
} // namespace

TEST(HttpForwardResponse, ContentLengthCompletesBeforeSourceClose)
{
    const std::string Wire = "HTTP/1.1 200 OK\r\n"
                             "Content-Length: 9\r\n"
                             "Connection: keep-alive\r\n"
                             "\r\n"
                             "origin-ok";
    const auto Result = RunResponse(Wire, {});
    EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::Eof);
    EXPECT_FALSE(Result.Failure.Native);
    EXPECT_EQ(Result.Bytes, Wire);
}

TEST(HttpForwardResponse, ZeroContentLengthCompletesAtHeaders)
{
    const std::string Wire = "HTTP/1.1 200 OK\r\n"
                             "Content-Length: 0\r\n"
                             "Connection: keep-alive\r\n"
                             "\r\n";
    const auto Result = RunResponse(Wire, {});
    EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::Eof);
    EXPECT_FALSE(Result.Failure.Native);
    EXPECT_EQ(Result.Bytes, Wire);
}

TEST(HttpForwardResponse, ResponseHeadersDoNotApplyRequestFieldPolicy)
{
    const auto Parsed = Preview::Http11::ParseResponseHeaders(
        "Host: origin.example\r\n"
        "Proxy-Authorization: opaque\r\n"
        "Connection: host\r\n"
        "Content-Length: 0",
        false);
    ASSERT_TRUE(Parsed.has_value());
    EXPECT_TRUE(Parsed->HasContentLength);
    EXPECT_EQ(Parsed->ContentLength, 0U);
}

TEST(HttpForwardResponse, HeadIgnoresResponseBodyFraming)
{
    const std::string Wire = "HTTP/1.1 200 OK\r\n"
                             "Content-Length: 9\r\n"
                             "Transfer-Encoding: gzip\r\n"
                             "Connection: keep-alive\r\n"
                             "\r\n";
    RunOptions Options;
    Options.Framing.RequestMethod = ForwardResponseMethod::Head;
    const auto Result = RunResponse(Wire, Options);
    EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::Eof);
    EXPECT_FALSE(Result.Failure.Native);
    EXPECT_EQ(Result.Bytes, Wire);
}

TEST(HttpForwardResponse, Status204And304IgnoreResponseBodyFraming)
{
    const std::array<std::string, 2> Wires{
        "HTTP/1.1 204 No Content\r\nContent-Length: 4\r\nTransfer-Encoding: gzip\r\n\r\n",
        "HTTP/1.1 304 Not Modified\r\nContent-Length: 4\r\nTransfer-Encoding: gzip\r\n\r\n"};
    for (const auto &Wire : Wires)
    {
        const auto Result = RunResponse(Wire, {});
        EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::Eof);
        EXPECT_FALSE(Result.Failure.Native);
        EXPECT_EQ(Result.Bytes, Wire);
    }
}

TEST(HttpForwardResponse, InformationalResponseContinuesToFinalResponse)
{
    const std::string Wire = "HTTP/1.1 103 Early Hints\r\n"
                             "Content-Length: 3\r\n"
                             "\r\n"
                             "HTTP/1.1 200 OK\r\n"
                             "Content-Length: 9\r\n"
                             "\r\n"
                             "origin-ok";
    const auto Result = RunResponse(Wire, {});
    EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::Eof);
    EXPECT_FALSE(Result.Failure.Native);
    EXPECT_EQ(Result.Bytes, Wire);
}

TEST(HttpForwardResponse, ChunkedResponsePreservesExtensionsAndTrailers)
{
    const std::string Wire = "HTTP/1.1 200 OK\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "Connection: keep-alive\r\n"
                             "\r\n"
                             "4;foo=bar\r\nWiki\r\n"
                             "5\r\npedia\r\n"
                             "0\r\n"
                             "X-Trailer: done\r\n"
                             "\r\n";
    const auto Result = RunResponse(Wire, {});
    EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::Eof);
    EXPECT_FALSE(Result.Failure.Native);
    EXPECT_EQ(Result.Bytes, Wire);
}

TEST(HttpForwardResponse, TransferEncodingGzipUsesCloseDelimitedBody)
{
    const std::string Wire = "HTTP/1.1 200 OK\r\n"
                             "Transfer-Encoding: gzip\r\n"
                             "\r\n"
                             "encoded-body";
    RunOptions Options;
    Options.ShutdownSource = true;
    const auto Result = RunResponse(Wire, Options);
    EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::Eof);
    EXPECT_FALSE(Result.Failure.Native);
    EXPECT_EQ(Result.Bytes, Wire);
}

TEST(HttpForwardResponse, CloseDelimitedBodyWaitsForSourceEof)
{
    const std::string Wire = "HTTP/1.1 200 OK\r\n"
                             "Connection: keep-alive\r\n"
                             "\r\n"
                             "close-delimited";
    RunOptions Options;
    Options.SourceTimeout = std::chrono::milliseconds{20};
    const auto Result = RunResponse(Wire, Options);
    EXPECT_EQ(Result.Bytes, Wire);
    EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::Timeout);
    EXPECT_EQ(Result.Failure.Native, static_cast<std::error_code>(
        Net::experimental::error::make_error_code(
            Net::experimental::error::channel_cancelled)));
}

TEST(HttpForwardResponse, ConflictingContentLengthIsRejected)
{
    const std::string Wire = "HTTP/1.1 200 OK\r\n"
                             "Content-Length: 4\r\n"
                             "Content-Length: 5\r\n"
                             "\r\n"
                             "data!";
    const auto Result = RunResponse(Wire, {});
    EXPECT_TRUE(IsProtocolError(Result.Failure, Error::BadMessage));
}

TEST(HttpForwardResponse, PrematureContentLengthEofIsRejected)
{
    const std::string Wire = "HTTP/1.1 200 OK\r\n"
                             "Content-Length: 9\r\n"
                             "\r\n"
                             "short";
    RunOptions Options;
    Options.ShutdownSource = true;
    const auto Result = RunResponse(Wire, Options);
    EXPECT_TRUE(IsProtocolError(Result.Failure, Error::UnexpectedEof));
}

TEST(HttpForwardResponse, MalformedChunkExtensionIsRejected)
{
    const std::string Wire = "HTTP/1.1 200 OK\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n"
                             "4;=bad\r\nWiki\r\n0\r\n\r\n";
    const auto Result = RunResponse(Wire, {});
    EXPECT_TRUE(IsProtocolError(Result.Failure, Error::BadMessage));
}

TEST(HttpForwardResponse, MalformedChunkTrailerIsRejected)
{
    const std::string Wire = "HTTP/1.1 200 OK\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n"
                             "0\r\n"
                             "Bad Trailer: value\r\n"
                             "\r\n";
    const auto Result = RunResponse(Wire, {});
    EXPECT_TRUE(IsProtocolError(Result.Failure, Error::BadMessage));
}

TEST(HttpForwardResponse, ForbiddenChunkTrailerFieldIsRejected)
{
    const std::string Wire = "HTTP/1.1 200 OK\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n"
                             "0\r\n"
                             "Content-Length: 0\r\n"
                             "\r\n";
    const auto Result = RunResponse(Wire, {});
    EXPECT_TRUE(IsProtocolError(Result.Failure, Error::BadMessage));
}

TEST(HttpForwardResponse, TruncatedChunkedBodyIsRejected)
{
    const std::string Wire = "HTTP/1.1 200 OK\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n"
                             "4\r\nWi";
    RunOptions Options;
    Options.ShutdownSource = true;
    const auto Result = RunResponse(Wire, Options);
    EXPECT_TRUE(IsProtocolError(Result.Failure, Error::UnexpectedEof));
}

TEST(HttpForwardResponse, Upgrade101EntersTunnelMode)
{
    const std::string Wire = "HTTP/1.1 101 Switching Protocols\r\n"
                             "Connection: Upgrade\r\n"
                             "Upgrade: websocket\r\n"
                             "\r\n"
                             "tunnel-data";
    RunOptions Options;
    Options.Framing.AllowUpgrade = true;
    const auto Result = ReadFirst(Wire, Options);
    EXPECT_TRUE(Result.Failure.Succeeded());
    EXPECT_EQ(Result.Bytes, Wire);
}

TEST(HttpForwardResponse, Upgrade101WithoutPermissionIsRejected)
{
    const std::string Wire = "HTTP/1.1 101 Switching Protocols\r\n"
                             "Connection: Upgrade\r\n"
                             "Upgrade: websocket\r\n"
                             "\r\n";
    const auto Result = RunResponse(Wire, {});
    EXPECT_TRUE(IsProtocolError(Result.Failure, Error::BadMessage));
}

TEST(HttpForwardResponse, HeaderAndTrailerBuffersAreBounded)
{
    const auto HeaderLimit = Preview::Http11::MaxResponseHeaderBlockBytes;
    Preview::Http11::ForwardResponseFraming HeaderParser({});
    std::string HeaderWire = "HTTP/1.1 200 OK\r\nX-Pad: ";
    HeaderWire.append(HeaderLimit, 'x');
    HeaderWire.append("\r\n\r\n");
    const auto HeaderResult = HeaderParser.Consume(Preview::AsBytesSpan(HeaderWire));
    EXPECT_EQ(HeaderResult.ErrorCode, Error::BadLength);

    Preview::Http11::ForwardResponseFraming TrailerParser({});
    std::string TrailerWire = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Pad: ";
    TrailerWire.append(HeaderLimit, 'x');
    TrailerWire.append("\r\n\r\n");
    const auto TrailerResult = TrailerParser.Consume(Preview::AsBytesSpan(TrailerWire));
    EXPECT_EQ(TrailerResult.ErrorCode, Error::BadLength);
}

TEST(HttpForwardResponse, CancelWakesPendingReadAndPreservesCancellation)
{
    Net::io_context IoContext;
    auto [PeerEnd, SourceEnd] = Preview::MakeMemoryPair(IoContext.get_executor());
    auto Peer = std::make_shared<Preview::MemoryStream>(std::move(PeerEnd));
    auto Source = std::make_shared<Preview::MemoryStream>(std::move(SourceEnd));
    auto Framed = Preview::Http11::MakeForwardResponseTransport({Source, {}});
    auto ReadError = std::make_shared<Preview::Fault::Failure>();
    auto ReadCount = std::make_shared<std::size_t>(0);
    RunCoroutine(IoContext, RunCancelRead(CancelReadRequest{
        IoContext, Peer, Framed, ReadCount, ReadError}));

    EXPECT_EQ(*ReadCount, 0U);
    EXPECT_EQ(ReadError->Code, Preview::Fault::Code::Canceled);
    EXPECT_EQ(ReadError->Native, std::make_error_code(std::errc::operation_canceled));
    EXPECT_TRUE(Peer->IsOpen());
    CheckTransmissionClose(Preview::Testing::Http11::DriveCloseTransmission(IoContext, Framed));
    CheckTransmissionClose(Preview::Testing::Http11::DriveCloseTransmission(IoContext, Peer));
    CheckTransmissionClose(Preview::Testing::Http11::DriveCloseTransmission(IoContext, Source));
}

TEST(HttpForwardResponse, ShutdownAndWriteDelegateToInner)
{
    Net::io_context IoContext;
    auto [PeerEnd, SourceEnd] = Preview::MakeMemoryPair(IoContext.get_executor());
    auto Peer = std::make_shared<Preview::MemoryStream>(std::move(PeerEnd));
    auto Source = std::make_shared<Preview::MemoryStream>(std::move(SourceEnd));
    auto Framed = Preview::Http11::MakeForwardResponseTransport({Source, {}});
    auto Received = std::make_shared<std::string>();
    RunCoroutine(IoContext, RunShutdownAndWrite(
        ShutdownWriteRequest{Peer, Framed, Received}));

    EXPECT_EQ(*Received, "write-through");
    CheckTransmissionClose(Preview::Testing::Http11::DriveCloseTransmission(IoContext, Framed));
    CheckTransmissionClose(Preview::Testing::Http11::DriveCloseTransmission(IoContext, Peer));
    CheckTransmissionClose(Preview::Testing::Http11::DriveCloseTransmission(IoContext, Source));
    EXPECT_FALSE(Framed->IsOpen());
}
