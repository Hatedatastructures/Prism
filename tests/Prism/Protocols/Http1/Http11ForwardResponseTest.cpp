/**
 * @file Http11ForwardResponseTest.cpp
 * @brief HTTP/1.1 CONNECT 响应转发边界测试。
 * @details 覆盖：
 *          - CONNECT 请求解析（方法/目标/Host/Proxy-Authorization）
 *          - 客户端请求构造与响应状态码提取
 *          - Basic 认证（407/200）
 *          - CONNECT E2E：握手 + 隧道双向转发
 *          - 异常路径：畸形请求 400 / 读失败
 */

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Protocols/Http1/Conn.hpp>
#include <Prism/Protocols/Http1/IngressFactory.hpp>
#include <Prism/Protocols/Http1/ForwardRequest.hpp>
#include <Prism/Protocols/Http1/Parser.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <system_error>

#include "HttpTestSupport.hpp"
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    using Prism::Error;
    using Prism::SharedTransmission;
    using Prism::Testing::Http11::ReadUntilEof;
    using Prism::Testing::Http11::CheckTransmissionClose;
    using Prism::Testing::Http11::CloseTransmission;
    using Prism::Testing::Http11::InspectControl;
    using Prism::Testing::Http11::InspectExactWrite;
    using Prism::Testing::Http11::MakeBytePool;
    using Prism::Testing::Http11::RunMemoryCase;
    using Prism::Testing::Http11::RunCoroutine;
    using Prism::Testing::Http11::SpawnTask;
    using Prism::Testing::Http11::WaitForTask;

    [[nodiscard]] auto IsProtocolFailure(
        const Prism::Fault::Failure &Failure,
        const Prism::Error Expected) -> bool
    {
        const auto Native = static_cast<std::error_code>(Prism::make_error_code(Expected));
        return Failure.Code == Prism::Fault::ToCode(Native) && Failure.Native == Native;
    }

    struct ResponseFailureRequest final
    {
        SharedTransmission Client;
        SharedTransmission ServerTransport;
        std::string Wire;
        Prism::Fault::Failure *ReadError;
    };

    /**
     * @brief 读取释放后的响应转发并保留真实错误。
     * @param Request 请求 wire、传输和错误输出。
     */
    auto RunResponseFailure(ResponseFailureRequest Request) -> Net::awaitable<void>
    {
        Prism::Http11::ServerConn Server(Request.ServerTransport, MakeBytePool());
        const auto Write = co_await Request.Client->WriteExact(Prism::AsBytesSpan(Request.Wire));
        auto ErrorCode = InspectExactWrite(Write, Request.Wire.size()).Error;
        if (ErrorCode)
        {
            ADD_FAILURE() << ErrorCode.message();
            co_return;
        }
        const auto Shutdown = co_await Request.Client->WriteShutdown();
        ErrorCode = InspectControl(Shutdown);
        if (ErrorCode)
        {
            *Request.ReadError = Prism::Fault::FromNative(ErrorCode);
            co_return;
        }
        Prism::Http11::HttpRequest HttpRequest;
        const auto RequestRead = co_await Server.ReadRequest(HttpRequest);
        if (RequestRead.Failed())
        {
            ADD_FAILURE() << "HTTP request read failed";
            co_return;
        }
        auto Forwarded = Server.ReleaseForward();
        if (!Forwarded)
        {
            *Request.ReadError = Prism::Fault::FromNative(
                std::make_error_code(std::errc::io_error));
            co_return;
        }
        const auto Result = co_await ReadUntilEof(Forwarded);
        *Request.ReadError = Result.Failure;
        CheckTransmissionClose(co_await CloseTransmission(std::move(Forwarded)));
    }

    struct ResponseWatchdogRequest final
    {
        std::shared_ptr<Net::steady_timer> Watchdog;
        std::shared_ptr<std::atomic_bool> TimedOut;
        SharedTransmission Client;
        SharedTransmission ServerTransport;
    };

    /**
     * @brief 超时关闭未完成的 downstream response 场景。
     * @param Request watchdog、传输和超时结果。
     */
    auto RunResponseWatchdog(ResponseWatchdogRequest Request) -> Net::awaitable<void>
    {
        boost::system::error_code Error;
        co_await Request.Watchdog->async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (!Error)
        {
            Request.TimedOut->store(true);
            CheckTransmissionClose(co_await CloseTransmission(Request.Client));
            CheckTransmissionClose(co_await CloseTransmission(Request.ServerTransport));
        }
    }

    struct DownstreamResponseRequest final
    {
        SharedTransmission Client;
        SharedTransmission ServerTransport;
        std::string Wire;
        std::string Response;
        std::shared_ptr<Net::steady_timer> Watchdog;
        std::shared_ptr<std::atomic_bool> TimedOut;
        std::string *ClientResponse;
        Prism::Fault::Failure *ReadError;
    };

    /**
     * @brief 处理 request 半关闭后的 downstream response。
     * @param Request 请求、响应、watchdog 和结果输出。
     */
    auto RunDownstreamResponse(DownstreamResponseRequest Request) -> Net::awaitable<void>
    {
        Prism::Http11::ServerConn Server(Request.ServerTransport, MakeBytePool());
        const auto Write = co_await Request.Client->WriteExact(Prism::AsBytesSpan(Request.Wire));
        auto ErrorCode = InspectExactWrite(Write, Request.Wire.size()).Error;
        if (ErrorCode)
        {
            Request.Watchdog->cancel();
            ADD_FAILURE() << ErrorCode.message();
            co_return;
        }
        const auto Shutdown = co_await Request.Client->WriteShutdown();
        ErrorCode = InspectControl(Shutdown);
        if (ErrorCode)
        {
            Request.Watchdog->cancel();
            *Request.ReadError = Prism::Fault::FromNative(ErrorCode);
            co_return;
        }
        Prism::Http11::HttpRequest HttpRequest;
        const auto RequestRead = co_await Server.ReadRequest(HttpRequest);
        if (RequestRead.Failed())
        {
            Request.Watchdog->cancel();
            ADD_FAILURE() << "HTTP request read failed";
            co_return;
        }
        auto Forwarded = Server.ReleaseForward();
        if (!Forwarded)
        {
            Request.Watchdog->cancel();
            ADD_FAILURE() << "HTTP forward transport was not produced";
            co_return;
        }
        const auto Result = co_await ReadUntilEof(Forwarded);
        *Request.ReadError = Result.Failure;
        const auto ResponseWrite = co_await Forwarded->WriteExact(
            Prism::AsBytesSpan(Request.Response));
        ErrorCode = InspectExactWrite(ResponseWrite, Request.Response.size()).Error;
        if (ErrorCode)
        {
            Request.Watchdog->cancel();
            ADD_FAILURE() << ErrorCode.message();
            co_return;
        }
        std::array<std::byte, 128> Buffer{};
        const auto Read = co_await Request.Client->ReadSome(Buffer);
        const auto Count = Read.Bytes;
        if (Count > Buffer.size())
        {
            Request.Watchdog->cancel();
            *Request.ReadError = Prism::Fault::FromNative(
                std::make_error_code(std::errc::protocol_error));
            CheckTransmissionClose(co_await CloseTransmission(std::move(Forwarded)));
            co_return;
        }
        Request.ClientResponse->assign(reinterpret_cast<const char *>(Buffer.data()), Count);
        if (Read.Failure.Failed())
        {
            *Request.ReadError = Read.Failure;
        }
        Request.Watchdog->cancel();
        CheckTransmissionClose(co_await CloseTransmission(std::move(Forwarded)));
    }

    /** @brief 等待原 watchdog 任务后返回，避免遗留 detached timer。 */
    auto RunDownstreamResponseCase(
        Net::io_context &Io,
        DownstreamResponseRequest Request) -> Net::awaitable<void>
    {
        auto WatchdogTask = SpawnTask(Io.get_executor(), RunResponseWatchdog(
            ResponseWatchdogRequest{
                Request.Watchdog,
                Request.TimedOut,
                Request.Client,
                Request.ServerTransport}));
        co_await RunDownstreamResponse(std::move(Request));
        co_await WaitForTask(std::move(WatchdogTask));
    }
}

TEST(Http11Connect, ReleaseForwardRejectsPrematureContentLengthEof)
{
    Net::io_context Io;
    auto [ClientEnd, ServerEnd] = Prism::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientEnd));
    auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(ServerEnd));
    const std::string Wire = "POST /short HTTP/1.1\r\n"
                             "Host: example.com\r\n"
                             "Content-Length: 6\r\n"
                             "\r\n"
                             "abc";
    Prism::Fault::Failure ReadError;

    RunMemoryCase(Io, {Client, ServerTransport}, RunResponseFailure(ResponseFailureRequest{
        Client, ServerTransport, Wire, &ReadError}));

    EXPECT_TRUE(IsProtocolFailure(ReadError, Prism::Error::UnexpectedEof));
}

TEST(Http11Connect, ReleaseForwardRejectsMalformedChunkSize)
{
    Net::io_context Io;
    auto [ClientEnd, ServerEnd] = Prism::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientEnd));
    auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(ServerEnd));
    const std::string Wire = "POST /bad-chunk HTTP/1.1\r\n"
                             "Host: example.com\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n"
                             "not-hex\r\n"
                             "payload\r\n"
                             "0\r\n\r\n";
    Prism::Fault::Failure ReadError;

    RunMemoryCase(Io, {Client, ServerTransport}, RunResponseFailure(ResponseFailureRequest{
        Client, ServerTransport, Wire, &ReadError}));

    EXPECT_TRUE(IsProtocolFailure(ReadError, Prism::Error::BadMessage));
}

TEST(Http11Connect, ReleaseForwardRejectsOverlongChunkSize)
{
    Net::io_context Io;
    auto [ClientEnd, ServerEnd] = Prism::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientEnd));
    auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(ServerEnd));
    const std::string Wire = "POST /long-chunk HTTP/1.1\r\n"
                             "Host: example.com\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n" +
                             std::string(Prism::Http11::MaxHdrSize + 1U, '0') + "\r\n";
    Prism::Fault::Failure ReadError;

    RunMemoryCase(Io, {Client, ServerTransport}, RunResponseFailure(ResponseFailureRequest{
        Client, ServerTransport, Wire, &ReadError}));

    EXPECT_TRUE(IsProtocolFailure(ReadError, Prism::Error::BadMessage));
}

TEST(Http11Connect, ReleaseForwardRejectsOverlongChunkTrailer)
{
    Net::io_context Io;
    auto [ClientEnd, ServerEnd] = Prism::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientEnd));
    auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(ServerEnd));
    const std::string Wire = "POST /long-trailer HTTP/1.1\r\n"
                             "Host: example.com\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n"
                             "0\r\nX-Trailer: " +
                             std::string(Prism::Http11::MaxHdrSize + 1U, 'x') + "\r\n\r\n";
    Prism::Fault::Failure ReadError;

    RunMemoryCase(Io, {Client, ServerTransport}, RunResponseFailure(ResponseFailureRequest{
        Client, ServerTransport, Wire, &ReadError}));

    EXPECT_TRUE(IsProtocolFailure(ReadError, Prism::Error::BadMessage));
}

TEST(Http11Connect, ReleaseForwardAllowsDownstreamResponseAfterRequestHalfClose)
{
    Net::io_context Io;
    auto [ClientEnd, ServerEnd] = Prism::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientEnd));
    auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(ServerEnd));
    const std::string Wire = "GET /response HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const std::string Response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
    Prism::Fault::Failure ReadError;
    std::string ClientResponse;
    auto Watchdog = std::make_shared<Net::steady_timer>(Io.get_executor());
    auto TimedOut = std::make_shared<std::atomic_bool>(false);
    Watchdog->expires_after(std::chrono::milliseconds(250));

    RunMemoryCase(Io, {Client, ServerTransport}, RunDownstreamResponseCase(Io,
        DownstreamResponseRequest{
            Client, ServerTransport, Wire, Response, Watchdog, TimedOut,
            &ClientResponse, &ReadError}));

    EXPECT_FALSE(TimedOut->load()) << "downstream response watchdog expired";
    EXPECT_EQ(ReadError.Code, Prism::Fault::Code::Eof);
    EXPECT_FALSE(ReadError.Native);
    EXPECT_EQ(ClientResponse, Response);
}
