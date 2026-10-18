/**
 * @file Http11ForwardRequestFramingTest.cpp
 * @brief HTTP/1.1 首请求 body framing 和后续请求边界测试。
 */

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Protocols/Http1/Conn.hpp>
#include <Prism/Protocols/Http1/IngressFactory.hpp>
#include <Prism/Protocols/Http1/ForwardRequest.hpp>
#include <Prism/Protocols/Http1/Parser.hpp>
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
#include <vector>

#include "HttpTestSupport.hpp"
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using Prism::Error;
    using Prism::SharedTransmission;
    using Prism::Testing::Http11::CheckTransmissionClose;
    using Prism::Testing::Http11::CloseTransmission;
    using Prism::Testing::Http11::InspectControl;
    using Prism::Testing::Http11::InspectExactWrite;
    using Prism::Testing::Http11::MakeBytePool;
    using Prism::Testing::Http11::ReadUntilEof;
    using Prism::Testing::Http11::RunMemoryCase;
    using Prism::Testing::Http11::RunCoroutine;
    using Prism::Testing::Http11::SpawnTask;
    using Prism::Testing::Http11::WaitForTask;
}
namespace
{
    struct CoalescedRequest final
    {
        SharedTransmission Client;
        SharedTransmission ServerTransport;
        std::string Raw;
        std::size_t ExpectedSize;
        std::string *Received;
    };

    /**
     * @brief 读取释放后的转发请求及其完整 body。
     * @param Request 请求 wire、传输和结果输出。
     */
    auto RunCoalescedRequest(CoalescedRequest Request) -> Net::awaitable<void>
    {
        Prism::Http11::ServerConn Server(Request.ServerTransport, MakeBytePool());
        std::error_code Error;
        const auto Write = co_await Request.Client->WriteExact(Prism::AsBytesSpan(Request.Raw));
        Error = InspectExactWrite(Write, Request.Raw.size()).Error;
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        const auto Shutdown = co_await Request.Client->WriteShutdown();
        Error = InspectControl(Shutdown);
        if (Error)
        {
            ADD_FAILURE() << Error.message();
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
            ADD_FAILURE() << "HTTP forward transport was not produced";
            co_return;
        }
        std::vector<std::byte> Buffer(Request.ExpectedSize);
        const auto Read = co_await Forwarded->ReadExact(std::span<std::byte>(Buffer));
        const auto Count = Read.Bytes;
        if (Count <= Buffer.size())
        {
            Request.Received->assign(reinterpret_cast<const char *>(Buffer.data()), Count);
        }
        else
        {
            Error = std::make_error_code(std::errc::protocol_error);
        }
        if (!Error)
        {
            Error = Prism::Fault::ToNative(Read.Failure);
        }
        EXPECT_FALSE(Error);
        CheckTransmissionClose(co_await CloseTransmission(std::move(Forwarded)));
    }

    struct BoundedForwardRequest final
    {
        SharedTransmission Client;
        SharedTransmission ServerTransport;
        std::string Wire;
        std::string *Received;
        Prism::Fault::Failure *ReadError;
    };

    /**
     * @brief 将 coalesced 请求限制在声明的 Content-Length 内。
     * @param Request 请求 wire、传输和结果输出。
     */
    auto RunBoundedForward(BoundedForwardRequest Request) -> Net::awaitable<void>
    {
        Prism::Http11::ServerConn Server(Request.ServerTransport, MakeBytePool());
        std::error_code Error;
        const auto Write = co_await Request.Client->WriteExact(Prism::AsBytesSpan(Request.Wire));
        Error = InspectExactWrite(Write, Request.Wire.size()).Error;
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        const auto Shutdown = co_await Request.Client->WriteShutdown();
        Error = InspectControl(Shutdown);
        if (Error)
        {
            *Request.ReadError = Prism::Fault::FromNative(Error);
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
        *Request.Received = Result.Bytes;
        *Request.ReadError = Result.Failure;
        CheckTransmissionClose(co_await CloseTransmission(std::move(Forwarded)));
    }

    struct FragmentedForwardRequest final
    {
        SharedTransmission Client;
        SharedTransmission ServerTransport;
        std::string Header;
        std::string Body;
        std::string Followup;
        std::string *Received;
        Prism::Fault::Failure *ReadError;
    };

    /**
     * @brief 分段发送 body 和后续请求并验证 Content-Length 边界。
     * @param Request 分段输入、传输和结果输出。
     */
    auto RunFragmentedForward(FragmentedForwardRequest Request) -> Net::awaitable<void>
    {
        Prism::Http11::ServerConn Server(Request.ServerTransport, MakeBytePool());
        std::error_code Error;
        const auto Write = co_await Request.Client->WriteExact(Prism::AsBytesSpan(Request.Header));
        Error = InspectExactWrite(Write, Request.Header.size()).Error;
        if (Error)
        {
            ADD_FAILURE() << Error.message();
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
            ADD_FAILURE() << "HTTP forward transport was not produced";
            co_return;
        }
        const auto FollowupWrite = co_await Request.Client->WriteExact(
            Prism::AsBytesSpan(Request.Body + Request.Followup));
        Error = InspectExactWrite(FollowupWrite, Request.Body.size() + Request.Followup.size()).Error;
        if (Error)
        {
            ADD_FAILURE() << Error.message();
            co_return;
        }
        const auto Shutdown = co_await Request.Client->WriteShutdown();
        Error = InspectControl(Shutdown);
        if (Error)
        {
            *Request.ReadError = Prism::Fault::FromNative(Error);
            co_return;
        }
        const auto Result = co_await ReadUntilEof(Forwarded);
        *Request.Received = Result.Bytes;
        *Request.ReadError = Result.Failure;
        CheckTransmissionClose(co_await CloseTransmission(std::move(Forwarded)));
    }

}

TEST(Http11Connect, ReleaseForwardPreservesCoalescedRequestAndBody)
{
    Net::io_context Io;
    auto [ClientEnd, ServerEnd] = Prism::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientEnd));
    auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(ServerEnd));
    const std::string Raw = "POST http://example.com/upload HTTP/1.1\r\n"
                             "Host: example.com\r\n"
                             "Content-Length: 7\r\n"
                             "\r\n"
                             "payload";
    const std::string Expected = "POST /upload HTTP/1.1\r\n"
                                "Host: example.com\r\n"
                                "Content-Length: 7\r\n"
                                "\r\n"
                                "payload";
    std::string Received;

    RunMemoryCase(Io, {Client, ServerTransport}, RunCoalescedRequest(CoalescedRequest{
        Client, ServerTransport, Raw, Expected.size(), &Received}));

    EXPECT_EQ(Received, Expected);
}

TEST(Http11Connect, ReleaseForwardBoundsCoalescedContentLengthBeforeFollowup)
{
    Net::io_context Io;
    auto [ClientEnd, ServerEnd] = Prism::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientEnd));
    auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(ServerEnd));
    const std::string First = "POST /first HTTP/1.1\r\n"
                              "Host: example.com\r\n"
                              "Content-Length: 3\r\n"
                              "\r\none";
    const std::string Followup = "GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const std::string Wire = First + Followup;
    std::string Received;
    Prism::Fault::Failure ReadError;

    RunMemoryCase(Io, {Client, ServerTransport}, RunBoundedForward(BoundedForwardRequest{
        Client, ServerTransport, Wire, &Received, &ReadError}));

    EXPECT_EQ(ReadError.Code, Prism::Fault::Code::Eof);
    EXPECT_FALSE(ReadError.Native);
    EXPECT_EQ(Received,
              "POST /first HTTP/1.1\r\n"
              "Host: example.com\r\n"
              "Content-Length: 3\r\n"
              "\r\n"
              "one");
}

TEST(Http11Connect, ReleaseForwardBoundsFragmentedContentLengthBeforeFollowup)
{
    Net::io_context Io;
    auto [ClientEnd, ServerEnd] = Prism::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientEnd));
    auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(ServerEnd));
    const std::string Header = "POST /fragmented HTTP/1.1\r\n"
                               "Host: example.com\r\n"
                               "Content-Length: 6\r\n"
                               "\r\n";
    const std::string Body = "abcdef";
    const std::string Followup = "GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n";
    std::string Received;
    Prism::Fault::Failure ReadError;

    RunMemoryCase(Io, {Client, ServerTransport}, RunFragmentedForward(FragmentedForwardRequest{
        Client, ServerTransport, Header, Body, Followup, &Received, &ReadError}));

    EXPECT_EQ(ReadError.Code, Prism::Fault::Code::Eof);
    EXPECT_FALSE(ReadError.Native);
    EXPECT_EQ(Received,
              "POST /fragmented HTTP/1.1\r\n"
              "Host: example.com\r\n"
              "Content-Length: 6\r\n"
              "\r\n"
              "abcdef");
}

TEST(Http11Connect, ReleaseForwardBoundsChunkedMessageBeforeFollowup)
{
    Net::io_context Io;
    auto [ClientEnd, ServerEnd] = Prism::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientEnd));
    auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(ServerEnd));
    const std::string First = "POST /chunked HTTP/1.1\r\n"
                              "Host: example.com\r\n"
                              "Transfer-Encoding: chunked\r\n"
                              "\r\n"
                              "3\r\none\r\n"
                              "0\r\n"
                              "X-Trailer: done\r\n"
                              "\r\n";
    const std::string Followup = "GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const std::string Wire = First + Followup;
    std::string Received;
    Prism::Fault::Failure ReadError;

    RunMemoryCase(Io, {Client, ServerTransport}, RunBoundedForward(BoundedForwardRequest{
        Client, ServerTransport, Wire, &Received, &ReadError}));

    EXPECT_EQ(ReadError.Code, Prism::Fault::Code::Eof);
    EXPECT_FALSE(ReadError.Native);
    EXPECT_EQ(Received,
              "POST /chunked HTTP/1.1\r\n"
              "Host: example.com\r\n"
              "Transfer-Encoding: chunked\r\n"
              "\r\n"
              "3\r\none\r\n"
              "0\r\n"
              "X-Trailer: done\r\n"
              "\r\n");
}

TEST(Http11Connect, ReleaseForwardStopsAtHeaderForUnframedGet)
{
    Net::io_context Io;
    auto [ClientEnd, ServerEnd] = Prism::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientEnd));
    auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(ServerEnd));
    const std::string First = "GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const std::string Followup = "GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const std::string Wire = First + Followup;
    std::string Received;
    Prism::Fault::Failure ReadError;

    RunMemoryCase(Io, {Client, ServerTransport}, RunBoundedForward(BoundedForwardRequest{
        Client, ServerTransport, Wire, &Received, &ReadError}));

    EXPECT_EQ(ReadError.Code, Prism::Fault::Code::Eof);
    EXPECT_FALSE(ReadError.Native);
    EXPECT_EQ(Received, First);
}
