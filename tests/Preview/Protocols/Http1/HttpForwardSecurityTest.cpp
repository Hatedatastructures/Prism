/**
 * @file HttpForwardSecurityTest.cpp
 * @brief HTTP/1.1 正向转发安全与消息边界测试
 */

#include <Preview/Protocols/Http1/IngressFactory.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include "HttpTestSupport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <chrono>
#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <gtest/gtest.h>
#include <TestSupport/Preview/ProviderBindings.hpp>

namespace
{
    namespace Net = boost::asio;
    using Preview::Testing::Http11::CheckTransmissionClose;
    using Preview::Testing::Http11::CloseTransmission;
    using Preview::Testing::Http11::InspectControl;
    using Preview::Testing::Http11::InspectExactWrite;
    using Preview::Testing::Http11::MakeBytePool;
    using Preview::Testing::Http11::RunMemoryCase;

    struct HttpIngressCapture
    {
        Preview::Fault::Failure IngressFailure;
        Preview::Fault::Failure StreamFailure;
        std::string Bytes;
        std::string ClientResponse;
        bool ClientClosed{false};
    };

    struct HttpIngressRequest final
    {
        std::shared_ptr<Preview::MemoryStream> Client;
        std::shared_ptr<Preview::MemoryStream> Server;
        std::string Request;
        std::shared_ptr<HttpIngressCapture> Capture;
    };

    struct CaptureStreamRequest final
    {
        Preview::SharedTransmission Transport;
        std::string *Output;
        std::size_t Limit;
        bool *Closed;
    };

    /** @brief 累计真实读字节后识别 EOF、零进度和有界捕获失败。 */
    auto CaptureUntilEof(CaptureStreamRequest Request)
        -> Net::awaitable<Preview::Fault::Failure>
    {
        std::array<std::byte, 97> Buffer{};
        while (Request.Output->size() <= Request.Limit)
        {
            const auto Read = co_await Request.Transport->ReadSome(Buffer);
            if (Read.Bytes > Buffer.size() ||
                Read.Bytes > Request.Limit - Request.Output->size())
            {
                co_return Preview::Fault::FromNative(
                    std::make_error_code(std::errc::protocol_error));
            }
            if (Read.Bytes != 0U)
            {
                Request.Output->append(
                    reinterpret_cast<const char *>(Buffer.data()), Read.Bytes);
            }
            if (Read.Failure.Failed())
            {
                if (Read.Failure.Code == Preview::Fault::Code::Eof)
                {
                    if (Request.Closed != nullptr)
                    {
                        *Request.Closed = true;
                    }
                    co_return Read.Failure;
                }
                co_return Read.Failure;
            }
            if (Read.Bytes == 0U)
            {
                co_return Preview::Fault::Failure{Preview::Fault::Code::WouldBlock};
            }
        }
        co_return Preview::Fault::FromNative(
            std::make_error_code(std::errc::message_size));
    }

    /** @brief 执行认证 ingress 的真实转发、响应和关闭观察。 */
    auto RunAuthenticatedHttpIngress(HttpIngressRequest Request)
        -> Net::awaitable<void>
    {
        auto Authenticator = Preview::Testing::ProviderAccount(Preview::Testing::ProviderAccountInput{Preview::AccountId{1U}, Preview::Account::Credential::Password("pass"), "user", "user", {}})->Authenticator;
        Preview::Http11::IngressOptions Config;
        Config.RequireAuth = true;
        Config.Authenticator = Authenticator;
        Preview::Http11::IngressFactory Handler(std::move(Config));

        const auto Write = co_await Request.Client->WriteExact(
            Preview::AsBytesSpan(Request.Request));
        const auto WriteCheck = InspectExactWrite(Write, Request.Request.size());
        if (WriteCheck.Error)
        {
            ADD_FAILURE() << WriteCheck.Error.message();
            Request.Capture->StreamFailure = Preview::Fault::FromNative(WriteCheck.Error);
            Request.Capture->IngressFailure = Preview::Fault::FromNative(WriteCheck.Error);
            co_return;
        }
        const auto Shutdown = co_await Request.Client->WriteShutdown();
        const auto ShutdownError = InspectControl(Shutdown);
        if (ShutdownError)
        {
            Request.Capture->StreamFailure = Preview::Fault::FromNative(ShutdownError);
            Request.Capture->IngressFailure = Preview::Fault::FromNative(ShutdownError);
            co_return;
        }

        auto Result = co_await Handler.Accept(
            Preview::Contract::StreamAcceptInput{Request.Server, {}, MakeBytePool()});
        if (!Result)
        {
            Request.Capture->IngressFailure = Result.error();
            Request.Client->SetTimeout(std::chrono::milliseconds(250));
            const auto CaptureError = co_await CaptureUntilEof(CaptureStreamRequest{
                Request.Client, &Request.Capture->ClientResponse, 256U,
                &Request.Capture->ClientClosed});
            Request.Capture->StreamFailure = CaptureError;
            if (CaptureError.Code != Preview::Fault::Code::Eof || CaptureError.Native)
            {
                ADD_FAILURE() << "client response capture failed";
                Request.Capture->IngressFailure = CaptureError;
            }
            co_return;
        }

        auto Plane = std::move(*Result);
        const auto Transport = Plane.Transport();
        if (!Transport)
        {
            Request.Capture->IngressFailure = Preview::Fault::Failure{
                Preview::Fault::Code::IoError};
            co_return;
        }
        if (Request.Request.find("Upgrade:") != std::string::npos &&
            Request.Request.find("Connection:") != std::string::npos)
        {
            constexpr std::string_view UpgradeResponse =
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
            const auto UpgradeWrite = co_await Transport->WriteExact(
                Preview::AsBytesSpan(UpgradeResponse));
            const auto CheckedUpgradeWrite = InspectExactWrite(
                UpgradeWrite, UpgradeResponse.size());
            if (CheckedUpgradeWrite.Error)
            {
                ADD_FAILURE() << CheckedUpgradeWrite.Error.message();
                Request.Capture->StreamFailure = Preview::Fault::FromNative(
                    CheckedUpgradeWrite.Error);
                Request.Capture->IngressFailure = Preview::Fault::FromNative(
                    CheckedUpgradeWrite.Error);
            }
        }
        if (Request.Capture->IngressFailure.Succeeded())
        {
            const auto CaptureError = co_await CaptureUntilEof(CaptureStreamRequest{
                Transport, &Request.Capture->Bytes, Request.Request.size() + 256U, nullptr});
            Request.Capture->StreamFailure = CaptureError;
            if (CaptureError.Code != Preview::Fault::Code::Eof || CaptureError.Native)
            {
                ADD_FAILURE() << "forwarded request capture failed";
                Request.Capture->IngressFailure = CaptureError;
            }
        }
        CheckTransmissionClose(co_await CloseTransmission(Transport));
    }

    auto CaptureAuthenticatedHttpIngress(std::string_view Request) -> HttpIngressCapture
    {
        Net::io_context Io;
        const auto Pair = Preview::Testing::Http11::MakeOwnedMemoryPair(Io.get_executor());
        auto Client = Pair.First;
        auto Server = Pair.Second;
        auto Capture = std::make_shared<HttpIngressCapture>();
        RunMemoryCase(Io, Pair, RunAuthenticatedHttpIngress(HttpIngressRequest{
            Client, Server, std::string(Request), Capture}));
        return *Capture;
    }
} // namespace

TEST(HttpForwardSecurity, StripsProxyAndConnectionHeadersFromAuthenticatedAbsoluteForm)
{
    const std::string Request = "POST http://origin.example:8080/upload?q=1 HTTP/1.1\r\n"
                                "Host: attacker.example\r\n"
                                "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
                                "Proxy-Connection: keep-alive\r\n"
                                "Connection: X-Hop, keep-alive\r\n"
                                "Keep-Alive: timeout=5\r\n"
                                "X-Hop: hop-only\r\n"
                                "Authorization: Bearer origin-token\r\n"
                                "X-Duplicate: first\r\n"
                                "X-Duplicate: second\r\n"
                                "Content-Length: 7\r\n"
                                "\r\n"
                                "payload";

    const auto Capture = CaptureAuthenticatedHttpIngress(Request);

    ASSERT_TRUE(Capture.IngressFailure.Succeeded());
    EXPECT_EQ(Capture.StreamFailure.Code, Preview::Fault::Code::Eof);
    EXPECT_FALSE(Capture.StreamFailure.Native);
    EXPECT_EQ(Capture.Bytes,
              "POST /upload?q=1 HTTP/1.1\r\n"
              "Host: origin.example:8080\r\n"
              "Authorization: Bearer origin-token\r\n"
              "X-Duplicate: first\r\n"
              "X-Duplicate: second\r\n"
              "Content-Length: 7\r\n"
              "\r\n"
              "payload");
}

TEST(HttpForwardSecurity, RejectsUnsupportedHttpsAbsoluteFormBeforeDial)
{
    const std::string Request = "GET hTtPs://origin.example/private HTTP/1.1\r\n"
                                "Host: origin.example\r\n"
                                "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
                                "\r\n";

    const auto Capture = CaptureAuthenticatedHttpIngress(Request);

    EXPECT_EQ(Capture.IngressFailure.Code, Preview::Fault::Code::BadMessage);
    EXPECT_TRUE(Capture.Bytes.empty());
    EXPECT_EQ(Capture.ClientResponse, "HTTP/1.1 400 Bad Request\r\n"
                                     "Content-Length: 0\r\n"
                                     "\r\n");
    EXPECT_TRUE(Capture.ClientClosed);
}

TEST(HttpForwardSecurity, RejectsLiteralFragmentsBeforeForwarding)
{
    const std::array<std::string_view, 4> Targets = {
        "http://origin.example/path#fragment",
        "/path#fragment",
        "#fragment",
        "origin.example:443#fragment",
    };

    for (const auto Target : Targets)
    {
        const std::string Method = Target.starts_with("origin.") ? "CONNECT" : "GET";
        const std::string Request = Method + " " + std::string(Target) + " HTTP/1.1\r\n"
                                    "Host: origin.example\r\n"
                                    "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
                                    "\r\n";
        const auto Capture = CaptureAuthenticatedHttpIngress(Request);

        EXPECT_EQ(Capture.IngressFailure.Code, Preview::Fault::Code::BadMessage) << Target;
        EXPECT_TRUE(Capture.Bytes.empty()) << Target;
        EXPECT_EQ(Capture.ClientResponse,
                  "HTTP/1.1 400 Bad Request\r\n"
                  "Content-Length: 0\r\n"
                  "\r\n")
            << Target;
        EXPECT_TRUE(Capture.ClientClosed) << Target;
    }
}

TEST(HttpForwardSecurity, PreservesOriginFormChunkedBodyAndRemovesHopFields)
{
    const std::string Request = "POST /chunked HTTP/1.1\r\n"
                                "Host: origin.example\r\n"
                                "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
                                "Proxy-Connection: Keep-Alive\r\n"
                                "Connection: X-Hop, close\r\n"
                                "X-Hop: hop-only\r\n"
                                "Keep-Alive: timeout=5\r\n"
                                "TE: trailers\r\n"
                                "Transfer-Encoding: chunked\r\n"
                                "\r\n"
                                "7\r\npayload\r\n0\r\n\r\n";

    const auto Capture = CaptureAuthenticatedHttpIngress(Request);

    ASSERT_TRUE(Capture.IngressFailure.Succeeded());
    EXPECT_EQ(Capture.StreamFailure.Code, Preview::Fault::Code::Eof);
    EXPECT_FALSE(Capture.StreamFailure.Native);
    EXPECT_EQ(Capture.Bytes,
              "POST /chunked HTTP/1.1\r\n"
              "Host: origin.example\r\n"
              "Transfer-Encoding: chunked\r\n"
              "\r\n"
              "7\r\npayload\r\n0\r\n\r\n");
}

TEST(HttpForwardSecurity, RetainsUpgradeHandshakeSemantics)
{
    const std::string Request = "GET http://origin.example/events HTTP/1.1\r\n"
                                "Host: ignored.example\r\n"
                                "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
                                "Connection: keep-alive, Upgrade, X-Hop\r\n"
                                "Upgrade: websocket\r\n"
                                "X-Hop: hop-only\r\n"
                                "\r\n";

    const auto Capture = CaptureAuthenticatedHttpIngress(Request);

    ASSERT_TRUE(Capture.IngressFailure.Succeeded());
    EXPECT_EQ(Capture.Bytes,
              "GET /events HTTP/1.1\r\n"
              "Host: origin.example\r\n"
              "Connection: Upgrade\r\n"
              "Upgrade: websocket\r\n"
              "\r\n");
}

TEST(HttpForwardSecurity, RejectsMissingCredentialsAndMalformedHeaders)
{
    const std::string MissingCredentials = "GET http://origin.example/private HTTP/1.1\r\n"
                                           "Host: origin.example\r\n"
                                           "\r\n";
    const std::string MalformedHeader = "GET http://origin.example/private HTTP/1.1\r\n"
                                        "Host: origin.example\r\n"
                                        "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
                                        "Bad Header: invalid\r\n"
                                        "\r\n";
    const std::string ConnectionNamesHost = "GET /private HTTP/1.1\r\n"
                                            "Host: origin.example\r\n"
                                            "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
                                            "Connection: Host\r\n"
                                            "\r\n";
    const std::string ConflictingFraming = "POST /private HTTP/1.1\r\n"
                                           "Host: origin.example\r\n"
                                           "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
                                           "Transfer-Encoding: chunked\r\n"
                                           "Content-Length: 7\r\n"
                                           "\r\n"
                                           "7\r\npayload\r\n0\r\n\r\n";
    const std::string UnboundedTransferCoding = "POST /private HTTP/1.1\r\n"
                                                "Host: origin.example\r\n"
                                                "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
                                                "Transfer-Encoding: gzip\r\n"
                                                "\r\n";

    EXPECT_EQ(CaptureAuthenticatedHttpIngress(MissingCredentials).IngressFailure.Code,
              Preview::Fault::Code::AuthFailed);
    EXPECT_EQ(CaptureAuthenticatedHttpIngress(MalformedHeader).IngressFailure.Code,
              Preview::Fault::Code::BadMessage);
    const auto HostHop = CaptureAuthenticatedHttpIngress(ConnectionNamesHost);
    EXPECT_EQ(HostHop.IngressFailure.Code, Preview::Fault::Code::BadMessage);
    EXPECT_TRUE(HostHop.Bytes.empty());
    EXPECT_EQ(CaptureAuthenticatedHttpIngress(ConflictingFraming).IngressFailure.Code,
              Preview::Fault::Code::BadMessage);
    EXPECT_EQ(CaptureAuthenticatedHttpIngress(UnboundedTransferCoding).IngressFailure.Code,
              Preview::Fault::Code::BadMessage);
}

TEST(HttpForwardSecurity, KeepsCoalescedConnectPayloadOnTunnelBranch)
{
    const std::string Payload = "first-tunnel-bytes";
    const std::string Request = "CONNECT origin.example:443 HTTP/1.1\r\n"
                                "Host: origin.example:443\r\n"
                                "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
                                "\r\n" +
                                Payload;

    const auto Capture = CaptureAuthenticatedHttpIngress(Request);

    ASSERT_TRUE(Capture.IngressFailure.Succeeded());
    EXPECT_EQ(Capture.Bytes, Payload);
}
