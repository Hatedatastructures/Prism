/**
 * @file Http11ConnectParsingTest.cpp
 * @brief HTTP/1.1 请求解析与构造行为测试。
 */

#include <Preview/Account/Authenticator.hpp>
#include <Preview/Protocols/Http1/Conn.hpp>
#include <Preview/Protocols/Http1/IngressFactory.hpp>
#include <Preview/Protocols/Http1/ForwardRequest.hpp>
#include <Preview/Protocols/Http1/Parser.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Transport/Reliable.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include "HttpTestSupport.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using Preview::Error;
    using Preview::SharedTransmission;
    using Preview::Testing::Http11::CheckTransmissionClose;
    using Preview::Testing::Http11::CloseTransmission;
    using Preview::Testing::Http11::InspectControl;
    using Preview::Testing::Http11::InspectExactWrite;
    using Preview::Testing::Http11::MakeBytePool;
    using Preview::Testing::Http11::ReadUntilEof;
    using Preview::Testing::Http11::RunMemoryCase;
    using Preview::Testing::Http11::RunCoroutine;
    using Preview::Testing::Http11::SpawnTask;
    using Preview::Testing::Http11::WaitForTask;
}
TEST(Http11Connect, ParseRequestOk)
{
    const std::string Raw = "CONNECT example.com:443 HTTP/1.1\r\n"
                            "Host: example.com:443\r\n"
                            "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
                            "User-Agent: test\r\n"
                            "\r\n";
    Preview::Http11::HttpRequest Request;
    const auto Result = Preview::Http11::ParseRequest(Raw, Request);
    EXPECT_EQ(Result, Preview::Fault::Code::Success);
    EXPECT_EQ(Request.Method, "CONNECT");
    EXPECT_EQ(Request.Target, "example.com:443");
    EXPECT_EQ(Request.version, "HTTP/1.1");
    EXPECT_EQ(Request.host, "example.com:443");
    EXPECT_EQ(Request.authorization, "Basic dXNlcjpwYXNz");
}

TEST(Http11Connect, ParsesAbsoluteFormAndBuildsOriginRequest)
{
    const std::string Raw = "POST http://example.com:8080/api?q=1 HTTP/1.1\r\n"
                             "Host: example.com:8080\r\n"
                             "X-Request: keep\r\n"
                             "Content-Length: 7\r\n"
                             "\r\n"
                             "payload";
    Preview::Http11::HttpRequest Request;

    ASSERT_EQ(Preview::Http11::ParseRequest(Raw, Request), Preview::Fault::Code::Success);
    ASSERT_TRUE(Preview::Http11::ResolveTarget(Request).has_value());
    const auto Target = *Preview::Http11::ResolveTarget(Request);
    EXPECT_EQ(Target.Form, Preview::Http11::RequestForm::Absolute);
    EXPECT_EQ(Target.Host, "example.com");
    EXPECT_EQ(Target.Port, 8080);

    EXPECT_EQ(
        Preview::Http11::BuildForwardRequest(Raw, Request),
        "POST /api?q=1 HTTP/1.1\r\n"
        "Host: example.com:8080\r\n"
        "X-Request: keep\r\n"
        "Content-Length: 7\r\n"
        "\r\n"
        "payload");
}

TEST(Http11Connect, RejectsHttpsAbsoluteFormCaseInsensitively)
{
    const std::array<std::string_view, 2> Targets = {
        "https://origin.example/private",
        "HtTpS://origin.example/private",
    };

    for (const auto Target : Targets)
    {
        const std::string Raw = "GET " + std::string(Target) + " HTTP/1.1\r\n"
                                 "Host: origin.example\r\n"
                                 "\r\n";
        Preview::Http11::HttpRequest Request;
        ASSERT_EQ(Preview::Http11::ParseRequest(Raw, Request), Preview::Fault::Code::Success)
            << Target;
        EXPECT_FALSE(Preview::Http11::ResolveTarget(Request).has_value()) << Target;
    }
}

TEST(Http11Connect, RejectsLiteralFragmentsAcrossRequestTargetForms)
{
    struct FragmentTarget
    {
        std::string_view Method;
        std::string_view Target;
        std::string_view Host;
    };
    const std::array<FragmentTarget, 4> Targets = {
        FragmentTarget{"GET", "http://origin.example/path#fragment", "origin.example"},
        FragmentTarget{"GET", "/path#fragment", "origin.example"},
        FragmentTarget{"GET", "#fragment", "origin.example"},
        FragmentTarget{"CONNECT", "origin.example:443#fragment", "origin.example:443"},
    };

    for (const auto &Case : Targets)
    {
        const std::string Raw = std::string(Case.Method) + " " + std::string(Case.Target) +
                                " HTTP/1.1\r\nHost: " + std::string(Case.Host) + "\r\n\r\n";
        Preview::Http11::HttpRequest Request;
        ASSERT_EQ(Preview::Http11::ParseRequest(Raw, Request), Preview::Fault::Code::Success)
            << Case.Target;
        EXPECT_FALSE(Preview::Http11::ResolveTarget(Request).has_value()) << Case.Target;
    }
}

TEST(Http11Connect, RejectsMalformedConnectAuthorities)
{
    const std::array<std::string_view, 2> Authorities = {
        "2001:db8::1:443",
        "[not-an-ip]:443",
    };

    for (const auto Authority : Authorities)
    {
        const std::string Raw = "CONNECT " + std::string(Authority) + " HTTP/1.1\r\n"
                                "Host: " + std::string(Authority) + "\r\n"
                                "\r\n";
        Preview::Http11::HttpRequest Request;
        ASSERT_EQ(Preview::Http11::ParseRequest(Raw, Request), Preview::Fault::Code::Success)
            << Authority;
        EXPECT_EQ(Request.Target, Authority);
        EXPECT_FALSE(Preview::Http11::ResolveTarget(Request).has_value()) << Authority;
    }
}

TEST(Http11Connect, ParseCaseInsensitiveHeaders)
{
    const std::string Raw = "CONNECT host:80 HTTP/1.1\r\n"
                            "hOsT: host:80\r\n"
                            "PrOxY-aUtHoRiZaTiOn: Basic abc\r\n"
                            "\r\n";
    Preview::Http11::HttpRequest Request;
    const auto Result = Preview::Http11::ParseRequest(Raw, Request);
    EXPECT_EQ(Result, Preview::Fault::Code::Success);
    EXPECT_EQ(Request.host, "host:80");
    EXPECT_EQ(Request.authorization, "Basic abc");
}

TEST(Http11Connect, ParseMalformed)
{
    Preview::Http11::HttpRequest Request;
    // 缺请求行
    EXPECT_EQ(Preview::Http11::ParseRequest("GET\r\n\r\n", Request), Preview::Fault::Code::ParseError);
    // 缺头结束
    EXPECT_EQ(Preview::Http11::ParseRequest("CONNECT h:1 HTTP/1.1\r\nHost: h:1\r\n", Request),
              Preview::Fault::Code::ParseError);
    // 空数据
    EXPECT_EQ(Preview::Http11::ParseRequest("", Request), Preview::Fault::Code::ParseError);
}

struct OverreportedHeaderRequest final
{
    std::shared_ptr<Preview::PreviewMockTransport> Transport;
    Preview::Http11::HttpRequest *Request;
    Preview::Fault::Code *Result;
};

auto RunOverreportedHeaderRead(OverreportedHeaderRequest Request) -> Net::awaitable<void>
{
    Preview::Http11::ServerConn Server(Request.Transport, MakeBytePool());
    *Request.Result = co_await Server.ReadRequest(*Request.Request);
}

TEST(Http11Connect, RejectsOverreportedHeaderRead)
{
    Net::io_context Io;
    auto Raw = std::make_shared<Preview::PreviewMockTransport>(Io.get_executor());
    Raw->OverreportRead = true;
    Preview::Http11::HttpRequest Request;
    Preview::Fault::Code Result = Preview::Fault::Code::Success;

    Preview::Testing::Http11::RunOwnedCase(Io, {Raw},
        RunOverreportedHeaderRead(OverreportedHeaderRequest{Raw, &Request, &Result}));

    EXPECT_EQ(Result, Preview::Fault::Code::IoError);
}

TEST(Http11Connect, ParseRejectsDuplicateSecurityHeaders)
{
    const std::string Raw = "CONNECT host:80 HTTP/1.1\r\n"
                            "Host: host:80\r\n"
                            "Host: other:80\r\n"
                            "Proxy-Authorization: Basic abc\r\n"
                            "Proxy-Authorization: Basic def\r\n"
                            "\r\n";
    Preview::Http11::HttpRequest Request;
    EXPECT_EQ(Preview::Http11::ParseRequest(Raw, Request), Preview::Fault::Code::ParseError);
}

TEST(Http11Connect, ParseRejectsObsoleteFoldingAndInvalidCharacters)
{
    const std::string Folded = "CONNECT host:80 HTTP/1.1\r\n"
                               "Host: host:80\r\n"
                               "\tcontinued\r\n"
                               "\r\n";
    const std::string InvalidName = "CONNECT host:80 HTTP/1.1\r\n"
                                     "Bad Header: value\r\n"
                                     "\r\n";
    const std::string InvalidValue = "CONNECT host:80 HTTP/1.1\r\n"
                                      "Host: host:\x01\r\n"
                                      "\r\n";
    Preview::Http11::HttpRequest Request;
    EXPECT_EQ(Preview::Http11::ParseRequest(Folded, Request), Preview::Fault::Code::ParseError);
    EXPECT_EQ(Preview::Http11::ParseRequest(InvalidName, Request), Preview::Fault::Code::ParseError);
    EXPECT_EQ(Preview::Http11::ParseRequest(InvalidValue, Request), Preview::Fault::Code::ParseError);
}

TEST(Http11Connect, ParseRejectsOversizedHeaderBlock)
{
    std::string Raw = "CONNECT host:80 HTTP/1.1\r\nHost: host:80\r\nX-Pad: ";
    Raw.append(Preview::Http11::MaxHdrSize, 'x');
    Raw.append("\r\n\r\n");
    Preview::Http11::HttpRequest Request;
    EXPECT_EQ(Preview::Http11::ParseRequest(Raw, Request), Preview::Fault::Code::ParseError);
}

TEST(Http11Connect, ParseStatusCode)
{
    EXPECT_EQ(Preview::Http11::ParseStatusCode("HTTP/1.1 200 Connection Established\r\n\r\n"), 200);
    EXPECT_EQ(Preview::Http11::ParseStatusCode("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"), 407);
    EXPECT_EQ(Preview::Http11::ParseStatusCode("garbage"), 0);
}

TEST(Http11Connect, MakeConnectRequest)
{
    const auto Request = Preview::Http11::MakeConnectRequest("example.com", 443);
    EXPECT_TRUE(Request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
    EXPECT_TRUE(Request.find("Host: example.com:443\r\n") != std::string::npos);
    EXPECT_EQ(Request.find("Proxy-Authorization"), std::string::npos);

    const auto WithAuth = Preview::Http11::MakeConnectRequest("h", 80, "Basic dXNlcjpwYXNz");
    EXPECT_TRUE(WithAuth.find("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n") != std::string::npos);
}

