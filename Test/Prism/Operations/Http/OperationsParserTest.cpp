/**
 * @file OperationsParserTest.cpp
 * @brief Operations HTTP 请求解析与安全头验证测试。
 */

#include <gtest/gtest.h>

#include <Prism/Operations/Routes/RequestParser.hpp>

TEST(Task10OperationsHttpParser, RejectsRepeatedSecurityHeaders)
{
    Prism::Operations::HttpRequest Request;
    EXPECT_EQ(Prism::Operations::RequestParserDetail::ParseRequest(
        "GET /Operations/Health HTTP/1.1\r\nHost: 127.0.0.1:9090\r\n"
        "Host: 127.0.0.1:9090\r\n\r\n", Request), Prism::Operations::RequestParserDetail::ParseStatus::Malformed);
    EXPECT_EQ(Prism::Operations::RequestParserDetail::ParseRequest(
        "GET /Operations/Health HTTP/1.1\r\nHost: 127.0.0.1:9090\r\n"
        "Origin: http://127.0.0.1:9090\r\nOrigin: http://127.0.0.1:9090\r\n\r\n",
        Request), Prism::Operations::RequestParserDetail::ParseStatus::Malformed);
    EXPECT_EQ(Prism::Operations::RequestParserDetail::ParseRequest(
        "POST /Operations/Reload HTTP/1.1\r\nHost: 127.0.0.1:9090\r\n"
        "Authorization: Bearer one\r\nAuthorization: Bearer two\r\n"
        "Content-Length: 0\r\n\r\n", Request), Prism::Operations::RequestParserDetail::ParseStatus::Malformed);
}
