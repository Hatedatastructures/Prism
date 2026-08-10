/**
 * @file HttpCommon.cpp
 * @brief HTTP CONNECT 代理 common 模块测试（客户端与服务端编解码）
 */

#include <common/http/http.hpp>

#include <gtest/gtest.h>

using namespace psm_test;

TEST(HttpCommon, ConnectRequestRoundTrip)
{
    http::client c;
    http::server s;

    const auto req = c.connect_request("example.com", 443);
    const auto parsed = s.parse_connect(req);
    ASSERT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.host, "example.com");
    EXPECT_EQ(parsed.port, 443);
}

TEST(HttpCommon, ExtraHeaders)
{
    http::client c;
    http::server s;

    const auto req = c.connect_request("127.0.0.1", 8080, "User-Agent: prism-test");
    const auto parsed = s.parse_connect(req);
    ASSERT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.host, "127.0.0.1");
    EXPECT_EQ(parsed.port, 8080);
}

TEST(HttpCommon, ResponseOk)
{
    http::client c;

    const auto ok = http::server::ok_response();
    ASSERT_TRUE(c.parse_response(ok));

    const auto bad = http::server::fail_response();
    EXPECT_FALSE(c.parse_response(bad));
}

TEST(HttpCommon, RejectBadRequest)
{
    http::server s;

    const std::string garbage = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    const auto parsed = s.parse_connect(view(
        reinterpret_cast<const std::uint8_t *>(garbage.data()), garbage.size()));
    EXPECT_FALSE(parsed.valid);
}
