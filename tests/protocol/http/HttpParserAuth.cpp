/**
 * @file HttpParserAuth.cpp
 * @brief HTTP parser 认证和转发构建单元测试
 * @details 覆盖 authenticate_proxy 和 build_fwd 两个未测试函数。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/protocol/http/parser.hpp>
#include <prism/account/directory.hpp>
#include <prism/crypto/sha224.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/trace/spdlog.hpp>

#include <cstdint>
#include <string>
#include <string_view>


#include <gtest/gtest.h>

namespace
{
    namespace http = psm::protocol::http;

    auto b64_encode_str(std::string_view sv) -> psm::memory::string
    {
        const auto *ptr = reinterpret_cast<const std::uint8_t *>(sv.data());
        return psm::crypto::base64_encode(std::span<const std::uint8_t>{ptr, sv.size()});
    }

    TEST(HttpParserAuth, BuildFwdGet)
    {
        http::proxy_request req;
        req.method = "GET";
        req.target = "/path/to/resource?query=1";
        req.version = "HTTP/1.1";

        auto result = http::build_fwd(req, std::pmr::get_default_resource());
        EXPECT_TRUE(result == "GET /path/to/resource?query=1 HTTP/1.1\r\n")
            << "build_fwd: GET request line";
    }

    TEST(HttpParserAuth, BuildFwdConnect)
    {
        http::proxy_request req;
        req.method = "CONNECT";
        req.target = "example.com:443";
        req.version = "HTTP/1.1";

        auto result = http::build_fwd(req, std::pmr::get_default_resource());
        EXPECT_TRUE(result == "CONNECT example.com:443 HTTP/1.1\r\n")
            << "build_fwd: CONNECT request line";
    }

    TEST(HttpParserAuth, BuildFwdRootPath)
    {
        http::proxy_request req;
        req.method = "GET";
        req.target = "/";
        req.version = "HTTP/1.1";

        auto result = http::build_fwd(req, std::pmr::get_default_resource());
        EXPECT_TRUE(result == "GET / HTTP/1.1\r\n")
            << "build_fwd: root path";
    }

    TEST(HttpParserAuth, BuildFwdHttp10)
    {
        http::proxy_request req;
        req.method = "POST";
        req.target = "/api";
        req.version = "HTTP/1.0";

        auto result = http::build_fwd(req, std::pmr::get_default_resource());
        EXPECT_TRUE(result == "POST /api HTTP/1.0\r\n")
            << "build_fwd: HTTP/1.0";
    }

    TEST(HttpParserAuth, AuthenticateProxyNoPrefix)
    {
        psm::account::directory dir;
        auto result = http::authenticate_proxy("Bearer token123", dir);
        EXPECT_TRUE(!result.authenticated) << "auth: no Basic prefix -> not authenticated";
        EXPECT_TRUE(!result.error_response.empty()) << "auth: has error response";
    }

    TEST(HttpParserAuth, AuthenticateProxyEmpty)
    {
        psm::account::directory dir;
        auto result = http::authenticate_proxy("", dir);
        EXPECT_TRUE(!result.authenticated) << "auth: empty -> not authenticated";
    }

    TEST(HttpParserAuth, AuthenticateProxyWrongCredentials)
    {
        psm::account::directory dir;
        const auto correct_hash = psm::crypto::sha224("password123");
        dir.upsert(correct_hash, 1);

        auto b64 = b64_encode_str("user:wrongpass");
        auto header = psm::memory::string("Basic ") + b64;

        auto result = http::authenticate_proxy(header, dir);
        EXPECT_TRUE(!result.authenticated) << "auth: wrong password -> not authenticated";
    }

    TEST(HttpParserAuth, AuthenticateProxyCorrectCredentials)
    {
        psm::account::directory dir;
        const auto hash = psm::crypto::sha224("mypassword");
        dir.upsert(hash, 10);

        auto b64 = b64_encode_str("user:mypassword");
        auto header = psm::memory::string("Basic ") + b64;

        auto result = http::authenticate_proxy(header, dir);
        EXPECT_TRUE(result.authenticated) << "auth: correct password -> authenticated";
    }

    TEST(HttpParserAuth, AuthenticateProxyNoColon)
    {
        psm::account::directory dir;
        auto b64 = b64_encode_str("userpassword");
        auto header = psm::memory::string("Basic ") + b64;

        auto result = http::authenticate_proxy(header, dir);
        EXPECT_TRUE(!result.authenticated) << "auth: no colon -> not authenticated";
    }

    TEST(HttpParserAuth, AuthenticateProxyEmptyPassword)
    {
        psm::account::directory dir;
        auto b64 = b64_encode_str("user:");
        auto header = psm::memory::string("Basic ") + b64;

        auto result = http::authenticate_proxy(header, dir);
        EXPECT_TRUE(!result.authenticated) << "auth: empty password -> not authenticated";
    }

    TEST(HttpParserAuth, AuthenticateProxyCaseInsensitive)
    {
        psm::account::directory dir;
        const auto hash = psm::crypto::sha224("pass");
        dir.upsert(hash, 1);

        auto b64 = b64_encode_str("user:pass");
        auto header = psm::memory::string("basic ") + b64;

        auto result = http::authenticate_proxy(header, dir);
        EXPECT_TRUE(result.authenticated) << "auth: case-insensitive basic -> authenticated";
    }

} // namespace
