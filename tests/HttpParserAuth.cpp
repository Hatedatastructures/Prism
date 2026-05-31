/**
 * @file HttpParserAuth.cpp
 * @brief HTTP parser 认证和转发构建单元测试
 * @details 覆盖 authenticate_proxy 和 build_fwd 两个未测试函数。
 */

#include <prism/memory.hpp>
#include <prism/protocol/http/parser.hpp>
#include <prism/account/directory.hpp>
#include <prism/crypto/sha224.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/trace/spdlog.hpp>

#include <cstdint>
#include <string>
#include <string_view>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace http = psm::protocol::http;

    auto b64_encode_str(std::string_view sv) -> psm::memory::string
    {
        const auto *ptr = reinterpret_cast<const std::uint8_t *>(sv.data());
        return psm::crypto::base64_encode(std::span<const std::uint8_t>{ptr, sv.size()});
    }

    void TestBuildFwdGet(TestRunner &runner)
    {
        http::proxy_request req;
        req.method = "GET";
        req.target = "/path/to/resource?query=1";
        req.version = "HTTP/1.1";

        auto result = http::build_fwd(req, std::pmr::get_default_resource());
        runner.Check(result == "GET /path/to/resource?query=1 HTTP/1.1\r\n",
                     "build_fwd: GET request line");
    }

    void TestBuildFwdConnect(TestRunner &runner)
    {
        http::proxy_request req;
        req.method = "CONNECT";
        req.target = "example.com:443";
        req.version = "HTTP/1.1";

        auto result = http::build_fwd(req, std::pmr::get_default_resource());
        runner.Check(result == "CONNECT example.com:443 HTTP/1.1\r\n",
                     "build_fwd: CONNECT request line");
    }

    void TestBuildFwdRootPath(TestRunner &runner)
    {
        http::proxy_request req;
        req.method = "GET";
        req.target = "/";
        req.version = "HTTP/1.1";

        auto result = http::build_fwd(req, std::pmr::get_default_resource());
        runner.Check(result == "GET / HTTP/1.1\r\n",
                     "build_fwd: root path");
    }

    void TestBuildFwdHttp10(TestRunner &runner)
    {
        http::proxy_request req;
        req.method = "POST";
        req.target = "/api";
        req.version = "HTTP/1.0";

        auto result = http::build_fwd(req, std::pmr::get_default_resource());
        runner.Check(result == "POST /api HTTP/1.0\r\n",
                     "build_fwd: HTTP/1.0");
    }

    void TestAuthenticateProxyNoPrefix(TestRunner &runner)
    {
        psm::account::directory dir;
        auto result = http::authenticate_proxy("Bearer token123", dir);
        runner.Check(!result.authenticated, "auth: no Basic prefix → not authenticated");
        runner.Check(!result.error_response.empty(), "auth: has error response");
    }

    void TestAuthenticateProxyEmpty(TestRunner &runner)
    {
        psm::account::directory dir;
        auto result = http::authenticate_proxy("", dir);
        runner.Check(!result.authenticated, "auth: empty → not authenticated");
    }

    void TestAuthenticateProxyWrongCredentials(TestRunner &runner)
    {
        psm::account::directory dir;
        const auto correct_hash = psm::crypto::sha224("password123");
        dir.upsert(correct_hash, 1);

        auto b64 = b64_encode_str("user:wrongpass");
        auto header = psm::memory::string("Basic ") + b64;

        auto result = http::authenticate_proxy(header, dir);
        runner.Check(!result.authenticated, "auth: wrong password → not authenticated");
    }

    void TestAuthenticateProxyCorrectCredentials(TestRunner &runner)
    {
        psm::account::directory dir;
        const auto hash = psm::crypto::sha224("mypassword");
        dir.upsert(hash, 10);

        auto b64 = b64_encode_str("user:mypassword");
        auto header = psm::memory::string("Basic ") + b64;

        auto result = http::authenticate_proxy(header, dir);
        runner.Check(result.authenticated, "auth: correct password → authenticated");
    }

    void TestAuthenticateProxyNoColon(TestRunner &runner)
    {
        psm::account::directory dir;
        auto b64 = b64_encode_str("userpassword");
        auto header = psm::memory::string("Basic ") + b64;

        auto result = http::authenticate_proxy(header, dir);
        runner.Check(!result.authenticated, "auth: no colon → not authenticated");
    }

    void TestAuthenticateProxyEmptyPassword(TestRunner &runner)
    {
        psm::account::directory dir;
        auto b64 = b64_encode_str("user:");
        auto header = psm::memory::string("Basic ") + b64;

        auto result = http::authenticate_proxy(header, dir);
        runner.Check(!result.authenticated, "auth: empty password → not authenticated");
    }

    void TestAuthenticateProxyCaseInsensitive(TestRunner &runner)
    {
        psm::account::directory dir;
        const auto hash = psm::crypto::sha224("pass");
        dir.upsert(hash, 1);

        auto b64 = b64_encode_str("user:pass");
        auto header = psm::memory::string("basic ") + b64;

        auto result = http::authenticate_proxy(header, dir);
        runner.Check(result.authenticated, "auth: case-insensitive basic → authenticated");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("HttpParserAuth");

    TestBuildFwdGet(runner);
    TestBuildFwdConnect(runner);
    TestBuildFwdRootPath(runner);
    TestBuildFwdHttp10(runner);
    TestAuthenticateProxyNoPrefix(runner);
    TestAuthenticateProxyEmpty(runner);
    TestAuthenticateProxyWrongCredentials(runner);
    TestAuthenticateProxyCorrectCredentials(runner);
    TestAuthenticateProxyNoColon(runner);
    TestAuthenticateProxyEmptyPassword(runner);
    TestAuthenticateProxyCaseInsensitive(runner);

    return runner.Summary();
}
