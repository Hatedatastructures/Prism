/**
 * @file TrustTunnelAuthPure.cpp
 * @brief TrustTunnel 认证纯函数测试
 * @details 测试 verify_basic_auth / resolve_stream_target
 */

#include <prism/memory.hpp>
#include "../src/prism/stealth/stack/trusttunnel/scheme.cpp"
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    void TestVerifyBasicAuthNoPrefix(TestRunner &runner)
    {
        psm::memory::vector<psm::stealth::trusttunnel::user> users;
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Token abc", users);
        runner.Check(!result, "auth: no Basic prefix");
    }

    void TestVerifyBasicAuthEmptyUsers(TestRunner &runner)
    {
        psm::memory::vector<psm::stealth::trusttunnel::user> users;
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic dGVzdDpwYXNz", users);
        runner.Check(!result, "auth: empty users list");
    }

    void TestVerifyBasicAuthValidCredentials(TestRunner &runner)
    {
        psm::memory::vector<psm::stealth::trusttunnel::user> users;
        users.push_back({psm::memory::string("test"), psm::memory::string("pass")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic dGVzdDpwYXNz", users);
        runner.Check(result, "auth: valid credentials");
    }

    void TestVerifyBasicAuthWrongPassword(TestRunner &runner)
    {
        psm::memory::vector<psm::stealth::trusttunnel::user> users;
        users.push_back({psm::memory::string("admin"), psm::memory::string("secret")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic YWRtaW46d3Jvbg==", users);
        runner.Check(!result, "auth: wrong password");
    }

    void TestVerifyBasicAuthTooShort(TestRunner &runner)
    {
        psm::memory::vector<psm::stealth::trusttunnel::user> users;
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic", users);
        runner.Check(!result, "auth: too short");
    }

    void TestVerifyBasicAuthEmptyValue(TestRunner &runner)
    {
        psm::memory::vector<psm::stealth::trusttunnel::user> users;
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic ", users);
        runner.Check(!result, "auth: empty after Basic ");
    }

    void TestResolveStreamCheck(TestRunner &runner)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = "_check";
        auto info = psm::stealth::trusttunnel::resolve_stream_target(1, headers);
        runner.Check(info.type == psm::multiplex::h2mux::stream_type::check, "resolve: check type");
        runner.Check(info.valid, "resolve: check valid");
    }

    void TestResolveStreamUdp(TestRunner &runner)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = "_udp2";
        headers.authority = "example.com:443";
        auto info = psm::stealth::trusttunnel::resolve_stream_target(1, headers);
        runner.Check(info.type == psm::multiplex::h2mux::stream_type::udp, "resolve: udp type");
        runner.Check(info.port == 443, "resolve: udp port=443");
        runner.Check(info.valid, "resolve: udp valid");
    }

    void TestResolveStreamIcmp(TestRunner &runner)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = "_icmp";
        headers.authority = "10.0.0.1:0";
        auto info = psm::stealth::trusttunnel::resolve_stream_target(1, headers);
        runner.Check(info.type == psm::multiplex::h2mux::stream_type::icmp, "resolve: icmp type");
    }

    void TestResolveStreamTcp(TestRunner &runner)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = "normal";
        headers.authority = "example.com:8080";
        auto info = psm::stealth::trusttunnel::resolve_stream_target(1, headers);
        runner.Check(info.type == psm::multiplex::h2mux::stream_type::tcp, "resolve: tcp type");
        runner.Check(info.port == 8080, "resolve: tcp port=8080");
        runner.Check(info.valid, "resolve: tcp valid");
    }

    void TestResolveStreamNoPort(TestRunner &runner)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = "normal";
        headers.authority = "example.com";
        auto info = psm::stealth::trusttunnel::resolve_stream_target(1, headers);
        runner.Check(info.type == psm::multiplex::h2mux::stream_type::tcp, "resolve: no port -> tcp");
        runner.Check(!info.valid, "resolve: no port -> not valid");
    }

    void TestResolveStreamBadPort(TestRunner &runner)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = "normal";
        headers.authority = "example.com:abc";
        auto info = psm::stealth::trusttunnel::resolve_stream_target(1, headers);
        runner.Check(!info.valid, "resolve: bad port -> not valid");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("TrustTunnelAuthPure");

    TestVerifyBasicAuthNoPrefix(runner);
    TestVerifyBasicAuthEmptyUsers(runner);
    TestVerifyBasicAuthValidCredentials(runner);
    TestVerifyBasicAuthWrongPassword(runner);
    TestVerifyBasicAuthTooShort(runner);
    TestVerifyBasicAuthEmptyValue(runner);
    TestResolveStreamCheck(runner);
    TestResolveStreamUdp(runner);
    TestResolveStreamIcmp(runner);
    TestResolveStreamTcp(runner);
    TestResolveStreamNoPort(runner);
    TestResolveStreamBadPort(runner);

    return runner.Summary();
}
