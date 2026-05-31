/**
 * @file TrustTunnel.cpp
 * @brief TrustTunnel 方案单元测试
 * @details 通过 #include 源文件直接测试 anonymous namespace 中的
 *          verify_basic_auth 和 resolve_stream_target 纯函数，
 *          以及公开接口 name/active/guess/snis。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/config.hpp>

// 直接 include 源文件以访问 anonymous namespace 函数
#include <prism/multiplex/h2mux/craft.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// 拉入源文件中 anonymous namespace 的函数定义
// 注意：必须在所有头文件之后 include
// anonymous namespace 函数在 psm::stealth::trusttunnel 命名空间中可见
#include "../src/prism/stealth/stack/trusttunnel/scheme.cpp"

using namespace psm::stealth::trusttunnel;

using psm::testing::TestRunner;

namespace
{
    void TestVerifyBasicAuthValid(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        psm::memory::vector<psm::stealth::trusttunnel::user> users(mr);
        users.push_back({.username = psm::memory::string("admin", mr),
                         .password = psm::memory::string("secret123", mr)});

        // "admin:secret123" base64 = "YWRtaW46c2VjcmV0MTIz"
        runner.Check(verify_basic_auth("Basic YWRtaW46c2VjcmV0MTIz", users),
                     "verify_basic_auth: valid credentials");
    }

    void TestVerifyBasicAuthWrongPassword(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        psm::memory::vector<psm::stealth::trusttunnel::user> users(mr);
        users.push_back({.username = psm::memory::string("admin", mr),
                         .password = psm::memory::string("secret123", mr)});

        // "admin:wrongpass" base64 = "YWRtaW46d3JvmdwYXNz"
        runner.Check(!verify_basic_auth("Basic YWRtaW46d3JvbmdwYXNz", users),
                     "verify_basic_auth: wrong password → false");
    }

    void TestVerifyBasicAuthNoPrefix(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        psm::memory::vector<psm::stealth::trusttunnel::user> users(mr);
        users.push_back({.username = psm::memory::string("admin", mr),
                         .password = psm::memory::string("secret", mr)});

        runner.Check(!verify_basic_auth("YWRtaW46c2VjcmV0", users),
                     "verify_basic_auth: no prefix → false");
    }

    void TestVerifyBasicAuthEmptyHeader(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        psm::memory::vector<psm::stealth::trusttunnel::user> users(mr);
        users.push_back({.username = psm::memory::string("admin", mr),
                         .password = psm::memory::string("secret", mr)});

        runner.Check(!verify_basic_auth("", users),
                     "verify_basic_auth: empty → false");
        runner.Check(!verify_basic_auth("Basic ", users),
                     "verify_basic_auth: 'Basic ' only → false");
    }

    void TestVerifyBasicAuthOverflowProtection(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        psm::memory::vector<psm::stealth::trusttunnel::user> users(mr);
        // 超长用户名+密码 > 192 字节
        psm::memory::string long_name(200, 'A', mr);
        psm::memory::string long_pass(200, 'B', mr);
        users.push_back({.username = std::move(long_name),
                         .password = std::move(long_pass)});

        // 即使 base64 匹配，超过 max_cred_len 也会被跳过
        runner.Check(!verify_basic_auth("Basic AAAA", users),
                     "verify_basic_auth: overflow protection → false");
    }

    void TestResolveStreamTargetCheck(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = psm::memory::string("server_check.example.com", mr);
        headers.authority = psm::memory::string("server_check.example.com:443", mr);

        auto info = resolve_stream_target(1, headers);
        runner.Check(info.type == psm::multiplex::h2mux::stream_type::check,
                     "resolve: _check → type=check");
        runner.Check(info.valid == true, "resolve: _check → valid=true");
    }

    void TestResolveStreamTargetUdp(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = psm::memory::string("server_udp2.example.com", mr);
        headers.authority = psm::memory::string("server_udp2.example.com:8443", mr);

        auto info = resolve_stream_target(3, headers);
        runner.Check(info.type == psm::multiplex::h2mux::stream_type::udp,
                     "resolve: _udp2 → type=udp");
        runner.Check(info.port == 8443, "resolve: _udp2 → port=8443");
        runner.Check(info.valid == true, "resolve: _udp2 → valid=true");
    }

    void TestResolveStreamTargetIcmp(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = psm::memory::string("server_icmp.example.com", mr);
        headers.authority = psm::memory::string("server_icmp.example.com:0", mr);

        auto info = resolve_stream_target(5, headers);
        runner.Check(info.type == psm::multiplex::h2mux::stream_type::icmp,
                     "resolve: _icmp → type=icmp");
    }

    void TestResolveStreamTargetTcp(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = psm::memory::string("server.example.com", mr);
        headers.authority = psm::memory::string("server.example.com:443", mr);

        auto info = resolve_stream_target(7, headers);
        runner.Check(info.type == psm::multiplex::h2mux::stream_type::tcp,
                     "resolve: default → type=tcp");
        runner.Check(info.host == "server.example.com", "resolve: host match");
        runner.Check(info.port == 443, "resolve: port=443");
        runner.Check(info.valid == true, "resolve: valid=true");
    }

    void TestResolveStreamTargetNoPort(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = psm::memory::string("server.example.com", mr);
        headers.authority = psm::memory::string("server.example.com", mr); // 无冒号

        auto info = resolve_stream_target(9, headers);
        runner.Check(info.valid == false, "resolve: no port → valid=false");
    }

    void TestResolveStreamTargetBadPort(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = psm::memory::string("server.example.com", mr);
        headers.authority = psm::memory::string("server.example.com:abc", mr);

        auto info = resolve_stream_target(11, headers);
        runner.Check(info.valid == false, "resolve: bad port → valid=false");
    }

    void TestSchemeMetadata(TestRunner &runner)
    {
        psm::stealth::trusttunnel::scheme s;
        runner.Check(s.name() == std::string_view{"trusttunnel"},
                     "scheme: name=trusttunnel");
        runner.Check(s.tier() == 2, "scheme: tier=2");
        runner.Check(s.unique() == false, "scheme: unique=false");
        runner.Check(s.category() == psm::stealth::scheme_category::stack,
                     "scheme: category=stack");

        psm::config cfg;
        auto guess = s.guess(cfg);
        runner.Check(guess.score == 100, "scheme: guess score=100");
        runner.Check(guess.solo_flag == 0, "scheme: guess solo_flag=0");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("TrustTunnel");

    TestVerifyBasicAuthValid(runner);
    TestVerifyBasicAuthWrongPassword(runner);
    TestVerifyBasicAuthNoPrefix(runner);
    TestVerifyBasicAuthEmptyHeader(runner);
    TestVerifyBasicAuthOverflowProtection(runner);
    TestResolveStreamTargetCheck(runner);
    TestResolveStreamTargetUdp(runner);
    TestResolveStreamTargetIcmp(runner);
    TestResolveStreamTargetTcp(runner);
    TestResolveStreamTargetNoPort(runner);
    TestResolveStreamTargetBadPort(runner);
    TestSchemeMetadata(runner);

    return runner.Summary();
}
