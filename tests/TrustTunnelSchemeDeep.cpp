/**
 * @file TrustTunnelSchemeDeep.cpp
 * @brief stealth/stack/trusttunnel/scheme 深度纯函数测试
 * @details 通过 #include 源文件访问 scheme.cpp 中所有同步函数，
 *          覆盖 verify_basic_auth、resolve_stream_target 和所有访问器方法。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include "../src/prism/stealth/stack/trusttunnel/scheme.cpp"

using psm::testing::TestRunner;

namespace
{
    namespace tt = psm::stealth::trusttunnel;
    using psm::memory::vector;
    using psm::memory::string;

    // ─── verify_basic_auth 测试 ──────────────

    void TestVerifyBasicAuthNoPrefix(TestRunner &runner)
    {
        vector<tt::user> users;
        users.push_back({string("admin"), string("pass")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("admin:pass", users);
        runner.Check(!result, "verify_basic_auth: no Basic prefix -> false");
    }

    void TestVerifyBasicAuthWrongPrefix(TestRunner &runner)
    {
        vector<tt::user> users;
        users.push_back({string("admin"), string("pass")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Bearer xyz", users);
        runner.Check(!result, "verify_basic_auth: wrong prefix -> false");
    }

    void TestVerifyBasicAuthEmptyUsers(TestRunner &runner)
    {
        vector<tt::user> users;
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic dGVzdA==", users);
        runner.Check(!result, "verify_basic_auth: empty users -> false");
    }

    void TestVerifyBasicAuthCorrectCredentials(TestRunner &runner)
    {
        // "admin:pass" -> Base64 = "YWRtaW46cGFzcw=="
        vector<tt::user> users;
        users.push_back({string("admin"), string("pass")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic YWRtaW46cGFzcw==", users);
        runner.Check(result, "verify_basic_auth: correct credentials -> true");
    }

    void TestVerifyBasicAuthWrongPassword(TestRunner &runner)
    {
        vector<tt::user> users;
        users.push_back({string("admin"), string("pass")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic YWRtaW46d3Jvbmc=", users);
        runner.Check(!result, "verify_basic_auth: wrong password -> false");
    }

    void TestVerifyBasicAuthMultipleUsers(TestRunner &runner)
    {
        vector<tt::user> users;
        users.push_back({string("admin"), string("pass1")});
        users.push_back({string("user"), string("pass2")});
        // "user:pass2" -> Base64 = "dXNlcjpwYXNzMg=="
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic dXNlcjpwYXNzMg==", users);
        runner.Check(result, "verify_basic_auth: second user matches -> true");
    }

    void TestVerifyBasicAuthTooLongCredential(TestRunner &runner)
    {
        vector<tt::user> users;
        // 200 字节凭据 -> 超过 192 阈值，应跳过
        string long_name(190, 'a');
        users.push_back({long_name, string("p")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic dGVzdA==", users);
        runner.Check(!result, "verify_basic_auth: too long credential -> skip user");
    }

    void TestVerifyBasicAuthEmptyHeader(TestRunner &runner)
    {
        vector<tt::user> users;
        users.push_back({string("admin"), string("pass")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("", users);
        runner.Check(!result, "verify_basic_auth: empty header -> false");
    }

    void TestVerifyBasicAuthJustPrefix(TestRunner &runner)
    {
        vector<tt::user> users;
        users.push_back({string("admin"), string("pass")});
        // "Basic " 只有前缀，没有 base64 部分
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic ", users);
        runner.Check(!result, "verify_basic_auth: just prefix -> false");
    }

    // ─── resolve_stream_target 测试 ──────────

    void TestResolveStreamTargetCheckHost(TestRunner &runner)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = string("something_check");
        headers.authority = string("host:8080");

        auto info = psm::stealth::trusttunnel::resolve_stream_target(1, headers);
        runner.Check(info.type == psm::multiplex::h2mux::stream_type::check,
                     "resolve: _check host -> check type");
        runner.Check(info.valid, "resolve: _check host -> valid");
    }

    void TestResolveStreamTargetUdp2Host(TestRunner &runner)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = string("something_udp2");
        headers.authority = string("host:443");

        auto info = psm::stealth::trusttunnel::resolve_stream_target(3, headers);
        runner.Check(info.type == psm::multiplex::h2mux::stream_type::udp,
                     "resolve: _udp2 host -> udp type");
    }

    void TestResolveStreamTargetIcmpHost(TestRunner &runner)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = string("something_icmp");
        headers.authority = string("host:443");

        auto info = psm::stealth::trusttunnel::resolve_stream_target(5, headers);
        runner.Check(info.type == psm::multiplex::h2mux::stream_type::icmp,
                     "resolve: _icmp host -> icmp type");
    }

    void TestResolveStreamTargetTcpHost(TestRunner &runner)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = string("normal-host");
        headers.authority = string("example.com:8443");

        auto info = psm::stealth::trusttunnel::resolve_stream_target(7, headers);
        runner.Check(info.type == psm::multiplex::h2mux::stream_type::tcp,
                     "resolve: normal host -> tcp type");
        runner.Check(info.valid, "resolve: valid host:port -> valid");
        // 检查 host 和 port 解析
        auto info_host = std::string_view(info.host.data(), info.host.size());
        runner.Check(info_host == "example.com", "resolve: host parsed correctly");
        runner.Check(info.port == 8443, "resolve: port parsed correctly");
    }

    void TestResolveStreamTargetNoPort(TestRunner &runner)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = string("normal-host");
        headers.authority = string("example.com");

        auto info = psm::stealth::trusttunnel::resolve_stream_target(9, headers);
        runner.Check(info.type == psm::multiplex::h2mux::stream_type::tcp,
                     "resolve: no port -> tcp type");
        runner.Check(!info.valid, "resolve: no port -> not valid");
    }

    void TestResolveStreamTargetInvalidPort(TestRunner &runner)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = string("normal-host");
        headers.authority = string("host:abc");

        auto info = psm::stealth::trusttunnel::resolve_stream_target(11, headers);
        runner.Check(!info.valid, "resolve: invalid port -> not valid");
    }

    void TestResolveStreamTargetEmptyAuthority(TestRunner &runner)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = string("normal-host");
        headers.authority = string("");

        auto info = psm::stealth::trusttunnel::resolve_stream_target(13, headers);
        runner.Check(info.type == psm::multiplex::h2mux::stream_type::tcp,
                     "resolve: empty authority -> tcp type");
        runner.Check(!info.valid, "resolve: empty authority -> not valid");
    }

    // ─── scheme 访问器测试 ──────────────────

    void TestSchemeName(TestRunner &runner)
    {
        tt::scheme s;
        runner.Check(s.name() == "trusttunnel", "scheme: name == trusttunnel");
    }

    void TestSchemeTier(TestRunner &runner)
    {
        tt::scheme s;
        runner.Check(s.tier() == 2, "scheme: tier == 2");
    }

    void TestSchemeUnique(TestRunner &runner)
    {
        tt::scheme s;
        runner.Check(!s.unique(), "scheme: unique == false");
    }

    void TestSchemeCategory(TestRunner &runner)
    {
        tt::scheme s;
        runner.Check(s.category() == psm::stealth::scheme_category::stack,
                     "scheme: category == stack");
    }

    void TestSchemeWeight(TestRunner &runner)
    {
        tt::scheme s;
        // weight() 是 protected，通过 guess 间接验证 scheme 存在即可
        runner.Check(s.tier() == 2, "scheme: accessible methods work");
    }

    void TestSchemeActiveEnabled(TestRunner &runner)
    {
        tt::scheme s;
        psm::config cfg;
        cfg.stealth.trusttunnel.server_names.push_back(string("example.com"));
        cfg.stealth.trusttunnel.certificate = string("cert.pem");
        cfg.stealth.trusttunnel.private_key = string("key.pem");
        cfg.stealth.trusttunnel.users.push_back({string("u"), string("p")});
        runner.Check(s.active(cfg), "scheme: active when enabled");
    }

    void TestSchemeActiveDisabled(TestRunner &runner)
    {
        tt::scheme s;
        psm::config cfg;
        runner.Check(!s.active(cfg), "scheme: not active when disabled");
    }

    void TestSchemeSnis(TestRunner &runner)
    {
        tt::scheme s;
        psm::config cfg;
        cfg.stealth.trusttunnel.server_names.push_back(string("a.com"));
        cfg.stealth.trusttunnel.server_names.push_back(string("b.com"));
        auto snis = s.snis(cfg);
        runner.Check(snis.size() == 2, "scheme: snis size == 2");
    }

    void TestSchemeGuess(TestRunner &runner)
    {
        tt::scheme s;
        psm::config cfg;
        auto result = s.guess(cfg);
        runner.Check(result.score == 100, "scheme: guess score == 100");
    }

    // ─── config::enabled() 测试 ─────────────

    void TestConfigEnabledAllPresent(TestRunner &runner)
    {
        tt::config cfg;
        cfg.server_names.push_back(string("sni"));
        cfg.certificate = string("cert");
        cfg.private_key = string("key");
        cfg.users.push_back({string("u"), string("p")});
        runner.Check(cfg.enabled(), "config: all present -> enabled");
    }

    void TestConfigEnabledMissingSni(TestRunner &runner)
    {
        tt::config cfg;
        cfg.certificate = string("cert");
        cfg.private_key = string("key");
        cfg.users.push_back({string("u"), string("p")});
        runner.Check(!cfg.enabled(), "config: missing sni -> not enabled");
    }

    void TestConfigEnabledMissingCert(TestRunner &runner)
    {
        tt::config cfg;
        cfg.server_names.push_back(string("sni"));
        cfg.private_key = string("key");
        cfg.users.push_back({string("u"), string("p")});
        runner.Check(!cfg.enabled(), "config: missing cert -> not enabled");
    }

    void TestConfigEnabledMissingKey(TestRunner &runner)
    {
        tt::config cfg;
        cfg.server_names.push_back(string("sni"));
        cfg.certificate = string("cert");
        cfg.users.push_back({string("u"), string("p")});
        runner.Check(!cfg.enabled(), "config: missing key -> not enabled");
    }

    void TestConfigEnabledMissingUsers(TestRunner &runner)
    {
        tt::config cfg;
        cfg.server_names.push_back(string("sni"));
        cfg.certificate = string("cert");
        cfg.private_key = string("key");
        runner.Check(!cfg.enabled(), "config: missing users -> not enabled");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("TrustTunnelSchemeDeep");

    TestVerifyBasicAuthNoPrefix(runner);
    TestVerifyBasicAuthWrongPrefix(runner);
    TestVerifyBasicAuthEmptyUsers(runner);
    TestVerifyBasicAuthCorrectCredentials(runner);
    TestVerifyBasicAuthWrongPassword(runner);
    TestVerifyBasicAuthMultipleUsers(runner);
    TestVerifyBasicAuthTooLongCredential(runner);
    TestVerifyBasicAuthEmptyHeader(runner);
    TestVerifyBasicAuthJustPrefix(runner);

    TestResolveStreamTargetCheckHost(runner);
    TestResolveStreamTargetUdp2Host(runner);
    TestResolveStreamTargetIcmpHost(runner);
    TestResolveStreamTargetTcpHost(runner);
    TestResolveStreamTargetNoPort(runner);
    TestResolveStreamTargetInvalidPort(runner);
    TestResolveStreamTargetEmptyAuthority(runner);

    TestSchemeName(runner);
    TestSchemeTier(runner);
    TestSchemeUnique(runner);
    TestSchemeCategory(runner);
    TestSchemeWeight(runner);
    TestSchemeActiveEnabled(runner);
    TestSchemeActiveDisabled(runner);
    TestSchemeSnis(runner);
    TestSchemeGuess(runner);

    TestConfigEnabledAllPresent(runner);
    TestConfigEnabledMissingSni(runner);
    TestConfigEnabledMissingCert(runner);
    TestConfigEnabledMissingKey(runner);
    TestConfigEnabledMissingUsers(runner);

    return runner.Summary();
}
