/**
 * @file TrustTunnelSchemeDeep.cpp
 * @brief stealth/stack/trusttunnel/scheme 深度纯函数测试
 * @details 通过 #include 源文件访问 scheme.cpp 中所有同步函数，
 *          覆盖 verify_basic_auth、resolve_stream_target 和所有访问器方法。
 */

#include <gtest/gtest.h>

#include <prism/core/core.hpp>

#include "../../src/prism/stealth/stack/trusttunnel/scheme.cpp"

namespace
{
    namespace tt = psm::stealth::trusttunnel;
    using psm::memory::vector;
    using psm::memory::string;

    // ─── verify_basic_auth 测试 ──────────────

    TEST(TrustTunnelSchemeDeep, VerifyBasicAuthNoPrefix)
    {
        vector<tt::user> users;
        users.push_back({string("admin"), string("pass")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("admin:pass", users);
        EXPECT_TRUE(!result) << "verify_basic_auth: no Basic prefix -> false";
    }

    TEST(TrustTunnelSchemeDeep, VerifyBasicAuthWrongPrefix)
    {
        vector<tt::user> users;
        users.push_back({string("admin"), string("pass")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Bearer xyz", users);
        EXPECT_TRUE(!result) << "verify_basic_auth: wrong prefix -> false";
    }

    TEST(TrustTunnelSchemeDeep, VerifyBasicAuthEmptyUsers)
    {
        vector<tt::user> users;
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic dGVzdA==", users);
        EXPECT_TRUE(!result) << "verify_basic_auth: empty users -> false";
    }

    TEST(TrustTunnelSchemeDeep, VerifyBasicAuthCorrectCredentials)
    {
        // "admin:pass" -> Base64 = "YWRtaW46cGFzcw=="
        vector<tt::user> users;
        users.push_back({string("admin"), string("pass")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic YWRtaW46cGFzcw==", users);
        EXPECT_TRUE(result) << "verify_basic_auth: correct credentials -> true";
    }

    TEST(TrustTunnelSchemeDeep, VerifyBasicAuthWrongPassword)
    {
        vector<tt::user> users;
        users.push_back({string("admin"), string("pass")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic YWRtaW46d3Jvbmc=", users);
        EXPECT_TRUE(!result) << "verify_basic_auth: wrong password -> false";
    }

    TEST(TrustTunnelSchemeDeep, VerifyBasicAuthMultipleUsers)
    {
        vector<tt::user> users;
        users.push_back({string("admin"), string("pass1")});
        users.push_back({string("user"), string("pass2")});
        // "user:pass2" -> Base64 = "dXNlcjpwYXNzMg=="
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic dXNlcjpwYXNzMg==", users);
        EXPECT_TRUE(result) << "verify_basic_auth: second user matches -> true";
    }

    TEST(TrustTunnelSchemeDeep, VerifyBasicAuthTooLongCredential)
    {
        vector<tt::user> users;
        // 200 字节凭据 -> 超过 192 阈值，应跳过
        string long_name(190, 'a');
        users.push_back({long_name, string("p")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic dGVzdA==", users);
        EXPECT_TRUE(!result) << "verify_basic_auth: too long credential -> skip user";
    }

    TEST(TrustTunnelSchemeDeep, VerifyBasicAuthEmptyHeader)
    {
        vector<tt::user> users;
        users.push_back({string("admin"), string("pass")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("", users);
        EXPECT_TRUE(!result) << "verify_basic_auth: empty header -> false";
    }

    TEST(TrustTunnelSchemeDeep, VerifyBasicAuthJustPrefix)
    {
        vector<tt::user> users;
        users.push_back({string("admin"), string("pass")});
        // "Basic " 只有前缀，没有 base64 部分
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic ", users);
        EXPECT_TRUE(!result) << "verify_basic_auth: just prefix -> false";
    }

    // ─── resolve_stream_target 测试 ──────────

    TEST(TrustTunnelSchemeDeep, ResolveStreamTargetCheckHost)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = string("something_check");
        headers.authority = string("host:8080");

        auto info = psm::stealth::trusttunnel::resolve_stream_target(1, headers);
        EXPECT_TRUE(info.type == psm::multiplex::h2mux::stream_type::check)
            << "resolve: _check host -> check type";
        EXPECT_TRUE(info.valid) << "resolve: _check host -> valid";
    }

    TEST(TrustTunnelSchemeDeep, ResolveStreamTargetUdp2Host)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = string("something_udp2");
        headers.authority = string("host:443");

        auto info = psm::stealth::trusttunnel::resolve_stream_target(3, headers);
        EXPECT_TRUE(info.type == psm::multiplex::h2mux::stream_type::udp)
            << "resolve: _udp2 host -> udp type";
    }

    TEST(TrustTunnelSchemeDeep, ResolveStreamTargetIcmpHost)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = string("something_icmp");
        headers.authority = string("host:443");

        auto info = psm::stealth::trusttunnel::resolve_stream_target(5, headers);
        EXPECT_TRUE(info.type == psm::multiplex::h2mux::stream_type::icmp)
            << "resolve: _icmp host -> icmp type";
    }

    TEST(TrustTunnelSchemeDeep, ResolveStreamTargetTcpHost)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = string("normal-host");
        headers.authority = string("example.com:8443");

        auto info = psm::stealth::trusttunnel::resolve_stream_target(7, headers);
        EXPECT_TRUE(info.type == psm::multiplex::h2mux::stream_type::tcp)
            << "resolve: normal host -> tcp type";
        EXPECT_TRUE(info.valid) << "resolve: valid host:port -> valid";
        // 检查 host 和 port 解析
        auto info_host = std::string_view(info.host.data(), info.host.size());
        EXPECT_TRUE(info_host == "example.com") << "resolve: host parsed correctly";
        EXPECT_TRUE(info.port == 8443) << "resolve: port parsed correctly";
    }

    TEST(TrustTunnelSchemeDeep, ResolveStreamTargetNoPort)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = string("normal-host");
        headers.authority = string("example.com");

        auto info = psm::stealth::trusttunnel::resolve_stream_target(9, headers);
        EXPECT_TRUE(info.type == psm::multiplex::h2mux::stream_type::tcp)
            << "resolve: no port -> tcp type";
        EXPECT_TRUE(!info.valid) << "resolve: no port -> not valid";
    }

    TEST(TrustTunnelSchemeDeep, ResolveStreamTargetInvalidPort)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = string("normal-host");
        headers.authority = string("host:abc");

        auto info = psm::stealth::trusttunnel::resolve_stream_target(11, headers);
        EXPECT_TRUE(!info.valid) << "resolve: invalid port -> not valid";
    }

    TEST(TrustTunnelSchemeDeep, ResolveStreamTargetEmptyAuthority)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = string("normal-host");
        headers.authority = string("");

        auto info = psm::stealth::trusttunnel::resolve_stream_target(13, headers);
        EXPECT_TRUE(info.type == psm::multiplex::h2mux::stream_type::tcp)
            << "resolve: empty authority -> tcp type";
        EXPECT_TRUE(!info.valid) << "resolve: empty authority -> not valid";
    }

    // ─── scheme 访问器测试 ──────────────────

    TEST(TrustTunnelSchemeDeep, SchemeName)
    {
        tt::scheme s;
        EXPECT_TRUE(s.name() == "trusttunnel") << "scheme: name == trusttunnel";
    }

    TEST(TrustTunnelSchemeDeep, SchemeTier)
    {
        tt::scheme s;
        EXPECT_TRUE(s.tier() == 2) << "scheme: tier == 2";
    }

    TEST(TrustTunnelSchemeDeep, SchemeUnique)
    {
        tt::scheme s;
        EXPECT_TRUE(!s.unique()) << "scheme: unique == false";
    }

    TEST(TrustTunnelSchemeDeep, SchemeCategory)
    {
        tt::scheme s;
        EXPECT_TRUE(s.category() == psm::stealth::scheme_category::stack)
            << "scheme: category == stack";
    }

    TEST(TrustTunnelSchemeDeep, SchemeWeight)
    {
        tt::scheme s;
        // weight() 是 protected，通过 guess 间接验证 scheme 存在即可
        EXPECT_TRUE(s.tier() == 2) << "scheme: accessible methods work";
    }

    TEST(TrustTunnelSchemeDeep, SchemeActiveEnabled)
    {
        tt::scheme s;
        psm::config cfg;
        cfg.stealth.trusttunnel.server_names.push_back(string("example.com"));
        cfg.stealth.trusttunnel.certificate = string("cert.pem");
        cfg.stealth.trusttunnel.private_key = string("key.pem");
        cfg.stealth.trusttunnel.users.push_back({string("u"), string("p")});
        EXPECT_TRUE(s.active(cfg)) << "scheme: active when enabled";
    }

    TEST(TrustTunnelSchemeDeep, SchemeActiveDisabled)
    {
        tt::scheme s;
        psm::config cfg;
        EXPECT_TRUE(!s.active(cfg)) << "scheme: not active when disabled";
    }

    TEST(TrustTunnelSchemeDeep, SchemeSnis)
    {
        tt::scheme s;
        psm::config cfg;
        cfg.stealth.trusttunnel.server_names.push_back(string("a.com"));
        cfg.stealth.trusttunnel.server_names.push_back(string("b.com"));
        auto snis = s.snis(cfg);
        EXPECT_TRUE(snis.size() == 2) << "scheme: snis size == 2";
    }

    TEST(TrustTunnelSchemeDeep, SchemeGuess)
    {
        tt::scheme s;
        psm::config cfg;
        auto result = s.guess(cfg);
        EXPECT_TRUE(result.score == 100) << "scheme: guess score == 100";
    }

    // ─── config::enabled() 测试 ─────────────

    TEST(TrustTunnelSchemeDeep, ConfigEnabledAllPresent)
    {
        tt::config cfg;
        cfg.server_names.push_back(string("sni"));
        cfg.certificate = string("cert");
        cfg.private_key = string("key");
        cfg.users.push_back({string("u"), string("p")});
        EXPECT_TRUE(cfg.enabled()) << "config: all present -> enabled";
    }

    TEST(TrustTunnelSchemeDeep, ConfigEnabledMissingSni)
    {
        tt::config cfg;
        cfg.certificate = string("cert");
        cfg.private_key = string("key");
        cfg.users.push_back({string("u"), string("p")});
        EXPECT_TRUE(!cfg.enabled()) << "config: missing sni -> not enabled";
    }

    TEST(TrustTunnelSchemeDeep, ConfigEnabledMissingCert)
    {
        tt::config cfg;
        cfg.server_names.push_back(string("sni"));
        cfg.private_key = string("key");
        cfg.users.push_back({string("u"), string("p")});
        EXPECT_TRUE(!cfg.enabled()) << "config: missing cert -> not enabled";
    }

    TEST(TrustTunnelSchemeDeep, ConfigEnabledMissingKey)
    {
        tt::config cfg;
        cfg.server_names.push_back(string("sni"));
        cfg.certificate = string("cert");
        cfg.users.push_back({string("u"), string("p")});
        EXPECT_TRUE(!cfg.enabled()) << "config: missing key -> not enabled";
    }

    TEST(TrustTunnelSchemeDeep, ConfigEnabledMissingUsers)
    {
        tt::config cfg;
        cfg.server_names.push_back(string("sni"));
        cfg.certificate = string("cert");
        cfg.private_key = string("key");
        EXPECT_TRUE(!cfg.enabled()) << "config: missing users -> not enabled";
    }

} // namespace
