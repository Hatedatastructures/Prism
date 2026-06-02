/**
 * @file TrustTunnelAuthPure.cpp
 * @brief TrustTunnel 认证纯函数测试
 * @details 测试 verify_basic_auth / resolve_stream_target
 */

#include <gtest/gtest.h>

#include <prism/memory.hpp>

#include "../../src/prism/stealth/stack/trusttunnel/scheme.cpp"

namespace
{
    TEST(TrustTunnelAuthPure, VerifyBasicAuthNoPrefix)
    {
        psm::memory::vector<psm::stealth::trusttunnel::user> users;
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Token abc", users);
        EXPECT_TRUE(!result) << "auth: no Basic prefix";
    }

    TEST(TrustTunnelAuthPure, VerifyBasicAuthEmptyUsers)
    {
        psm::memory::vector<psm::stealth::trusttunnel::user> users;
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic dGVzdDpwYXNz", users);
        EXPECT_TRUE(!result) << "auth: empty users list";
    }

    TEST(TrustTunnelAuthPure, VerifyBasicAuthValidCredentials)
    {
        psm::memory::vector<psm::stealth::trusttunnel::user> users;
        users.push_back({psm::memory::string("test"), psm::memory::string("pass")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic dGVzdDpwYXNz", users);
        EXPECT_TRUE(result) << "auth: valid credentials";
    }

    TEST(TrustTunnelAuthPure, VerifyBasicAuthWrongPassword)
    {
        psm::memory::vector<psm::stealth::trusttunnel::user> users;
        users.push_back({psm::memory::string("admin"), psm::memory::string("secret")});
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic YWRtaW46d3Jvbg==", users);
        EXPECT_TRUE(!result) << "auth: wrong password";
    }

    TEST(TrustTunnelAuthPure, VerifyBasicAuthTooShort)
    {
        psm::memory::vector<psm::stealth::trusttunnel::user> users;
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic", users);
        EXPECT_TRUE(!result) << "auth: too short";
    }

    TEST(TrustTunnelAuthPure, VerifyBasicAuthEmptyValue)
    {
        psm::memory::vector<psm::stealth::trusttunnel::user> users;
        auto result = psm::stealth::trusttunnel::verify_basic_auth("Basic ", users);
        EXPECT_TRUE(!result) << "auth: empty after Basic ";
    }

    TEST(TrustTunnelAuthPure, ResolveStreamCheck)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = "_check";
        auto info = psm::stealth::trusttunnel::resolve_stream_target(1, headers);
        EXPECT_TRUE(info.type == psm::multiplex::h2mux::stream_type::check) << "resolve: check type";
        EXPECT_TRUE(info.valid) << "resolve: check valid";
    }

    TEST(TrustTunnelAuthPure, ResolveStreamUdp)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = "_udp2";
        headers.authority = "example.com:443";
        auto info = psm::stealth::trusttunnel::resolve_stream_target(1, headers);
        EXPECT_TRUE(info.type == psm::multiplex::h2mux::stream_type::udp) << "resolve: udp type";
        EXPECT_TRUE(info.port == 443) << "resolve: udp port=443";
        EXPECT_TRUE(info.valid) << "resolve: udp valid";
    }

    TEST(TrustTunnelAuthPure, ResolveStreamIcmp)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = "_icmp";
        headers.authority = "10.0.0.1:0";
        auto info = psm::stealth::trusttunnel::resolve_stream_target(1, headers);
        EXPECT_TRUE(info.type == psm::multiplex::h2mux::stream_type::icmp) << "resolve: icmp type";
    }

    TEST(TrustTunnelAuthPure, ResolveStreamTcp)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = "normal";
        headers.authority = "example.com:8080";
        auto info = psm::stealth::trusttunnel::resolve_stream_target(1, headers);
        EXPECT_TRUE(info.type == psm::multiplex::h2mux::stream_type::tcp) << "resolve: tcp type";
        EXPECT_TRUE(info.port == 8080) << "resolve: tcp port=8080";
        EXPECT_TRUE(info.valid) << "resolve: tcp valid";
    }

    TEST(TrustTunnelAuthPure, ResolveStreamNoPort)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = "normal";
        headers.authority = "example.com";
        auto info = psm::stealth::trusttunnel::resolve_stream_target(1, headers);
        EXPECT_TRUE(info.type == psm::multiplex::h2mux::stream_type::tcp) << "resolve: no port -> tcp";
        EXPECT_TRUE(!info.valid) << "resolve: no port -> not valid";
    }

    TEST(TrustTunnelAuthPure, ResolveStreamBadPort)
    {
        psm::multiplex::h2mux::h2_headers headers;
        headers.host = "normal";
        headers.authority = "example.com:abc";
        auto info = psm::stealth::trusttunnel::resolve_stream_target(1, headers);
        EXPECT_TRUE(!info.valid) << "resolve: bad port -> not valid";
    }

} // namespace
