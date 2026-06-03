/**
 * @file TrustTunnelBench.cpp
 * @brief TrustTunnel 核心热路径基准测试
 * @details 测量 Basic Auth 验证、流目标解析、凭据编码性能。
 */

#include <benchmark/benchmark.h>
#include <prism/memory.hpp>
#include <prism/stealth/stack/trusttunnel/config.hpp>
#include <prism/multiplex/h2mux/craft.hpp>

#include <openssl/evp.h>
#include <string_view>

namespace
{
    namespace mem = psm::memory;

    // ─── verify_basic_auth 热路径 ───────────────
    // 从 trusttunnel/scheme.cpp 提取的认证验证逻辑

    auto encode_base64(std::string_view input) -> std::string
    {
        constexpr std::size_t max_len = 192;
        if (input.size() > max_len) return {};

        std::array<std::uint8_t, 256> buf{};
        auto len = EVP_EncodeBlock(buf.data(),
            reinterpret_cast<const std::uint8_t *>(input.data()),
            static_cast<int>(input.size()));
        return {reinterpret_cast<const char *>(buf.data()),
                static_cast<std::size_t>(len)};
    }

    auto verify_basic_auth(std::string_view auth_header,
                            const mem::vector<psm::stealth::trusttunnel::user> &users)
        -> bool
    {
        constexpr std::string_view prefix = "Basic ";
        if (auth_header.size() <= prefix.size() ||
            auth_header.substr(0, prefix.size()) != prefix)
        {
            return false;
        }

        auto b64_credentials = auth_header.substr(prefix.size());

        for (const auto &user : users)
        {
            mem::string expected_creds = user.username + ":" + user.password;
            auto creds_view = std::string_view(expected_creds.data(), expected_creds.size());

            constexpr std::size_t max_cred_len = 192;
            if (creds_view.size() > max_cred_len) continue;

            std::array<std::uint8_t, 256> encode_buf{};
            auto encoded_len = EVP_EncodeBlock(
                encode_buf.data(),
                reinterpret_cast<const std::uint8_t *>(creds_view.data()),
                static_cast<int>(creds_view.size()));

            auto encoded_str = std::string_view(
                reinterpret_cast<const char *>(encode_buf.data()),
                static_cast<std::size_t>(encoded_len));

            if (encoded_str == b64_credentials) return true;
        }
        return false;
    }

    // ─── resolve_stream_target 热路径 ───────────
    // 从 trusttunnel/scheme.cpp 提取的流目标解析逻辑

    using h2_headers = psm::multiplex::h2mux::h2_headers;
    using stream_info = psm::multiplex::h2mux::stream_info;
    using stream_type = psm::multiplex::h2mux::stream_type;

    auto resolve_stream_target(std::int32_t stream_id,
                                const h2_headers &headers) -> stream_info
    {
        stream_info info;
        auto authority = std::string_view(headers.authority.data(), headers.authority.size());
        auto host = std::string_view(headers.host.data(), headers.host.size());

        if (host.find("_check") != std::string_view::npos)
        {
            info.type = stream_type::check;
            info.valid = true;
            return info;
        }
        if (host.find("_udp2") != std::string_view::npos)
        {
            info.type = stream_type::udp;
        }
        else if (host.find("_icmp") != std::string_view::npos)
        {
            info.type = stream_type::icmp;
        }
        else
        {
            info.type = stream_type::tcp;
        }

        auto colon = authority.rfind(':');
        if (colon == std::string_view::npos) return info;

        info.host.assign(authority.substr(0, colon));
        auto port_view = authority.substr(colon + 1);
        auto port_val = std::uint16_t{0};
        auto [_, ec] = std::from_chars(
            port_view.data(), port_view.data() + port_view.size(), port_val);
        if (ec != std::errc()) return info;

        info.port = port_val;
        info.valid = true;
        return info;
    }

    // ─── 辅助：构造测试数据 ─────────────────────

    auto make_users(std::size_t n) -> mem::vector<psm::stealth::trusttunnel::user>
    {
        mem::vector<psm::stealth::trusttunnel::user> users;
        for (std::size_t i = 0; i < n; ++i)
        {
            psm::stealth::trusttunnel::user u;
            u.username = "user" + std::to_string(i);
            u.password = "pass" + std::to_string(i);
            users.push_back(std::move(u));
        }
        return users;
    }

    static const auto users_1 = make_users(1);
    static const auto users_10 = make_users(10);
    static const auto users_100 = make_users(100);

    // ─── Basic Auth 验证基准 ────────────────────

    static void BM_TrustTunnelVerifyAuth1User(benchmark::State &state)
    {
        auto creds = encode_base64("user0:pass0");
        auto auth = std::string("Basic ") + creds;
        for (auto _ : state)
        {
            auto ok = verify_basic_auth(auth, users_1);
            benchmark::DoNotOptimize(ok);
        }
    }
    BENCHMARK(BM_TrustTunnelVerifyAuth1User);

    static void BM_TrustTunnelVerifyAuth10Users(benchmark::State &state)
    {
        auto creds = encode_base64("user9:pass9");
        auto auth = std::string("Basic ") + creds;
        for (auto _ : state)
        {
            auto ok = verify_basic_auth(auth, users_10);
            benchmark::DoNotOptimize(ok);
        }
    }
    BENCHMARK(BM_TrustTunnelVerifyAuth10Users);

    static void BM_TrustTunnelVerifyAuth100Users(benchmark::State &state)
    {
        auto creds = encode_base64("user99:pass99");
        auto auth = std::string("Basic ") + creds;
        for (auto _ : state)
        {
            auto ok = verify_basic_auth(auth, users_100);
            benchmark::DoNotOptimize(ok);
        }
    }
    BENCHMARK(BM_TrustTunnelVerifyAuth100Users);

    static void BM_TrustTunnelVerifyAuthFail(benchmark::State &state)
    {
        auto auth = std::string("Basic aW52YWxpZDpjcmVk");
        for (auto _ : state)
        {
            auto ok = verify_basic_auth(auth, users_10);
            benchmark::DoNotOptimize(ok);
        }
    }
    BENCHMARK(BM_TrustTunnelVerifyAuthFail);

    // ─── 流目标解析基准 ─────────────────────────

    static void BM_TrustTunnelResolveTcp(benchmark::State &state)
    {
        h2_headers hdrs;
        hdrs.authority = "example.com:443";
        hdrs.host = "example.com";
        for (auto _ : state)
        {
            auto info = resolve_stream_target(1, hdrs);
            benchmark::DoNotOptimize(info);
        }
    }
    BENCHMARK(BM_TrustTunnelResolveTcp);

    static void BM_TrustTunnelResolveCheck(benchmark::State &state)
    {
        h2_headers hdrs;
        hdrs.authority = "health.local:443";
        hdrs.host = "health_check";
        for (auto _ : state)
        {
            auto info = resolve_stream_target(1, hdrs);
            benchmark::DoNotOptimize(info);
        }
    }
    BENCHMARK(BM_TrustTunnelResolveCheck);

    static void BM_TrustTunnelResolveUdp(benchmark::State &state)
    {
        h2_headers hdrs;
        hdrs.authority = "relay.local:8443";
        hdrs.host = "relay_udp2";
        for (auto _ : state)
        {
            auto info = resolve_stream_target(1, hdrs);
            benchmark::DoNotOptimize(info);
        }
    }
    BENCHMARK(BM_TrustTunnelResolveUdp);

    static void BM_TrustTunnelResolveIcmp(benchmark::State &state)
    {
        h2_headers hdrs;
        hdrs.authority = "ping.local:0";
        hdrs.host = "ping_icmp";
        for (auto _ : state)
        {
            auto info = resolve_stream_target(1, hdrs);
            benchmark::DoNotOptimize(info);
        }
    }
    BENCHMARK(BM_TrustTunnelResolveIcmp);

    // ─── Base64 编码基准 ────────────────────────

    static void BM_TrustTunnelBase64Encode(benchmark::State &state)
    {
        std::string creds = "admin:very_long_password_with_special_chars_!@#$%";
        for (auto _ : state)
        {
            auto encoded = encode_base64(creds);
            benchmark::DoNotOptimize(encoded);
        }
    }
    BENCHMARK(BM_TrustTunnelBase64Encode);

} // namespace

BENCHMARK_MAIN();
