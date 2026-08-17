/**
 * @file RestlsCodecDeep.cpp
 * @brief restls codec 字节级深测（纯函数）
 * @details 覆盖：密钥派生、服务端掩码、认证 MAC、掩码计算
 *          的确定性/差异性与边界。
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>

#include <common/protocols/restls/codec.hpp>

namespace
{
    using namespace preview;

    TEST(RestlsCodecDeep, DeriveSecret)
    {
        const auto s1 = restls::derive_secret("pw");
        EXPECT_EQ(s1.size(), 32u);
        EXPECT_EQ(restls::derive_secret("pw"), s1); // 确定性
        EXPECT_NE(restls::derive_secret("pw2"), s1); // 密码敏感
        EXPECT_EQ(restls::derive_secret("").size(), 32u); // 空密码不崩溃
    }

    TEST(RestlsCodecDeep, ComputeServerMask)
    {
        const auto secret = restls::derive_secret("pw");
        const std::array<std::uint8_t, 32> sr{0x01};
        const auto m1 = restls::compute_server_mask(secret, sr);
        EXPECT_EQ(m1.size(), restls::hs_maclen);
        // 确定性
        EXPECT_EQ(restls::compute_server_mask(secret, sr), m1);
        // server random 变化 → 掩码变化
        const std::array<std::uint8_t, 32> sr2{0x02};
        EXPECT_NE(restls::compute_server_mask(secret, sr2), m1);
    }

    TEST(RestlsCodecDeep, ComputeAuthMac)
    {
        const auto secret = restls::derive_secret("pw");
        const std::array<std::uint8_t, 32> sr{0x10};
        const std::array<std::uint8_t, 5> tls_hdr{0x17, 0x03, 0x03, 0x00, 0x10};
        const std::array<std::uint8_t, 8> payload{0x20};

        restls::auth_mac_input in{secret, sr, restls::flow_direction::to_client, 1, {}, tls_hdr,
                                  payload};
        const auto mac = restls::compute_auth_mac(in);
        EXPECT_EQ(mac.size(), restls::appdata_maclen);
        // 确定性
        EXPECT_EQ(restls::compute_auth_mac(in), mac);
        // counter 变化 → 不同
        restls::auth_mac_input in2{secret, sr, restls::flow_direction::to_client, 2, {}, tls_hdr,
                                   payload};
        EXPECT_NE(restls::compute_auth_mac(in2), mac);
        // 方向变化 → 不同
        restls::auth_mac_input in3{secret, sr, restls::flow_direction::to_server, 1, {}, tls_hdr,
                                   payload};
        EXPECT_NE(restls::compute_auth_mac(in3), mac);
    }

    TEST(RestlsCodecDeep, ComputeMask)
    {
        const auto secret = restls::derive_secret("pw");
        const std::array<std::uint8_t, 32> sr{0x30};
        const std::array<std::uint8_t, 32> sample{0x40};

        restls::mask_input in{secret, sr, restls::flow_direction::to_client, 5, sample};
        const auto mask = restls::compute_mask(in);
        EXPECT_EQ(mask.size(), restls::mask_len);
        // 确定性
        EXPECT_EQ(restls::compute_mask(in), mask);
        // counter 变化 → 不同
        restls::mask_input in2{secret, sr, restls::flow_direction::to_client, 6, sample};
        EXPECT_NE(restls::compute_mask(in2), mask);
    }

} // namespace
