/**
 * @file RestlsCodecDeep.cpp
 * @brief restls Codec 字节级深测（纯函数）
 * @details 覆盖：密钥派生、服务端掩码、认证 MAC、掩码计算
 *          的确定性/差异性与边界。
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>

#include <common/Protocols/Restls/Codec.hpp>

namespace
{
    using namespace Preview;

    TEST(RestlsCodecDeep, DeriveSecret)
    {
        const auto s1 = Restls::DeriveSecret("pw");
        EXPECT_EQ(s1.size(), 32u);
        EXPECT_EQ(Restls::DeriveSecret("pw"), s1); // 确定性
        EXPECT_NE(Restls::DeriveSecret("pw2"), s1); // 密码敏感
        EXPECT_EQ(Restls::DeriveSecret("").size(), 32u); // 空密码不崩溃
    }

    TEST(RestlsCodecDeep, ComputeServerMask)
    {
        const auto Secret = Restls::DeriveSecret("pw");
        const std::array<std::uint8_t, 32> sr{0x01};
        const auto m1 = Restls::ComputeServerMask(Secret, sr);
        EXPECT_EQ(m1.size(), Restls::HsMaclen);
        // 确定性
        EXPECT_EQ(Restls::ComputeServerMask(Secret, sr), m1);
        // Server random 变化 → 掩码变化
        const std::array<std::uint8_t, 32> sr2{0x02};
        EXPECT_NE(Restls::ComputeServerMask(Secret, sr2), m1);
    }

    TEST(RestlsCodecDeep, ComputeAuthMac)
    {
        const auto Secret = Restls::DeriveSecret("pw");
        const std::array<std::uint8_t, 32> sr{0x10};
        const std::array<std::uint8_t, 5> tls_hdr{0x17, 0x03, 0x03, 0x00, 0x10};
        const std::array<std::uint8_t, 8> payload{0x20};

        Restls::AuthMacInput in{Secret, sr, Restls::FlowDirection::to_client, 1, {}, tls_hdr,
                                  payload};
        const auto mac = Restls::ComputeAuthMac(in);
        EXPECT_EQ(mac.size(), Restls::AppdataMaclen);
        // 确定性
        EXPECT_EQ(Restls::ComputeAuthMac(in), mac);
        // counter 变化 → 不同
        Restls::AuthMacInput in2{Secret, sr, Restls::FlowDirection::to_client, 2, {}, tls_hdr,
                                   payload};
        EXPECT_NE(Restls::ComputeAuthMac(in2), mac);
        // 方向变化 → 不同
        Restls::AuthMacInput in3{Secret, sr, Restls::FlowDirection::to_server, 1, {}, tls_hdr,
                                   payload};
        EXPECT_NE(Restls::ComputeAuthMac(in3), mac);
    }

    TEST(RestlsCodecDeep, ComputeMask)
    {
        const auto Secret = Restls::DeriveSecret("pw");
        const std::array<std::uint8_t, 32> sr{0x30};
        const std::array<std::uint8_t, 32> Sample{0x40};

        Restls::MaskInput in{Secret, sr, Restls::FlowDirection::to_client, 5, Sample};
        const auto mask = Restls::ComputeMask(in);
        EXPECT_EQ(mask.size(), Restls::MaskLen);
        // 确定性
        EXPECT_EQ(Restls::ComputeMask(in), mask);
        // counter 变化 → 不同
        Restls::MaskInput in2{Secret, sr, Restls::FlowDirection::to_client, 6, Sample};
        EXPECT_NE(Restls::ComputeMask(in2), mask);
    }

} // namespace
