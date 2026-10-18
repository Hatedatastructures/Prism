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

#include <Prism/Protocols/Restls/Detail/Record.hpp>

namespace
{
    namespace Restls = Prism::Restls;

    TEST(RestlsCodecDeep, DeriveSecret)
    {
        const auto Secret = Restls::Detail::DeriveSecret("pw");
        EXPECT_EQ(Secret.size(), 32u);
        EXPECT_EQ(Restls::Detail::DeriveSecret("pw"), Secret); // 确定性
        EXPECT_NE(Restls::Detail::DeriveSecret("pw2"), Secret); // 密码敏感
        EXPECT_EQ(Restls::Detail::DeriveSecret("").size(), 32u); // 空密码不崩溃
    }

    TEST(RestlsCodecDeep, ComputeServerMask)
    {
        const auto Secret = Restls::Detail::DeriveSecret("pw");
        const std::array<std::uint8_t, 32> ServerRandom{0x01};
        const auto Mask = Restls::Detail::ComputeServerMask(Secret, ServerRandom);
        EXPECT_EQ(Mask.size(), Restls::HsMaclen);
        // 确定性
        EXPECT_EQ(Restls::Detail::ComputeServerMask(Secret, ServerRandom), Mask);
        // Server random 变化 → 掩码变化
        const std::array<std::uint8_t, 32> ServerRandomTwo{0x02};
        EXPECT_NE(Restls::Detail::ComputeServerMask(Secret, ServerRandomTwo), Mask);
    }

    TEST(RestlsCodecDeep, ComputeAuthMac)
    {
        const auto Secret = Restls::Detail::DeriveSecret("pw");
        const std::array<std::uint8_t, 32> ServerRandom{0x10};
        const std::array<std::uint8_t, 5> TlsHeader{0x17, 0x03, 0x03, 0x00, 0x10};
        const std::array<std::uint8_t, 8> Payload{0x20};

        Restls::Detail::AuthMacInput Input{Secret, ServerRandom, Restls::FlowDirection::ToClient, 1, {}, TlsHeader,
                                  Payload};
        const auto Mac = Restls::Detail::ComputeAuthMac(Input);
        EXPECT_EQ(Mac.size(), Restls::AppdataMaclen);
        // 确定性
        EXPECT_EQ(Restls::Detail::ComputeAuthMac(Input), Mac);
        // counter 变化 → 不同
        Restls::Detail::AuthMacInput InputTwo{Secret, ServerRandom, Restls::FlowDirection::ToClient, 2, {}, TlsHeader,
                                   Payload};
        EXPECT_NE(Restls::Detail::ComputeAuthMac(InputTwo), Mac);
        // 方向变化 → 不同
        Restls::Detail::AuthMacInput InputThree{Secret, ServerRandom, Restls::FlowDirection::ToServer, 1, {}, TlsHeader,
                                   Payload};
        EXPECT_NE(Restls::Detail::ComputeAuthMac(InputThree), Mac);
    }

    TEST(RestlsCodecDeep, ComputeMask)
    {
        const auto Secret = Restls::Detail::DeriveSecret("pw");
        const std::array<std::uint8_t, 32> ServerRandom{0x30};
        const std::array<std::uint8_t, 32> Sample{0x40};

        Restls::Detail::MaskInput Input{Secret, ServerRandom, Restls::FlowDirection::ToClient, 5, Sample};
        const auto Mask = Restls::Detail::ComputeMask(Input);
        EXPECT_EQ(Mask.size(), Restls::MaskLen);
        // 确定性
        EXPECT_EQ(Restls::Detail::ComputeMask(Input), Mask);
        // counter 变化 → 不同
        Restls::Detail::MaskInput InputTwo{Secret, ServerRandom, Restls::FlowDirection::ToClient, 6, Sample};
        EXPECT_NE(Restls::Detail::ComputeMask(InputTwo), Mask);
    }

} // namespace
