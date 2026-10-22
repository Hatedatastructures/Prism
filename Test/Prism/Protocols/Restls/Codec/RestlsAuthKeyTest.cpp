/**
 * @file RestlsAuthKeyTest.cpp
 * @brief Restls 认证密钥派生与固定 wire 向量测试。
 */

#include <array>
#include <cstdint>
#include <string>
#include <Prism/Protocols/Restls/Restls.hpp>
#include <Prism/Protocols/Restls/Detail/Codec.hpp>
#include <gtest/gtest.h>

namespace
{

    namespace Restls = Prism::Restls;

    template <typename ByteRange>
    auto Hex(const ByteRange &Bytes) -> std::string
    {
        static constexpr char Digits[] = "0123456789abcdef";
        std::string Output;
        Output.reserve(Bytes.size() * 2);
        for (const auto Byte : Bytes)
        {
            const auto Value = static_cast<std::uint8_t>(Byte);
            Output.push_back(Digits[Value >> 4]);
            Output.push_back(Digits[Value & 0x0f]);
        }
        return Output;
    }

TEST(RestlsBeast, AuthKeyDerivation)
    {
        const std::string password = "restls_password";
        const auto Secret = Restls::Detail::DeriveSecret(password);
        EXPECT_EQ(Secret.size(), 32u);

        std::array<std::uint8_t, 32> ServerRandom{};
        for (std::size_t i = 0; i < 32; ++i)
        {
            ServerRandom[i] = static_cast<std::uint8_t>(i);
        }
        const auto mask = Restls::Detail::ComputeServerMask(Secret, ServerRandom);
        EXPECT_EQ(mask.size(), Restls::HsMaclen);

        // 相同输入 → 相同输出
        const auto mask2 = Restls::Detail::ComputeServerMask(Secret, ServerRandom);
        EXPECT_EQ(mask, mask2);
    }

TEST(CarrierWireVector, RestlsTrafficKeyAndMaskAreExact)
    {
        const auto Secret = Prism::Restls::Detail::DeriveSecret("wire-vector-password");
        std::array<std::uint8_t, 32> ServerRandom{};
        for (std::size_t Index = 0; Index < ServerRandom.size(); ++Index)
        {
            ServerRandom[Index] = static_cast<std::uint8_t>(0x60 + Index);
        }
        const auto ServerMask = Prism::Restls::Detail::ComputeServerMask(Secret, ServerRandom);
        EXPECT_EQ(Hex(Secret),
                  "84b52d81e495d59d4f18c5d7c18d64b88a59f223b7378df641c0e7db6f7fc994");
        EXPECT_EQ(Hex(ServerMask),
                  "3efa1598c3da5630ef149568566750e5");
    }

} // namespace
