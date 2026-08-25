/**
 * @file ShadowtlsCodecDeep.cpp
 * @brief shadowtls Codec 字节级深测（纯函数）
 * @details 覆盖：SessionId 派生、ClientHello 验证、帧 HMAC、
 *          KDF 派生的确定性/差异性与错误路径。
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>

#include <common/Protocols/Shadowtls/Codec.hpp>

namespace
{
    using namespace Preview;

    TEST(ShadowtlsCodecDeep, SessionIdDerivation)
    {
        // 构造最小合法 ClientHello（SessionId 占位 32 字节，偏移 39）
        std::array<std::uint8_t, 96> hello{};
        hello[0] = 0x03;
        hello[1] = 0x03; // TLS 1.2
        std::array<std::uint8_t, 32> sid{};
        std::array<std::uint8_t, 32> sid2{};

        Shadowtls::SessionIdInput in{"pw", hello, sid};
        EXPECT_EQ(Shadowtls::GenerateSessionId(in), Error::none);
        EXPECT_NE(sid[sid.size() - 1], 0u); // 后 4 字节 HMAC 已写入

        // 同输入确定性（sid 前 28 随机 → 仅后 4 字节 HMAC 稳定）
        Shadowtls::SessionIdInput in2{"pw", hello, sid2};
        EXPECT_EQ(Shadowtls::GenerateSessionId(in2), Error::none);
        EXPECT_EQ(sid[sid.size() - 1], sid2[sid2.size() - 1]);

        // 超短 hello → bad_length
        const std::array<std::uint8_t, 4> tiny{};
        Shadowtls::SessionIdInput bad{"pw", tiny, sid};
        EXPECT_EQ(Shadowtls::GenerateSessionId(bad), Error::bad_length);
    }

    TEST(ShadowtlsCodecDeep, VerifyClientHelloShort)
    {
        // 短输入 → false（不崩溃）
        EXPECT_FALSE(Shadowtls::VerifyClientHello("pw", std::span<const std::byte>{}));
        const std::array<std::byte, 16> short_hello{};
        EXPECT_FALSE(Shadowtls::VerifyClientHello("pw", short_hello));
    }

    TEST(ShadowtlsCodecDeep, FrameHmacInput)
    {
        const std::array<std::uint8_t, 32> sr{0x44};
        const std::array<std::uint8_t, 8> payload{0x55};

        Shadowtls::FrameHmacInput in;
        in.password = "pw";
        in.ServerRandom = sr;
        in.tag = 'C';
        in.payload = payload;

        const auto hmac = Shadowtls::FrameHmacInput(in);
        EXPECT_EQ(hmac.size(), Shadowtls::HmacSize);
        // 同输入确定性
        EXPECT_EQ(Shadowtls::FrameHmacInput(in), hmac);
        // tag 变化 → 输出变化
        in.tag = 'S';
        EXPECT_NE(Shadowtls::FrameHmacInput(in), hmac);
    }

    TEST(ShadowtlsCodecDeep, KdfDerivation)
    {
        const std::array<std::uint8_t, 32> sr{0x66};
        const auto key = Shadowtls::Kdf("pw", sr);
        EXPECT_EQ(key.size(), 32u);
        EXPECT_EQ(Shadowtls::Kdf("pw", sr), key); // 确定性
        // 密码不同 → 密钥不同
        EXPECT_NE(Shadowtls::Kdf("other", sr), key);
        // ServerRandom 不同 → 密钥不同
        const std::array<std::uint8_t, 32> sr2{0x67};
        EXPECT_NE(Shadowtls::Kdf("pw", sr2), key);
    }

} // namespace
