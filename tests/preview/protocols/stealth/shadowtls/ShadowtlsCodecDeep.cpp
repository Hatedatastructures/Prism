/**
 * @file ShadowtlsCodecDeep.cpp
 * @brief shadowtls codec 字节级深测（纯函数）
 * @details 覆盖：session_id 派生、ClientHello 验证、帧 HMAC、
 *          KDF 派生的确定性/差异性与错误路径。
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>

#include <common/protocols/shadowtls/codec.hpp>

namespace
{
    using namespace preview;

    TEST(ShadowtlsCodecDeep, SessionIdDerivation)
    {
        // 构造最小合法 ClientHello（session_id 占位 32 字节，偏移 39）
        std::array<std::uint8_t, 96> hello{};
        hello[0] = 0x03;
        hello[1] = 0x03; // TLS 1.2
        std::array<std::uint8_t, 32> sid{};
        std::array<std::uint8_t, 32> sid2{};

        shadowtls::session_id_input in{"pw", hello, sid};
        EXPECT_EQ(shadowtls::generate_session_id(in), error::none);
        EXPECT_NE(sid[sid.size() - 1], 0u); // 后 4 字节 HMAC 已写入

        // 同输入确定性（sid 前 28 随机 → 仅后 4 字节 HMAC 稳定）
        shadowtls::session_id_input in2{"pw", hello, sid2};
        EXPECT_EQ(shadowtls::generate_session_id(in2), error::none);
        EXPECT_EQ(sid[sid.size() - 1], sid2[sid2.size() - 1]);

        // 超短 hello → bad_length
        const std::array<std::uint8_t, 4> tiny{};
        shadowtls::session_id_input bad{"pw", tiny, sid};
        EXPECT_EQ(shadowtls::generate_session_id(bad), error::bad_length);
    }

    TEST(ShadowtlsCodecDeep, VerifyClientHelloShort)
    {
        // 短输入 → false（不崩溃）
        EXPECT_FALSE(shadowtls::verify_client_hello("pw", std::span<const std::byte>{}));
        const std::array<std::byte, 16> short_hello{};
        EXPECT_FALSE(shadowtls::verify_client_hello("pw", short_hello));
    }

    TEST(ShadowtlsCodecDeep, FrameHmac)
    {
        const std::array<std::uint8_t, 32> sr{0x44};
        const std::array<std::uint8_t, 8> payload{0x55};

        shadowtls::frame_hmac_input in;
        in.password = "pw";
        in.server_random = sr;
        in.tag = 'C';
        in.payload = payload;

        const auto hmac = shadowtls::frame_hmac(in);
        EXPECT_EQ(hmac.size(), shadowtls::hmac_size);
        // 同输入确定性
        EXPECT_EQ(shadowtls::frame_hmac(in), hmac);
        // tag 变化 → 输出变化
        in.tag = 'S';
        EXPECT_NE(shadowtls::frame_hmac(in), hmac);
    }

    TEST(ShadowtlsCodecDeep, KdfDerivation)
    {
        const std::array<std::uint8_t, 32> sr{0x66};
        const auto key = shadowtls::kdf("pw", sr);
        EXPECT_EQ(key.size(), 32u);
        EXPECT_EQ(shadowtls::kdf("pw", sr), key); // 确定性
        // 密码不同 → 密钥不同
        EXPECT_NE(shadowtls::kdf("other", sr), key);
        // server_random 不同 → 密钥不同
        const std::array<std::uint8_t, 32> sr2{0x67};
        EXPECT_NE(shadowtls::kdf("pw", sr2), key);
    }

} // namespace
