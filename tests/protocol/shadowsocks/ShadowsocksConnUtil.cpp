/**
 * @file ShadowsocksConnUtil.cpp
 * @brief SS2022 conn 工具函数 + derive_aead_context 深度测试
 * @details 先包含所有重量级头文件（aead.hpp, blake3.hpp 等），
 *          再用 #define private public 仅打开 conn.hpp 的 private。
 *          通过 #include 源文件确保 gcov 计入覆盖行。
 */

#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>

// 在 #define private public 之前预包含所有传递依赖，防止类布局破坏
#include <prism/crypto/aead.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/core/core.hpp>
#include <prism/proto/protocol/common/address.hpp>
#include <prism/proto/protocol/common/target.hpp>
#include <prism/proto/protocol/shadowsocks/config.hpp>
#include <prism/proto/protocol/shadowsocks/constants.hpp>
#include <prism/proto/protocol/shadowsocks/framing.hpp>
#include <prism/proto/protocol/shadowsocks/packet.hpp>
#include <prism/proto/protocol/shadowsocks/util/salts.hpp>
#include <prism/proto/protocol/shadowsocks/util/cast.hpp>
#include <prism/net/transport/transmission.hpp>
#include <boost/asio.hpp>
#include <openssl/rand.h>


#include "common/MockTransport.hpp"
#include <gtest/gtest.h>

// 所有传递依赖已包含，现在仅打开 conn.hpp 的 private
#define private public
#include <prism/proto/protocol/shadowsocks/conn.hpp>
#undef private

// 包含源文件以获得 gcov 覆盖
#include "../../src/prism/proto/protocol/shadowsocks/conn.cpp"

using psm::testing::MockTransport;

// ─── as_u8_mut / to_bytes 在 ss 匿名命名空间中 ───

namespace psm::protocol::shadowsocks
{

    TEST(ShadowsocksConnUtil, AsU8MutVectorBasic)
    {
        std::vector<std::byte> v = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
        auto span = as_u8_mut(v);
        EXPECT_TRUE(span.size() == 3) << "as_u8_mut(vector): size=3";
        EXPECT_TRUE(span[0] == 0x01) << "as_u8_mut(vector): first byte";
        EXPECT_TRUE(span[2] == 0x03) << "as_u8_mut(vector): last byte";
    }

    TEST(ShadowsocksConnUtil, AsU8MutVectorEmpty)
    {
        std::vector<std::byte> v;
        auto span = as_u8_mut(v);
        EXPECT_TRUE(span.empty()) << "as_u8_mut(vector): empty";
    }

    TEST(ShadowsocksConnUtil, AsU8MutVectorWrite)
    {
        std::vector<std::byte> v(4, std::byte{0x00});
        auto span = as_u8_mut(v);
        span[0] = 0xAA;
        span[3] = 0xFF;
        EXPECT_TRUE(v[0] == std::byte{0xAA}) << "as_u8_mut(vector): write modifies original";
        EXPECT_TRUE(v[3] == std::byte{0xFF}) << "as_u8_mut(vector): write last byte";
    }

    TEST(ShadowsocksConnUtil, AsU8MutPmrBasic)
    {
        psm::memory::vector<std::byte> v(psm::memory::current_resource());
        v.push_back(std::byte{0x10});
        v.push_back(std::byte{0x20});
        auto span = as_u8_mut(v);
        EXPECT_TRUE(span.size() == 2) << "as_u8_mut(pmr): size=2";
        EXPECT_TRUE(span[0] == 0x10) << "as_u8_mut(pmr): first byte";
    }

    TEST(ShadowsocksConnUtil, AsU8MutPmrEmpty)
    {
        psm::memory::vector<std::byte> v(psm::memory::current_resource());
        auto span = as_u8_mut(v);
        EXPECT_TRUE(span.empty()) << "as_u8_mut(pmr): empty";
    }

    TEST(ShadowsocksConnUtil, AsU8MutPmrWrite)
    {
        psm::memory::vector<std::byte> v(8, std::byte{0x00}, psm::memory::current_resource());
        auto span = as_u8_mut(v);
        span[0] = 0x42;
        span[7] = 0xFF;
        EXPECT_TRUE(v[0] == std::byte{0x42}) << "as_u8_mut(pmr): write index 0";
        EXPECT_TRUE(v[7] == std::byte{0xFF}) << "as_u8_mut(pmr): write index 7";
    }

    TEST(ShadowsocksConnUtil, ToBytesUint8Vector)
    {
        std::vector<std::uint8_t> v = {0x01, 0x02, 0x03};
        auto bytes = to_bytes(v);
        EXPECT_TRUE(bytes.size() == 3) << "to_bytes: size=3";
        EXPECT_TRUE(bytes[0] == std::byte{0x01}) << "to_bytes: first byte";
        EXPECT_TRUE(bytes[2] == std::byte{0x03}) << "to_bytes: last byte";
    }

    TEST(ShadowsocksConnUtil, ToBytesEmpty)
    {
        std::vector<std::uint8_t> v;
        auto bytes = to_bytes(v);
        EXPECT_TRUE(bytes.empty()) << "to_bytes: empty";
    }

    TEST(ShadowsocksConnUtil, ToBytesUint32Vector)
    {
        std::vector<std::uint32_t> v = {0x01020304, 0x05060708};
        auto bytes = to_bytes(v);
        EXPECT_TRUE(bytes.size() == 8) << "to_bytes: uint32 vector -> 8 bytes";
    }

} // namespace psm::protocol::shadowsocks

// ─── derive_aead_context 测试在全局命名空间，用 ss:: 限定 ───

namespace
{
    namespace ss = psm::protocol::shadowsocks;

    static consteval auto psk128_b64() -> const char *
    {
        return "AAAAAAAAAAAAAAAAAAAAAA==";
    }

    static consteval auto psk256_b64() -> const char *
    {
        return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    }

    TEST(ShadowsocksConnUtil, DeriveAeadContextAes128)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = std::make_shared<MockTransport>();
        auto salts = std::make_shared<ss::salt_pool>();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        std::array<std::uint8_t, 16> salt{};
        for (std::size_t i = 0; i < 16; ++i)
            salt[i] = static_cast<std::uint8_t>(i);

        auto ctx = c.derive_aead_context(salt);
        EXPECT_TRUE(ctx != nullptr) << "derive: aes-128 context not null";
    }

    TEST(ShadowsocksConnUtil, DeriveAeadContextAes256)
    {
        ss::config cfg;
        cfg.psk = psk256_b64();
        cfg.method = "2022-blake3-aes-256-gcm";

        auto mock = std::make_shared<MockTransport>();
        auto salts = std::make_shared<ss::salt_pool>();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        std::array<std::uint8_t, 32> salt{};
        for (std::size_t i = 0; i < 32; ++i)
            salt[i] = static_cast<std::uint8_t>(i + 0x80);

        auto ctx = c.derive_aead_context(salt);
        EXPECT_TRUE(ctx != nullptr) << "derive: aes-256 context not null";
    }

    TEST(ShadowsocksConnUtil, DeriveAeadContextChaCha20)
    {
        ss::config cfg;
        cfg.psk = psk256_b64();
        cfg.method = "2022-blake3-chacha20-poly1305";

        auto mock = std::make_shared<MockTransport>();
        auto salts = std::make_shared<ss::salt_pool>();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        std::array<std::uint8_t, 32> salt{};
        for (std::size_t i = 0; i < 32; ++i)
            salt[i] = static_cast<std::uint8_t>(i);

        auto ctx = c.derive_aead_context(salt);
        EXPECT_TRUE(ctx != nullptr) << "derive: chacha20 context not null";
    }

    TEST(ShadowsocksConnUtil, DeriveAeadContextDifferentSalts)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = std::make_shared<MockTransport>();
        auto salts = std::make_shared<ss::salt_pool>();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        std::array<std::uint8_t, 16> salt1{};
        salt1[0] = 0x01;
        std::array<std::uint8_t, 16> salt2{};
        salt2[0] = 0x02;

        auto ctx1 = c.derive_aead_context(salt1);
        auto ctx2 = c.derive_aead_context(salt2);
        EXPECT_TRUE(ctx1 != nullptr) << "derive: salt1 context";
        EXPECT_TRUE(ctx2 != nullptr) << "derive: salt2 context";
    }

    TEST(ShadowsocksConnUtil, DeriveAeadContextEmptySalt)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = std::make_shared<MockTransport>();
        auto salts = std::make_shared<ss::salt_pool>();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        auto ctx = c.derive_aead_context(std::span<const std::uint8_t>{});
        EXPECT_TRUE(ctx != nullptr) << "derive: empty salt context";
    }

    TEST(ShadowsocksConnUtil, DeriveAeadContextEncryptDecrypt)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = std::make_shared<MockTransport>();
        auto salts = std::make_shared<ss::salt_pool>();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        std::array<std::uint8_t, 16> salt{};
        for (std::size_t i = 0; i < 16; ++i)
            salt[i] = static_cast<std::uint8_t>(i);

        auto seal_ctx = c.derive_aead_context(salt);
        EXPECT_TRUE(seal_ctx != nullptr) << "derive: roundtrip seal context";

        std::array<std::uint8_t, 4> plaintext = {0xDE, 0xAD, 0xBE, 0xEF};
        std::vector<std::uint8_t> ciphertext(plaintext.size() + psm::crypto::aead_context::tag_length(), 0);

        // 使用显式 nonce 重载（nonce=0），保证 seal 和 open 使用相同 nonce
        std::array<std::uint8_t, 12> seal_nonce{};
        auto seal_rc = seal_ctx->seal(psm::crypto::seal_input{
            ciphertext,
            plaintext,
            seal_nonce,
            {}});
        EXPECT_TRUE(seal_rc == psm::fault::code::success) << "derive: seal success";
        EXPECT_TRUE(ciphertext.size() == 4 + 16) << "derive: ciphertext = data + tag";

        // 派生独立解密上下文（nonce 从 0 开始，与加密上下文一致）
        auto open_ctx = c.derive_aead_context(salt);
        EXPECT_TRUE(open_ctx != nullptr) << "derive: roundtrip open context";

        // 使用显式 nonce 重载进行解密（nonce=0），绕过自动 nonce 递增问题
        std::array<std::uint8_t, 12> zero_nonce{};
        std::vector<std::uint8_t> decrypted(plaintext.size(), 0);
        auto open_rc = open_ctx->open(psm::crypto::open_input{
            decrypted,
            ciphertext,
            zero_nonce,
            {}});
        EXPECT_TRUE(open_rc == psm::fault::code::success) << "derive: open success";
        EXPECT_TRUE(decrypted.size() == 4) << "derive: decrypted size=4";
        EXPECT_TRUE(decrypted[0] == 0xDE) << "derive: decrypted byte 0";
        EXPECT_TRUE(decrypted[3] == 0xEF) << "derive: decrypted byte 3";
    }

} // namespace
