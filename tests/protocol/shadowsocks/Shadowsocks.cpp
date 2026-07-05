/**
 * @file Shadowsocks.cpp
 * @brief Shadowsocks 2022 (SIP022) 协议单元测试
 * @details 测试 SS2022 协议的 salt_pool 重放保护、地址解析、PSK 解码、
 * 密钥长度计算等功能，覆盖正常路径和各类边界条件。
 */

#include <prism/proto/protocol/shadowsocks.hpp>
#include <prism/proto/protocol/shadowsocks/framing.hpp>
#include <prism/proto/protocol/shadowsocks/util/salts.hpp>
#include <prism/proto/protocol/shadowsocks/constants.hpp>
#include <prism/proto/protocol/shadowsocks/config.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/foundation/foundation.hpp>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <span>
#include <string>
#include <thread>
#include <vector>


#include <gtest/gtest.h>

// ============================================================================
// Salt Pool 测试
// ============================================================================

/**
 * @brief 测试 salt 首次插入返回 true
 */
TEST(Shadowsocks, SaltPoolInsertAndCheck)
{
    psm::protocol::shadowsocks::salt_pool pool(60);

    std::array<std::uint8_t, 16> salt{};
    std::mt19937 rng(42);
    for (auto &b : salt)
        b = static_cast<std::uint8_t>(rng());

    EXPECT_TRUE(pool.check_and_insert(salt)) << "first insert should return true";
}

/**
 * @brief 测试重复 salt 返回 false
 */
TEST(Shadowsocks, SaltPoolDuplicateReplay)
{
    psm::protocol::shadowsocks::salt_pool pool(60);

    std::array<std::uint8_t, 16> salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                          0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    ASSERT_TRUE(pool.check_and_insert(salt)) << "first insert should return true";
    EXPECT_TRUE(!pool.check_and_insert(salt)) << "duplicate salt should return false";
}

/**
 * @brief 测试 salt 过期后可重新插入
 */
TEST(Shadowsocks, SaltPoolExpiry)
{
    // 1 秒 TTL
    psm::protocol::shadowsocks::salt_pool pool(1);

    std::array<std::uint8_t, 16> salt = {0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD,
                                          0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD};

    ASSERT_TRUE(pool.check_and_insert(salt)) << "first insert should return true";
    EXPECT_TRUE(!pool.check_and_insert(salt)) << "immediate retry should return false";

    // 等待过期（1 秒 + 安全余量）
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    EXPECT_TRUE(pool.check_and_insert(salt)) << "expired salt should be re-insertable";
}

/**
 * @brief 测试 cleanup() 正常工作
 */
TEST(Shadowsocks, SaltPoolCleanup)
{
    psm::protocol::shadowsocks::salt_pool pool(60);

    // 插入 5 个不同的 salt
    for (std::uint8_t i = 0; i < 5; ++i)
    {
        std::array<std::uint8_t, 16> salt{};
        salt[0] = i;
        ASSERT_TRUE(pool.check_and_insert(salt)) << "salt " << std::to_string(i) << " should insert successfully";
    }

    // cleanup 对未过期的条目不应删除
    pool.cleanup();

    // 验证所有 salt 仍然被拒绝（未过期）
    for (std::uint8_t i = 0; i < 5; ++i)
    {
        std::array<std::uint8_t, 16> salt{};
        salt[0] = i;
        EXPECT_TRUE(!pool.check_and_insert(salt)) << "salt " << std::to_string(i) << " should still be rejected after cleanup";
    }
}

// ============================================================================
// Format 解析测试
// ============================================================================

/**
 * @brief 测试解析 IPv4 地址+端口
 */
TEST(Shadowsocks, FormatParseAddressPortIPv4)
{
    // [atyp=0x01][127.0.0.1][port=8080 BE]
    const std::array<std::uint8_t, 7> buf = {0x01, 127, 0, 0, 1, 0x1F, 0x90};

    auto [ec, result] = psm::protocol::shadowsocks::format::parse_addr_port(buf);
    ASSERT_TRUE(psm::fault::succeeded(ec)) << "parse failed: " << psm::fault::describe(ec);

    EXPECT_TRUE(result.port == 8080) << "port should be 8080, got " << result.port;
    EXPECT_TRUE(result.offset == 7) << "offset should be 7, got " << result.offset;

    auto *ipv4 = std::get_if<psm::protocol::shadowsocks::ipv4_address>(&result.addr);
    ASSERT_TRUE(ipv4 != nullptr) << "address type should be IPv4";

    std::array<std::uint8_t, 4> expected = {127, 0, 0, 1};
    EXPECT_TRUE(ipv4->bytes == expected) << "IPv4 address mismatch";
}

/**
 * @brief 测试解析 IPv6 地址+端口
 */
TEST(Shadowsocks, FormatParseAddressPortIPv6)
{
    // [atyp=0x04][::1 16 bytes][port=80 BE]
    std::array<std::uint8_t, 19> buf{};
    buf[0] = 0x04;                         // atyp = IPv6
    buf[17] = 0x00; buf[18] = 0x50;        // port = 80

    auto [ec, result] = psm::protocol::shadowsocks::format::parse_addr_port(buf);
    ASSERT_TRUE(psm::fault::succeeded(ec)) << "parse failed: " << psm::fault::describe(ec);

    EXPECT_TRUE(result.port == 80) << "port should be 80, got " << result.port;
    EXPECT_TRUE(result.offset == 19) << "offset should be 19, got " << result.offset;
}

/**
 * @brief 测试解析域名地址+端口
 */
TEST(Shadowsocks, FormatParseAddressPortDomain)
{
    // [atyp=0x03][len=11]["example.com"][port=80 BE]
    const std::string domain = "example.com";
    std::vector<std::uint8_t> buf;
    buf.push_back(0x03);
    buf.push_back(static_cast<std::uint8_t>(domain.size()));
    buf.insert(buf.end(), domain.begin(), domain.end());
    buf.push_back(0x00);
    buf.push_back(0x50);

    auto [ec, result] = psm::protocol::shadowsocks::format::parse_addr_port(buf);
    ASSERT_TRUE(psm::fault::succeeded(ec)) << "parse failed: " << psm::fault::describe(ec);

    EXPECT_TRUE(result.port == 80) << "port should be 80, got " << result.port;

    auto *dom = std::get_if<psm::protocol::shadowsocks::domain_address>(&result.addr);
    ASSERT_TRUE(dom != nullptr) << "address type should be domain";
    EXPECT_TRUE(dom->length == domain.size()) << "domain length mismatch";
}

/**
 * @brief 测试空缓冲区返回错误
 */
TEST(Shadowsocks, FormatParseAddressPortEmpty)
{
    const std::span<const std::uint8_t> empty;
    auto [ec, result] = psm::protocol::shadowsocks::format::parse_addr_port(empty);

    EXPECT_TRUE(psm::fault::failed(ec)) << "empty buffer should fail";
    EXPECT_TRUE(ec == psm::fault::code::bad_message) << "expected bad_message error code";
}

// ============================================================================
// PSK 解码测试
// ============================================================================

/**
 * @brief 测试有效 16 字节 PSK 解码
 */
TEST(Shadowsocks, FormatDecodePskValid)
{
    // base64("AAAAAAAAAAAAAAAAAAAAAA==") -> 16 字节全零
    auto [ec, psk] = psm::protocol::shadowsocks::format::decode_psk("AAAAAAAAAAAAAAAAAAAAAA==");

    ASSERT_TRUE(psm::fault::succeeded(ec)) << "decode failed: " << psm::fault::describe(ec);
    ASSERT_TRUE(psk.size() == 16) << "PSK should be 16 bytes, got " << psk.size();

    for (auto b : psk)
    {
        EXPECT_TRUE(b == 0) << "PSK bytes should all be zero";
    }
}

/**
 * @brief 测试无效 base64 返回错误
 */
TEST(Shadowsocks, FormatDecodePskInvalidBase64)
{
    auto [ec, psk] = psm::protocol::shadowsocks::format::decode_psk("!!!invalid!!!");
    EXPECT_TRUE(psm::fault::failed(ec)) << "invalid base64 should fail";
}

/**
 * @brief 测试 PSK 长度不合法返回错误
 */
TEST(Shadowsocks, FormatDecodePskWrongLength)
{
    // "Zm9vYmFy" decodes to "foobar" = 6 bytes (neither 16 nor 32)
    auto [ec, psk] = psm::protocol::shadowsocks::format::decode_psk("Zm9vYmFy");
    EXPECT_TRUE(psm::fault::failed(ec)) << "wrong length PSK should fail";
    EXPECT_TRUE(ec == psm::fault::code::invalid_psk) << "expected invalid_psk error code";
}

/**
 * @brief 测试密钥/salt 长度计算
 */
TEST(Shadowsocks, FormatKeySaltLength)
{
    using cm = psm::protocol::shadowsocks::cipher_method;

    EXPECT_TRUE(psm::protocol::shadowsocks::format::keysalt_len(cm::aes_128_gcm) == 16) << "AES-128-GCM keysalt_len should be 16";
    EXPECT_TRUE(psm::protocol::shadowsocks::format::keysalt_len(cm::aes_256_gcm) == 32) << "AES-256-GCM keysalt_len should be 32";
}
