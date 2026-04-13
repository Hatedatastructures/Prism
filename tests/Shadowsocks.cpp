/**
 * @file Shadowsocks.cpp
 * @brief Shadowsocks 2022 (SIP022) 协议单元测试
 * @details 测试 SS2022 协议的 salt_pool 重放保护、地址解析、PSK 解码、
 * 密钥长度计算等功能，覆盖正常路径和各类边界条件。
 */

#include <prism/protocol/shadowsocks.hpp>
#include <prism/protocol/shadowsocks/format.hpp>
#include <prism/protocol/shadowsocks/salts.hpp>
#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/protocol/shadowsocks/config.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/fault.hpp>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace
{
    int passed = 0;
    int failed = 0;

    void log_info(const std::string_view msg)
    {
        psm::trace::info("[Shadowsocks] {}", msg);
    }

    void log_pass(const std::string_view msg)
    {
        ++passed;
        psm::trace::info("[Shadowsocks] PASS: {}", msg);
    }

    void log_fail(const std::string_view msg)
    {
        ++failed;
        psm::trace::error("[Shadowsocks] FAIL: {}", msg);
    }
}

// ============================================================================
// Salt Pool 测试
// ============================================================================

/**
 * @brief 测试 salt 首次插入返回 true
 */
void TestSaltPoolInsertAndCheck()
{
    log_info("=== TestSaltPoolInsertAndCheck ===");

    psm::protocol::shadowsocks::salt_pool pool(60);

    std::array<std::uint8_t, 16> salt{};
    std::mt19937 rng(42);
    for (auto &b : salt)
        b = static_cast<std::uint8_t>(rng());

    if (!pool.check_and_insert(salt))
    {
        log_fail("first insert should return true");
        return;
    }

    log_pass("SaltPoolInsertAndCheck");
}

/**
 * @brief 测试重复 salt 返回 false
 */
void TestSaltPoolDuplicateReplay()
{
    log_info("=== TestSaltPoolDuplicateReplay ===");

    psm::protocol::shadowsocks::salt_pool pool(60);

    std::array<std::uint8_t, 16> salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                          0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    if (!pool.check_and_insert(salt))
    {
        log_fail("first insert should return true");
        return;
    }

    if (pool.check_and_insert(salt))
    {
        log_fail("duplicate salt should return false");
        return;
    }

    log_pass("SaltPoolDuplicateReplay");
}

/**
 * @brief 测试 salt 过期后可重新插入
 */
void TestSaltPoolExpiry()
{
    log_info("=== TestSaltPoolExpiry ===");

    // 1 秒 TTL
    psm::protocol::shadowsocks::salt_pool pool(1);

    std::array<std::uint8_t, 16> salt = {0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD,
                                          0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD};

    if (!pool.check_and_insert(salt))
    {
        log_fail("first insert should return true");
        return;
    }

    if (pool.check_and_insert(salt))
    {
        log_fail("immediate retry should return false");
        return;
    }

    // 等待过期（1 秒 + 安全余量）
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    if (!pool.check_and_insert(salt))
    {
        log_fail("expired salt should be re-insertable");
        return;
    }

    log_pass("SaltPoolExpiry");
}

/**
 * @brief 测试 cleanup() 正常工作
 */
void TestSaltPoolCleanup()
{
    log_info("=== TestSaltPoolCleanup ===");

    psm::protocol::shadowsocks::salt_pool pool(60);

    // 插入 5 个不同的 salt
    for (std::uint8_t i = 0; i < 5; ++i)
    {
        std::array<std::uint8_t, 16> salt{};
        salt[0] = i;
        if (!pool.check_and_insert(salt))
        {
            log_fail("salt " + std::to_string(i) + " should insert successfully");
            return;
        }
    }

    // cleanup 对未过期的条目不应删除
    pool.cleanup();

    // 验证所有 salt 仍然被拒绝（未过期）
    for (std::uint8_t i = 0; i < 5; ++i)
    {
        std::array<std::uint8_t, 16> salt{};
        salt[0] = i;
        if (pool.check_and_insert(salt))
        {
            log_fail("salt " + std::to_string(i) + " should still be rejected after cleanup");
            return;
        }
    }

    log_pass("SaltPoolCleanup");
}

// ============================================================================
// Format 解析测试
// ============================================================================

/**
 * @brief 测试解析 IPv4 地址+端口
 */
void TestFormatParseAddressPortIPv4()
{
    log_info("=== TestFormatParseAddressPortIPv4 ===");

    // [atyp=0x01][127.0.0.1][port=8080 BE]
    const std::array<std::uint8_t, 7> buf = {0x01, 127, 0, 0, 1, 0x1F, 0x90};

    auto [ec, result] = psm::protocol::shadowsocks::format::parse_address_port(buf);
    if (psm::fault::failed(ec))
    {
        log_fail(std::format("parse failed: {}", std::string_view(psm::fault::describe(ec))));
        return;
    }

    if (result.port != 8080)
    {
        log_fail("port should be 8080, got " + std::to_string(result.port));
        return;
    }

    if (result.offset != 7)
    {
        log_fail("offset should be 7, got " + std::to_string(result.offset));
        return;
    }

    auto *ipv4 = std::get_if<psm::protocol::shadowsocks::ipv4_address>(&result.addr);
    if (!ipv4)
    {
        log_fail("address type should be IPv4");
        return;
    }

    std::array<std::uint8_t, 4> expected = {127, 0, 0, 1};
    if (ipv4->bytes != expected)
    {
        log_fail("IPv4 address mismatch");
        return;
    }

    log_pass("FormatParseAddressPortIPv4");
}

/**
 * @brief 测试解析 IPv6 地址+端口
 */
void TestFormatParseAddressPortIPv6()
{
    log_info("=== TestFormatParseAddressPortIPv6 ===");

    // [atyp=0x04][::1 16 bytes][port=80 BE]
    std::array<std::uint8_t, 19> buf{};
    buf[0] = 0x04;                         // atyp = IPv6
    buf[17] = 0x00; buf[18] = 0x50;        // port = 80

    auto [ec, result] = psm::protocol::shadowsocks::format::parse_address_port(buf);
    if (psm::fault::failed(ec))
    {
        log_fail(std::format("parse failed: {}", std::string_view(psm::fault::describe(ec))));
        return;
    }

    if (result.port != 80)
    {
        log_fail("port should be 80, got " + std::to_string(result.port));
        return;
    }

    if (result.offset != 19)
    {
        log_fail("offset should be 19, got " + std::to_string(result.offset));
        return;
    }

    log_pass("FormatParseAddressPortIPv6");
}

/**
 * @brief 测试解析域名地址+端口
 */
void TestFormatParseAddressPortDomain()
{
    log_info("=== TestFormatParseAddressPortDomain ===");

    // [atyp=0x03][len=11]["example.com"][port=80 BE]
    const std::string domain = "example.com";
    std::vector<std::uint8_t> buf;
    buf.push_back(0x03);
    buf.push_back(static_cast<std::uint8_t>(domain.size()));
    buf.insert(buf.end(), domain.begin(), domain.end());
    buf.push_back(0x00);
    buf.push_back(0x50);

    auto [ec, result] = psm::protocol::shadowsocks::format::parse_address_port(buf);
    if (psm::fault::failed(ec))
    {
        log_fail(std::format("parse failed: {}", std::string_view(psm::fault::describe(ec))));
        return;
    }

    if (result.port != 80)
    {
        log_fail("port should be 80, got " + std::to_string(result.port));
        return;
    }

    auto *dom = std::get_if<psm::protocol::shadowsocks::domain_address>(&result.addr);
    if (!dom)
    {
        log_fail("address type should be domain");
        return;
    }

    if (dom->length != domain.size())
    {
        log_fail("domain length mismatch");
        return;
    }

    log_pass("FormatParseAddressPortDomain");
}

/**
 * @brief 测试空缓冲区返回错误
 */
void TestFormatParseAddressPortEmpty()
{
    log_info("=== TestFormatParseAddressPortEmpty ===");

    const std::span<const std::uint8_t> empty;
    auto [ec, result] = psm::protocol::shadowsocks::format::parse_address_port(empty);

    if (psm::fault::succeeded(ec))
    {
        log_fail("empty buffer should fail");
        return;
    }

    if (ec != psm::fault::code::bad_message)
    {
        log_fail("expected bad_message error code");
        return;
    }

    log_pass("FormatParseAddressPortEmpty");
}

// ============================================================================
// PSK 解码测试
// ============================================================================

/**
 * @brief 测试有效 16 字节 PSK 解码
 */
void TestFormatDecodePskValid()
{
    log_info("=== TestFormatDecodePskValid ===");

    // base64("AAAAAAAAAAAAAAAAAAAAAA==") → 16 字节全零
    auto [ec, psk] = psm::protocol::shadowsocks::format::decode_psk("AAAAAAAAAAAAAAAAAAAAAA==");

    if (psm::fault::failed(ec))
    {
        log_fail(std::format("decode failed: {}", std::string_view(psm::fault::describe(ec))));
        return;
    }

    if (psk.size() != 16)
    {
        log_fail("PSK should be 16 bytes, got " + std::to_string(psk.size()));
        return;
    }

    for (auto b : psk)
    {
        if (b != 0)
        {
            log_fail("PSK bytes should all be zero");
            return;
        }
    }

    log_pass("FormatDecodePskValid");
}

/**
 * @brief 测试无效 base64 返回错误
 */
void TestFormatDecodePskInvalidBase64()
{
    log_info("=== TestFormatDecodePskInvalidBase64 ===");

    auto [ec, psk] = psm::protocol::shadowsocks::format::decode_psk("!!!invalid!!!");
    if (psm::fault::succeeded(ec))
    {
        log_fail("invalid base64 should fail");
        return;
    }

    log_pass("FormatDecodePskInvalidBase64");
}

/**
 * @brief 测试 PSK 长度不合法返回错误
 */
void TestFormatDecodePskWrongLength()
{
    log_info("=== TestFormatDecodePskWrongLength ===");

    // "Zm9vYmFy" decodes to "foobar" = 6 bytes (neither 16 nor 32)
    auto [ec, psk] = psm::protocol::shadowsocks::format::decode_psk("Zm9vYmFy");
    if (psm::fault::succeeded(ec))
    {
        log_fail("wrong length PSK should fail");
        return;
    }

    if (ec != psm::fault::code::invalid_psk)
    {
        log_fail("expected invalid_psk error code");
        return;
    }

    log_pass("FormatDecodePskWrongLength");
}

/**
 * @brief 测试密钥/salt 长度计算
 */
void TestFormatKeySaltLength()
{
    log_info("=== TestFormatKeySaltLength ===");

    using cm = psm::protocol::shadowsocks::cipher_method;

    if (psm::protocol::shadowsocks::format::key_salt_length(cm::aes_128_gcm) != 16)
    {
        log_fail("AES-128-GCM key_salt_length should be 16");
        return;
    }

    if (psm::protocol::shadowsocks::format::key_salt_length(cm::aes_256_gcm) != 32)
    {
        log_fail("AES-256-GCM key_salt_length should be 32");
        return;
    }

    log_pass("FormatKeySaltLength");
}

// ============================================================================
// 测试入口
// ============================================================================

/**
 * @brief 测试入口
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    log_info("Starting Shadowsocks tests...");

    // Salt Pool 测试
    TestSaltPoolInsertAndCheck();
    TestSaltPoolDuplicateReplay();
    TestSaltPoolExpiry();
    TestSaltPoolCleanup();

    // Format 解析测试
    TestFormatParseAddressPortIPv4();
    TestFormatParseAddressPortIPv6();
    TestFormatParseAddressPortDomain();
    TestFormatParseAddressPortEmpty();

    // PSK 解码测试
    TestFormatDecodePskValid();
    TestFormatDecodePskInvalidBase64();
    TestFormatDecodePskWrongLength();

    // 常量测试
    TestFormatKeySaltLength();

    psm::trace::info("[Shadowsocks] Results: {} passed, {} failed", passed, failed);
    psm::trace::shutdown();

    return failed > 0 ? 1 : 0;
}
