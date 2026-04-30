/**
 * @file Block.cpp
 * @brief AES-ECB 单块加解密单元测试
 * @details 测试 psm::crypto 命名空间下的 aes_ecb_encrypt 和 aes_ecb_decrypt
 * 函数，覆盖 AES-128/AES-256 往返加解密及 NIST SP 800-38A 已知测试向量。
 */

#include <prism/crypto/block.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/TestRunner.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace
{
    psm::testing::TestRunner runner("Block");
}

// ============================================================================
// AES-ECB 往返加解密测试
// ============================================================================

/**
 * @brief 测试 AES-128-ECB 加解密往返
 * @details 使用 16 字节密钥加密 16 字节明文，再解密密文，
 * 验证往返结果与原始明文一致。
 */
void TestAes128EcbEncryptDecrypt()
{
    runner.LogInfo("=== TestAes128EcbEncryptDecrypt ===");

    // AES-128 密钥 (16 字节)
    constexpr std::array<std::uint8_t, 16> key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    // 明文 (16 字节)
    constexpr std::array<std::uint8_t, 16> plaintext = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };

    // 加密
    const auto ciphertext = psm::crypto::aes_ecb_encrypt(
        std::span<const std::uint8_t, 16>{plaintext},
        std::span<const std::uint8_t>{key.data(), key.size()}
    );

    // 解密
    const auto decrypted = psm::crypto::aes_ecb_decrypt(
        std::span<const std::uint8_t, 16>{ciphertext},
        std::span<const std::uint8_t>{key.data(), key.size()}
    );

    // 验证往返一致性
    if (decrypted != plaintext)
    {
        runner.LogFail("AES-128-ECB roundtrip mismatch");
        return;
    }

    runner.LogPass("Aes128EcbEncryptDecrypt");
}

/**
 * @brief 测试 AES-256-ECB 加解密往返
 * @details 使用 32 字节密钥加密 16 字节明文，再解密密文，
 * 验证往返结果与原始明文一致。
 */
void TestAes256EcbEncryptDecrypt()
{
    runner.LogInfo("=== TestAes256EcbEncryptDecrypt ===");

    // AES-256 密钥 (32 字节)
    constexpr std::array<std::uint8_t, 32> key = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    // 明文 (16 字节)
    constexpr std::array<std::uint8_t, 16> plaintext = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };

    // 加密
    const auto ciphertext = psm::crypto::aes_ecb_encrypt(
        std::span<const std::uint8_t, 16>{plaintext},
        std::span<const std::uint8_t>{key.data(), key.size()}
    );

    // 解密
    const auto decrypted = psm::crypto::aes_ecb_decrypt(
        std::span<const std::uint8_t, 16>{ciphertext},
        std::span<const std::uint8_t>{key.data(), key.size()}
    );

    // 验证往返一致性
    if (decrypted != plaintext)
    {
        runner.LogFail("AES-256-ECB roundtrip mismatch");
        return;
    }

    runner.LogPass("Aes256EcbEncryptDecrypt");
}

// ============================================================================
// NIST 已知测试向量
// ============================================================================

/**
 * @brief 测试 AES-128-ECB NIST SP 800-38A 已知向量
 * @details 使用 NIST SP 800-38A 附录 F.1.1 的 AES-128-ECB 测试向量，
 * 验证加密输出与标准参考值完全一致。
 *
 * Key:       2b7e151628aed2a6abf7158809cf4f3c
 * Plaintext: 6bc1bee22e409f96e93d7e117393172a
 * Expected:  3ad77bb40d7a3660a89ecaf32466ef97
 */
void TestAes128NistVector()
{
    runner.LogInfo("=== TestAes128NistVector ===");

    // NIST SP 800-38A AES-128 密钥
    constexpr std::array<std::uint8_t, 16> key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    // NIST SP 800-38A 明文
    constexpr std::array<std::uint8_t, 16> plaintext = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };

    // NIST SP 800-38A 期望密文
    constexpr std::array<std::uint8_t, 16> expected = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
    };

    const auto ciphertext = psm::crypto::aes_ecb_encrypt(
        std::span<const std::uint8_t, 16>{plaintext},
        std::span<const std::uint8_t>{key.data(), key.size()}
    );

    if (ciphertext != expected)
    {
        runner.LogFail("AES-128-ECB NIST vector mismatch");
        return;
    }

    runner.LogPass("Aes128NistVector");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，依次运行 AES-128/AES-256
 * 往返加解密测试及 NIST 已知向量测试，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    // 初始化全局 PMR 内存池
    psm::memory::system::enable_global_pooling();
    // 初始化日志系统
    psm::trace::init({});

    runner.LogInfo("Starting block cipher tests...");

    // AES-ECB 往返测试
    TestAes128EcbEncryptDecrypt();
    TestAes256EcbEncryptDecrypt();

    // NIST 已知向量测试
    TestAes128NistVector();

    runner.LogInfo("Block cipher tests completed.");

    return runner.Summary();
}
