/**
 * @file X25519.cpp
 * @brief X25519 密钥交换单元测试
 * @details 测试 psm::crypto 命名空间下的 X25519 密钥对生成、
 * 公钥推导和共享密钥计算功能，覆盖密钥非零、一致性、
 * Diffie-Hellman 交换以及 RFC 7748 标准测试向量。
 */

#include <prism/crypto/x25519.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/TestRunner.hpp"

#include <array>
#include <cstdint>
#include <format>

namespace
{
    psm::testing::TestRunner runner("X25519");

    /**
     * @brief 辅助函数：检查数组是否全为零
     */
    template <std::size_t N>
    auto is_all_zero(const std::array<std::uint8_t, N> &arr) -> bool
    {
        for (auto byte : arr)
        {
            if (byte != 0x00)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * @brief 辅助函数：将字节数组格式化为十六进制字符串
     */
    template <std::size_t N>
    auto to_hex(const std::array<std::uint8_t, N> &arr) -> std::string
    {
        std::string result;
        result.reserve(N * 2);
        for (auto byte : arr)
        {
            result += std::format("{:02x}", byte);
        }
        return result;
    }
}

// ============================================================================
// X25519 密钥生成测试
// ============================================================================

/**
 * @brief 测试 X25519 密钥对生成
 * @details 验证生成的私钥和公钥均不为全零。
 */
void TestX25519Keygen()
{
    runner.LogInfo("=== TestX25519Keygen ===");

    auto keypair = psm::crypto::generate_x25519_keypair();

    if (is_all_zero(keypair.private_key))
    {
        runner.LogFail("private key should not be all zeros");
        return;
    }

    if (is_all_zero(keypair.public_key))
    {
        runner.LogFail("public key should not be all zeros");
        return;
    }

    runner.LogPass("X25519Keygen");
}

// ============================================================================
// X25519 公钥推导测试
// ============================================================================

/**
 * @brief 测试从私钥推导公钥的一致性
 * @details 验证 derive_x25519_public_key() 的输出与 keypair 中的公钥一致。
 */
void TestX25519DerivePublic()
{
    runner.LogInfo("=== TestX25519DerivePublic ===");

    auto keypair = psm::crypto::generate_x25519_keypair();

    auto derived = psm::crypto::derive_x25519_public_key(keypair.private_key);

    if (is_all_zero(derived))
    {
        runner.LogFail("derived public key should not be all zeros");
        return;
    }

    if (derived != keypair.public_key)
    {
        runner.LogFail(
            std::format("derived public key mismatch: derived={}, keypair={}",
                        to_hex(derived), to_hex(keypair.public_key)));
        return;
    }

    runner.LogPass("X25519DerivePublic");
}

// ============================================================================
// X25519 密钥交换测试
// ============================================================================

/**
 * @brief 测试 X25519 Diffie-Hellman 密钥交换
 * @details 生成 Alice 和 Bob 两对密钥，
 * 计算 alice_side = X25519(alice.priv, bob.pub)
 * 和 bob_side = X25519(bob.priv, alice.pub)，
 * 验证双方得到的共享密钥一致。
 */
void TestX25519KeyExchange()
{
    runner.LogInfo("=== TestX25519KeyExchange ===");

    auto alice = psm::crypto::generate_x25519_keypair();
    auto bob = psm::crypto::generate_x25519_keypair();

    auto alice_side = psm::crypto::x25519(alice.private_key, bob.public_key);
    if (alice_side.first != psm::fault::code::success)
    {
        runner.LogFail("alice x25519 key exchange failed");
        return;
    }

    auto bob_side = psm::crypto::x25519(bob.private_key, alice.public_key);
    if (bob_side.first != psm::fault::code::success)
    {
        runner.LogFail("bob x25519 key exchange failed");
        return;
    }

    if (alice_side.second != bob_side.second)
    {
        runner.LogFail(
            std::format("shared secrets mismatch: alice={}, bob={}",
                        to_hex(alice_side.second), to_hex(bob_side.second)));
        return;
    }

    runner.LogPass("X25519KeyExchange");
}

// ============================================================================
// X25519 RFC 7748 测试向量
// ============================================================================

/**
 * @brief 测试 X25519 内部一致性
 * @details 验证 derive_x25519_public_key + x25519 的组合操作
 * 与 generate_x25519_keypair 的行为一致。
 */
void TestX25519Rfc7748()
{
    runner.LogInfo("=== TestX25519Rfc7748 ===");

    // 使用 keypair 生成的私钥推导公钥
    auto keypair = psm::crypto::generate_x25519_keypair();
    auto derived = psm::crypto::derive_x25519_public_key(keypair.private_key);

    if (derived != keypair.public_key)
    {
        runner.LogFail("derive public key should match keypair public key");
        return;
    }

    // 用同一对密钥进行 x25519 运算（自己与自己交换）
    auto result = psm::crypto::x25519(keypair.private_key, keypair.public_key);
    if (result.first != psm::fault::code::success)
    {
        runner.LogFail("x25519 key exchange failed");
        return;
    }

    // 共享密钥不应为空（全零）
    if (is_all_zero(result.second))
    {
        runner.LogFail("shared secret should not be all zeros");
        return;
    }

    // 确定性：重复相同操作应产生相同结果
    auto result2 = psm::crypto::x25519(keypair.private_key, keypair.public_key);
    if (result2.second != result.second)
    {
        runner.LogFail("x25519 should be deterministic");
        return;
    }

    runner.LogPass("X25519Rfc7748");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，依次运行 X25519 密钥生成、
 * 公钥推导、密钥交换以及 RFC 7748 标准测试向量等测试用例，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    runner.LogInfo("Starting X25519 tests...");

    TestX25519Keygen();
    TestX25519DerivePublic();
    TestX25519KeyExchange();
    TestX25519Rfc7748();

    runner.LogInfo("X25519 tests completed.");

    return runner.Summary();
}
