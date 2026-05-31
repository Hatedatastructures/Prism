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

    auto keypair = psm::crypto::generate_keypair();

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
 * @details 验证 derive_pubkey() 的输出与 keypair 中的公钥一致。
 */
void TestX25519DerivePublic()
{
    runner.LogInfo("=== TestX25519DerivePublic ===");

    auto keypair = psm::crypto::generate_keypair();

    auto derived = psm::crypto::derive_pubkey(keypair.private_key);

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

    auto alice = psm::crypto::generate_keypair();
    auto bob = psm::crypto::generate_keypair();

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
 * @details 验证 derive_pubkey + x25519 的组合操作
 * 与 generate_keypair 的行为一致。
 */
void TestX25519Rfc7748()
{
    runner.LogInfo("=== TestX25519Rfc7748 ===");

    // 使用 keypair 生成的私钥推导公钥
    auto keypair = psm::crypto::generate_keypair();
    auto derived = psm::crypto::derive_pubkey(keypair.private_key);

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

// ============================================================================
// X25519 异常输入测试
// ============================================================================

/**
 * @brief 测试 derive_pubkey 对无效长度的处理
 * @details 传入过短(16字节)和过长(48字节)的私钥，
 * 验证返回全零公钥。
 */
void TestDerivePubkeyInvalidSize()
{
    runner.LogInfo("=== TestDerivePubkeyInvalidSize ===");

    // 过短：16 字节
    const std::array<std::uint8_t, 16> short_key = {};
    auto derived_short = psm::crypto::derive_pubkey(short_key);
    if (!is_all_zero(derived_short))
    {
        runner.LogFail("derive_pubkey with 16-byte key should return all zeros");
        return;
    }

    // 过长：48 字节
    const std::array<std::uint8_t, 48> long_key = {};
    auto derived_long = psm::crypto::derive_pubkey(long_key);
    if (!is_all_zero(derived_long))
    {
        runner.LogFail("derive_pubkey with 48-byte key should return all zeros");
        return;
    }

    runner.LogPass("DerivePubkeyInvalidSize");
}

/**
 * @brief 测试 x25519 对无效私钥长度的处理
 * @details 传入 16 字节私钥和 32 字节对端公钥，
 * 验证返回 invalid_argument 且共享密钥全零。
 */
void TestX25519InvalidPrivateKeySize()
{
    runner.LogInfo("=== TestX25519InvalidPrivateKeySize ===");

    const std::array<std::uint8_t, 16> short_priv = {};
    const std::array<std::uint8_t, 32> peer_pub = {};

    auto [ec, shared] = psm::crypto::x25519(short_priv, peer_pub);

    if (ec != psm::fault::code::invalid_argument)
    {
        runner.LogFail("x25519 with 16-byte private key should return invalid_argument, got "
                       + std::to_string(static_cast<int>(ec)));
        return;
    }

    if (!is_all_zero(shared))
    {
        runner.LogFail("shared secret should be all zeros for invalid private key");
        return;
    }

    runner.LogPass("X25519InvalidPrivateKeySize");
}

/**
 * @brief 测试 x25519 对无效对端公钥长度的处理
 * @details 传入 32 字节私钥和 16 字节对端公钥，
 * 验证返回 invalid_argument。
 */
void TestX25519InvalidPeerPubkeySize()
{
    runner.LogInfo("=== TestX25519InvalidPeerPubkeySize ===");

    const std::array<std::uint8_t, 32> priv = {};
    const std::array<std::uint8_t, 16> short_peer = {};

    auto [ec, shared] = psm::crypto::x25519(priv, short_peer);

    if (ec != psm::fault::code::invalid_argument)
    {
        runner.LogFail("x25519 with 16-byte peer pubkey should return invalid_argument, got "
                       + std::to_string(static_cast<int>(ec)));
        return;
    }

    runner.LogPass("X25519InvalidPeerPubkeySize");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，依次运行 X25519 密钥生成、
 * 公钥推导、密钥交换以及 RFC 7748 标准测试向量等测试用例，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    runner.LogInfo("Starting X25519 tests...");

    TestX25519Keygen();
    TestX25519DerivePublic();
    TestX25519KeyExchange();
    TestX25519Rfc7748();
    TestDerivePubkeyInvalidSize();
    TestX25519InvalidPrivateKeySize();
    TestX25519InvalidPeerPubkeySize();

    runner.LogInfo("X25519 tests completed.");

    return runner.Summary();
}
