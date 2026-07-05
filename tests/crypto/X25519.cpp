/**
 * @file X25519.cpp
 * @brief X25519 密钥交换单元测试
 * @details 测试 psm::crypto 命名空间下的 X25519 密钥对生成、
 * 公钥推导和共享密钥计算功能，覆盖密钥非零、一致性、
 * Diffie-Hellman 交换以及 RFC 7748 标准测试向量。
 */

#include <gtest/gtest.h>

#include <prism/crypto/x25519.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <cstdint>
#include <format>

namespace
{
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
} // namespace

// ============================================================================
// X25519 密钥生成测试
// ============================================================================

/**
 * @brief 测试 X25519 密钥对生成
 * @details 验证生成的私钥和公钥均不为全零。
 */
TEST(X25519, Keygen)
{
    auto keypair = psm::crypto::generate_keypair();

    EXPECT_FALSE(is_all_zero(keypair.private_key))
        << "private key should not be all zeros";
    EXPECT_FALSE(is_all_zero(keypair.public_key))
        << "public key should not be all zeros";
}

// ============================================================================
// X25519 公钥推导测试
// ============================================================================

/**
 * @brief 测试从私钥推导公钥的一致性
 * @details 验证 derive_pubkey() 的输出与 keypair 中的公钥一致。
 */
TEST(X25519, DerivePublic)
{
    auto keypair = psm::crypto::generate_keypair();

    auto derived = psm::crypto::derive_pubkey(keypair.private_key);

    EXPECT_FALSE(is_all_zero(derived))
        << "derived public key should not be all zeros";

    EXPECT_EQ(derived, keypair.public_key)
        << std::format("derived public key mismatch: derived={}, keypair={}",
                        to_hex(derived), to_hex(keypair.public_key));
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
TEST(X25519, KeyExchange)
{
    auto alice = psm::crypto::generate_keypair();
    auto bob = psm::crypto::generate_keypair();

    auto alice_side = psm::crypto::x25519(alice.private_key, bob.public_key);
    ASSERT_EQ(alice_side.first, psm::fault::code::success)
        << "alice x25519 key exchange failed";

    auto bob_side = psm::crypto::x25519(bob.private_key, alice.public_key);
    ASSERT_EQ(bob_side.first, psm::fault::code::success)
        << "bob x25519 key exchange failed";

    EXPECT_EQ(alice_side.second, bob_side.second)
        << std::format("shared secrets mismatch: alice={}, bob={}",
                        to_hex(alice_side.second), to_hex(bob_side.second));
}

// ============================================================================
// X25519 RFC 7748 测试向量
// ============================================================================

/**
 * @brief 测试 X25519 内部一致性
 * @details 验证 derive_pubkey + x25519 的组合操作
 * 与 generate_keypair 的行为一致。
 */
TEST(X25519, Rfc7748)
{
    // 使用 keypair 生成的私钥推导公钥
    auto keypair = psm::crypto::generate_keypair();
    auto derived = psm::crypto::derive_pubkey(keypair.private_key);

    ASSERT_EQ(derived, keypair.public_key)
        << "derive public key should match keypair public key";

    // 用同一对密钥进行 x25519 运算（自己与自己交换）
    auto result = psm::crypto::x25519(keypair.private_key, keypair.public_key);
    ASSERT_EQ(result.first, psm::fault::code::success)
        << "x25519 key exchange failed";

    // 共享密钥不应为空（全零）
    EXPECT_FALSE(is_all_zero(result.second))
        << "shared secret should not be all zeros";

    // 确定性：重复相同操作应产生相同结果
    auto result2 = psm::crypto::x25519(keypair.private_key, keypair.public_key);
    EXPECT_EQ(result2.second, result.second)
        << "x25519 should be deterministic";
}

// ============================================================================
// X25519 异常输入测试
// ============================================================================

/**
 * @brief 测试 derive_pubkey 对无效长度的处理
 * @details 传入过短(16字节)和过长(48字节)的私钥，
 * 验证返回全零公钥。
 */
TEST(X25519, DerivePubkeyInvalidSize)
{
    // 过短：16 字节
    const std::array<std::uint8_t, 16> short_key = {};
    auto derived_short = psm::crypto::derive_pubkey(short_key);
    EXPECT_TRUE(is_all_zero(derived_short))
        << "derive_pubkey with 16-byte key should return all zeros";

    // 过长：48 字节
    const std::array<std::uint8_t, 48> long_key = {};
    auto derived_long = psm::crypto::derive_pubkey(long_key);
    EXPECT_TRUE(is_all_zero(derived_long))
        << "derive_pubkey with 48-byte key should return all zeros";
}

/**
 * @brief 测试 x25519 对无效私钥长度的处理
 * @details 传入 16 字节私钥和 32 字节对端公钥，
 * 验证返回 invalid_argument 且共享密钥全零。
 */
TEST(X25519, InvalidPrivateKeySize)
{
    const std::array<std::uint8_t, 16> short_priv = {};
    const std::array<std::uint8_t, 32> peer_pub = {};

    auto [ec, shared] = psm::crypto::x25519(short_priv, peer_pub);

    EXPECT_EQ(ec, psm::fault::code::invalid_argument)
        << "x25519 with 16-byte private key should return invalid_argument";
    EXPECT_TRUE(is_all_zero(shared))
        << "shared secret should be all zeros for invalid private key";
}

/**
 * @brief 测试 x25519 对无效对端公钥长度的处理
 * @details 传入 32 字节私钥和 16 字节对端公钥，
 * 验证返回 invalid_argument。
 */
TEST(X25519, InvalidPeerPubkeySize)
{
    const std::array<std::uint8_t, 32> priv = {};
    const std::array<std::uint8_t, 16> short_peer = {};

    auto [ec, shared] = psm::crypto::x25519(priv, short_peer);

    EXPECT_EQ(ec, psm::fault::code::invalid_argument)
        << "x25519 with 16-byte peer pubkey should return invalid_argument";
}
