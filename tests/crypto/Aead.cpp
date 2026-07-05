/**
 * @file Aead.cpp
 * @brief AEAD 加密解密单元测试
 * @details 测试 psm::crypto::aead_context 的 AES-128/256-GCM 加解密功能，
 * 覆盖 seal/open 往返、错误密钥、篡改密文、AD 不匹配、nonce 自动递增、
 * 空明文、大载荷、移动语义、输出尺寸验证等场景。
 */

#include <gtest/gtest.h>

#include <prism/crypto/aead.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/foundation/foundation.hpp>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

/**
 * @brief 测试 AES-128-GCM seal/open 往返
 */
TEST(Aead, SealOpenRoundtripAes128)
{
    const std::array<std::uint8_t, 16> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_128_gcm, key);

    const std::string plaintext = "Hello AES-128-GCM!";
    const auto pt_data = reinterpret_cast<const std::uint8_t *>(plaintext.data());
    const auto pt_span = std::span<const std::uint8_t>(pt_data, plaintext.size());

    // 使用显式 nonce 避免自增导致 seal/open nonce 不匹配
    const std::array<std::uint8_t, 12> nonce{};

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_size(pt_span.size()));
    auto ec = ctx.seal(psm::crypto::seal_input{ciphertext, pt_span, nonce, {}});
    ASSERT_FALSE(psm::fault::failed(ec)) << "seal failed";

    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_size(ciphertext.size()));
    ec = ctx.open(psm::crypto::open_input{decrypted, ciphertext, nonce, {}});
    ASSERT_FALSE(psm::fault::failed(ec)) << "open failed";

    EXPECT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0)
        << "decrypted data does not match original";
}

/**
 * @brief 测试 AES-256-GCM seal/open 往返
 */
TEST(Aead, SealOpenRoundtripAes256)
{
    const std::array<std::uint8_t, 32> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_256_gcm, key);

    const std::string plaintext = "Hello AES-256-GCM!";
    const auto pt_data = reinterpret_cast<const std::uint8_t *>(plaintext.data());
    const auto pt_span = std::span<const std::uint8_t>(pt_data, plaintext.size());

    // 使用显式 nonce 避免自增导致 seal/open nonce 不匹配
    const std::array<std::uint8_t, 12> nonce{};

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_size(pt_span.size()));
    auto ec = ctx.seal(psm::crypto::seal_input{ciphertext, pt_span, nonce, {}});
    ASSERT_FALSE(psm::fault::failed(ec)) << "seal failed";

    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_size(ciphertext.size()));
    ec = ctx.open(psm::crypto::open_input{decrypted, ciphertext, nonce, {}});
    ASSERT_FALSE(psm::fault::failed(ec)) << "open failed";

    EXPECT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0)
        << "decrypted data does not match original";
}

/**
 * @brief 测试错误密钥导致解密失败
 */
TEST(Aead, WrongKey)
{
    const std::array<std::uint8_t, 16> key_a = {};
    const std::array<std::uint8_t, 16> key_b = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    psm::crypto::aead_context ctx_a(psm::crypto::aead_cipher::aes_128_gcm, key_a);

    const std::string plaintext = "secret data";
    const auto pt_data = reinterpret_cast<const std::uint8_t *>(plaintext.data());
    const auto pt_span = std::span<const std::uint8_t>(pt_data, plaintext.size());

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_size(pt_span.size()));
    ctx_a.seal(ciphertext, pt_span);

    // 使用不同密钥解密
    psm::crypto::aead_context ctx_b(psm::crypto::aead_cipher::aes_128_gcm, key_b);
    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_size(ciphertext.size()));
    auto ec = ctx_b.open(decrypted, ciphertext);

    EXPECT_FALSE(psm::fault::succeeded(ec)) << "wrong key should produce crypto_error";
}

/**
 * @brief 测试篡改密文导致解密失败
 */
TEST(Aead, TamperedCiphertext)
{
    const std::array<std::uint8_t, 16> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_128_gcm, key);

    const std::string plaintext = "tamper test data here";
    const auto pt_data = reinterpret_cast<const std::uint8_t *>(plaintext.data());
    const auto pt_span = std::span<const std::uint8_t>(pt_data, plaintext.size());

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_size(pt_span.size()));
    ctx.seal(ciphertext, pt_span);

    // 篡改密文中的一个字节（跳过最后 16 字节的 tag，修改密文区域）
    ciphertext[0] ^= 0xFF;

    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_size(ciphertext.size()));
    auto ec = ctx.open(decrypted, ciphertext);

    EXPECT_FALSE(psm::fault::succeeded(ec)) << "tampered ciphertext should produce crypto_error";
}

/**
 * @brief 测试 AD 不匹配导致解密失败
 */
TEST(Aead, MissingAd)
{
    const std::array<std::uint8_t, 16> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_128_gcm, key);

    const std::string plaintext = "test with AD";
    const auto pt_data = reinterpret_cast<const std::uint8_t *>(plaintext.data());
    const auto pt_span = std::span<const std::uint8_t>(pt_data, plaintext.size());
    const std::array<std::uint8_t, 4> ad = {1, 2, 3, 4};

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_size(pt_span.size()));
    ctx.seal(ciphertext, pt_span, ad);

    // 不带 AD 解密
    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_size(ciphertext.size()));
    auto ec = ctx.open(decrypted, ciphertext);

    EXPECT_FALSE(psm::fault::succeeded(ec)) << "missing AD should produce crypto_error";
}

/**
 * @brief 测试 nonce 自动递增
 */
TEST(Aead, NonceAutoIncrement)
{
    const std::array<std::uint8_t, 16> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_128_gcm, key);

    const std::array<std::uint8_t, 4> plaintext = {0x01, 0x02, 0x03, 0x04};

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_size(plaintext.size()));
    std::vector<std::uint8_t> dummy(psm::crypto::aead_context::open_size(ciphertext.size()));

    // 验证 seal 自动递增 nonce
    auto nonce0 = ctx.nonce();
    ctx.seal(ciphertext, plaintext);
    auto nonce1 = ctx.nonce();

    EXPECT_NE(nonce0, nonce1) << "nonce should change after first seal";

    // 验证 open 自动递增 nonce
    // 用显式 nonce（匹配当前内部 nonce）seal 新密文，使 auto-nonce open 能成功并递增
    std::array<std::uint8_t, 12> seal_nonce;
    std::memcpy(seal_nonce.data(), nonce1.data(), 12);

    std::vector<std::uint8_t> ct2(psm::crypto::aead_context::seal_size(plaintext.size()));
    std::vector<std::uint8_t> dec2(psm::crypto::aead_context::open_size(ct2.size()));

    ctx.seal(psm::crypto::seal_input{ct2, plaintext, seal_nonce, {}});
    ctx.open(dec2, ct2);
    auto nonce2 = ctx.nonce();

    EXPECT_NE(nonce1, nonce2) << "nonce should change after open";
}

/**
 * @brief 测试空明文 seal/open
 */
TEST(Aead, EmptyPlaintext)
{
    const std::array<std::uint8_t, 16> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_128_gcm, key);

    const std::span<const std::uint8_t> empty_pt;
    const std::array<std::uint8_t, 12> nonce{};

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_size(0));
    auto ec = ctx.seal(psm::crypto::seal_input{ciphertext, empty_pt, nonce, {}});
    ASSERT_FALSE(psm::fault::failed(ec)) << "seal empty plaintext failed";

    // 空明文的密文应该只有 tag（16 字节）
    EXPECT_EQ(ciphertext.size(), 16) << "empty plaintext ciphertext should be 16 bytes (tag only)";

    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_size(ciphertext.size()));
    ec = ctx.open(psm::crypto::open_input{decrypted, ciphertext, nonce, {}});
    ASSERT_FALSE(psm::fault::failed(ec)) << "open empty ciphertext failed";

    EXPECT_TRUE(decrypted.empty()) << "decrypted empty plaintext should be empty";
}

/**
 * @brief 测试大载荷 seal/open
 */
TEST(Aead, LargePayload)
{
    const std::array<std::uint8_t, 16> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_128_gcm, key);

    // 16KB 载荷
    std::vector<std::uint8_t> plaintext(16384);
    for (std::size_t i = 0; i < plaintext.size(); ++i)
    {
        plaintext[i] = static_cast<std::uint8_t>(i & 0xFF);
    }

    const std::array<std::uint8_t, 12> nonce{};

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_size(plaintext.size()));
    auto ec = ctx.seal(psm::crypto::seal_input{ciphertext, plaintext, nonce, {}});
    ASSERT_FALSE(psm::fault::failed(ec)) << "seal large payload failed";

    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_size(ciphertext.size()));
    ec = ctx.open(psm::crypto::open_input{decrypted, ciphertext, nonce, {}});
    ASSERT_FALSE(psm::fault::failed(ec)) << "open large payload failed";

    EXPECT_EQ(decrypted, plaintext) << "large payload roundtrip mismatch";
}

/**
 * @brief 测试移动语义
 */
TEST(Aead, MoveSemantics)
{
    const std::array<std::uint8_t, 16> key = {};
    auto ctx1 = std::make_unique<psm::crypto::aead_context>(psm::crypto::aead_cipher::aes_128_gcm, key);

    const std::string plaintext = "move test";
    const auto pt_data = reinterpret_cast<const std::uint8_t *>(plaintext.data());
    const auto pt_span = std::span<const std::uint8_t>(pt_data, plaintext.size());
    const std::array<std::uint8_t, 12> nonce{};

    // 移动构造
    psm::crypto::aead_context ctx2(std::move(*ctx1));
    ctx1.reset();

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_size(pt_span.size()));
    auto ec = ctx2.seal(psm::crypto::seal_input{ciphertext, pt_span, nonce, {}});
    ASSERT_FALSE(psm::fault::failed(ec)) << "seal after move-construct failed";

    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_size(ciphertext.size()));
    ec = ctx2.open(psm::crypto::open_input{decrypted, ciphertext, nonce, {}});
    ASSERT_FALSE(psm::fault::failed(ec)) << "open after move-construct failed";

    // 移动赋值
    const std::array<std::uint8_t, 16> key2 = {0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD,
                                               0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD};
    psm::crypto::aead_context ctx3(psm::crypto::aead_cipher::aes_128_gcm, key2);
    ctx3 = std::move(ctx2);

    // ctx3 应该继承 ctx2 的密钥，继续正常工作
    std::array<std::uint8_t, 12> nonce2{};
    nonce2[11] = 1;
    std::vector<std::uint8_t> ct2(psm::crypto::aead_context::seal_size(pt_span.size()));
    ec = ctx3.seal(psm::crypto::seal_input{ct2, pt_span, nonce2, {}});
    EXPECT_FALSE(psm::fault::failed(ec)) << "seal after move-assign failed";
}

/**
 * @brief 测试输出尺寸计算
 */
TEST(Aead, OutputSizeValidation)
{
    // seal_size(n) = n + 16
    EXPECT_EQ(psm::crypto::aead_context::seal_size(100), 116);

    // open_size(n + 16) = n
    EXPECT_EQ(psm::crypto::aead_context::open_size(116), 100);

    // tag_length = 16
    EXPECT_EQ(psm::crypto::aead_context::tag_length(), 16);

    // nonce_length = 12 (AES-GCM)
    const std::array<std::uint8_t, 16> tmp_key{};
    psm::crypto::aead_context ctx128(psm::crypto::aead_cipher::aes_128_gcm, tmp_key);
    EXPECT_EQ(ctx128.nonce_length(), 12) << "nonce_length should be 12 for AES-GCM";
}

/**
 * @brief 测试无效加密算法构造
 * @details 使用非法的 cipher 枚举值构造 aead_context，
 * 验证 seal/open 均返回 crypto_error。
 */
TEST(Aead, InvalidCipher)
{
    const std::array<std::uint8_t, 32> key = {};
    psm::crypto::aead_context ctx(static_cast<psm::crypto::aead_cipher>(99), key);

    const std::array<std::uint8_t, 16> plaintext = {};
    const std::array<std::uint8_t, 12> nonce{};
    const std::array<std::uint8_t, 16> ciphertext = {};

    std::vector<std::uint8_t> out_ciphertext(psm::crypto::aead_context::seal_size(plaintext.size()));
    auto seal_ec = ctx.seal(psm::crypto::seal_input{out_ciphertext, plaintext, nonce, {}});
    EXPECT_EQ(seal_ec, psm::fault::code::crypto_error)
        << "seal on invalid cipher should return crypto_error";

    std::vector<std::uint8_t> out_plaintext(psm::crypto::aead_context::open_size(ciphertext.size()));
    auto open_ec = ctx.open(psm::crypto::open_input{out_plaintext, ciphertext, nonce, {}});
    EXPECT_EQ(open_ec, psm::fault::code::crypto_error)
        << "open on invalid cipher should return crypto_error";
}

/**
 * @brief 测试 ChaCha20-Poly1305 seal/open 往返
 */
TEST(Aead, ChaCha20Roundtrip)
{
    const std::array<std::uint8_t, 32> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::chacha20_poly1305, key);

    EXPECT_EQ(ctx.nonce_length(), 12) << "ChaCha20 nonce_length should be 12";

    const std::string plaintext = "Hello ChaCha20-Poly1305!";
    const auto pt_data = reinterpret_cast<const std::uint8_t *>(plaintext.data());
    const auto pt_span = std::span<const std::uint8_t>(pt_data, plaintext.size());
    const std::array<std::uint8_t, 12> nonce{};

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_size(pt_span.size()));
    auto ec = ctx.seal(psm::crypto::seal_input{ciphertext, pt_span, nonce, {}});
    ASSERT_FALSE(psm::fault::failed(ec)) << "ChaCha20 seal failed";

    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_size(ciphertext.size()));
    ec = ctx.open(psm::crypto::open_input{decrypted, ciphertext, nonce, {}});
    ASSERT_FALSE(psm::fault::failed(ec)) << "ChaCha20 open failed";

    EXPECT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0)
        << "ChaCha20 decrypted data does not match original";
}

/**
 * @brief 测试 XChaCha20-Poly1305 seal/open 往返
 */
TEST(Aead, XChaCha20Roundtrip)
{
    const std::array<std::uint8_t, 32> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::xchacha20_poly1305, key);

    EXPECT_EQ(ctx.nonce_length(), 24) << "XChaCha20 nonce_length should be 24";

    const std::string plaintext = "Hello XChaCha20-Poly1305!";
    const auto pt_data = reinterpret_cast<const std::uint8_t *>(plaintext.data());
    const auto pt_span = std::span<const std::uint8_t>(pt_data, plaintext.size());
    const std::array<std::uint8_t, 24> nonce{};

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_size(pt_span.size()));
    auto ec = ctx.seal(psm::crypto::seal_input{ciphertext, pt_span, nonce, {}});
    ASSERT_FALSE(psm::fault::failed(ec)) << "XChaCha20 seal failed";

    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_size(ciphertext.size()));
    ec = ctx.open(psm::crypto::open_input{decrypted, ciphertext, nonce, {}});
    ASSERT_FALSE(psm::fault::failed(ec)) << "XChaCha20 open failed";

    EXPECT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0)
        << "XChaCha20 decrypted data does not match original";
}
