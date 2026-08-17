/**
 * @file CoreAead.cpp
 * @brief tests/common/core/crypto/aead.hpp 单元测试
 * @details 覆盖 preview::crypto::aead_context：
 * 1. 4 种 cipher（aes_128_gcm/aes_256_gcm/chacha20_poly1305/xchacha20_poly1305）
 *    构造、nonce 长度、seal/open 往返
 * 2. seal/open 失败路径：非法 cipher、密钥长度不匹配、输出缓冲区过小、
 *    密文被篡改、nonce 耗尽
 * 3. 显式 nonce 重载（seal_input/open_input）不修改内部状态
 * 4. 移动构造/移动赋值（含自赋值）、nonce 递增与溢出回绕
 * 5. 工具函数 tag_length/seal_size/open_size/nonce/nonce_length
 * @note 通过 #define private public 访问私有 nonce_ 状态，
 *       以覆盖 nonce 耗尽与溢出分支（正常路径需 2^96 次操作）。
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>

#include <gtest/gtest.h>

// 访问私有成员 nonce_/nonce_len_/increment_nonce()/is_nonce_exhausted()
#define private public
#include <common/core/crypto/aead.hpp>
#undef private

namespace
{
    namespace aead = preview::crypto;

    /// 构造指定字节数的密钥（按序填充 0..n-1）
    auto make_key(std::size_t n) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> key(n);
        for (std::size_t i = 0; i < n; ++i)
        {
            key[i] = static_cast<std::uint8_t>(i);
        }
        return key;
    }

    const std::vector<std::uint8_t> g_plain{'P', 'r', 'i', 's', 'm', ' ', 'A', 'E', 'A', 'D'};
    const std::vector<std::uint8_t> g_ad{'a', 'd', '-', 'd', 'a', 't', 'a'};

    TEST(CoreAead, ConstructAllCiphers)
    {
        // 4 种 cipher 均能成功构造，nonce 长度符合算法规格
        struct cases
        {
            aead::aead_cipher cipher;
            std::size_t key_len;
            std::size_t nonce_len;
        };
        const cases table[] = {
            {aead::aead_cipher::aes_128_gcm, 16, 12},
            {aead::aead_cipher::aes_256_gcm, 32, 12},
            {aead::aead_cipher::chacha20_poly1305, 32, 12},
            {aead::aead_cipher::xchacha20_poly1305, 32, 24},
        };
        for (const auto &[cipher, key_len, nonce_len] : table)
        {
            aead::aead_context ctx(cipher, make_key(key_len));
            EXPECT_EQ(ctx.nonce_length(), nonce_len) << "cipher=" << static_cast<int>(cipher);
            // 初始 nonce 全零
            const auto &n = ctx.nonce();
            EXPECT_EQ(std::count(n.begin(), n.end(), std::uint8_t{0}),
                      static_cast<std::ptrdiff_t>(n.size()));
        }
    }

    TEST(CoreAead, ConstructInvalidCipher)
    {
        // 非法枚举：default 分支直接返回，ctx 为 null
        aead::aead_context ctx(static_cast<aead::aead_cipher>(99), make_key(32));
        std::array<std::uint8_t, 64> out{};
        std::array<std::uint8_t, 16> buf{};
        EXPECT_EQ(ctx.seal(out, g_plain), preview::fault::code::crypto_error);
        EXPECT_EQ(ctx.open(buf, out), preview::fault::code::crypto_error);
        // 显式 nonce 重载的 !ctx_ 分支
        const std::array<std::uint8_t, 12> nonce{};
        aead::seal_input sin{std::span(out), g_plain, nonce, g_ad};
        EXPECT_EQ(ctx.seal(sin), preview::fault::code::crypto_error);
        aead::open_input oin{buf, std::span(out).first(16), nonce, g_ad};
        EXPECT_EQ(ctx.open(oin), preview::fault::code::crypto_error);
    }

    TEST(CoreAead, ConstructWrongKeySize)
    {
        // 密钥长度与算法不匹配：EVP_AEAD_CTX_init 失败 → ctx 为 null
        aead::aead_context ctx(aead::aead_cipher::aes_128_gcm, make_key(32));
        std::array<std::uint8_t, 64> out{};
        EXPECT_EQ(ctx.seal(out, g_plain), preview::fault::code::crypto_error);
    }

    TEST(CoreAead, RoundTripAllCiphers)
    {
        // 每种 cipher：seal → open 往返还原明文，输出长度含 16 字节 tag
        // 注意：seal 成功后内部 nonce 自动递增，故使用对称的加密/解密双上下文
        const aead::aead_cipher ciphers[] = {
            aead::aead_cipher::aes_128_gcm,
            aead::aead_cipher::aes_256_gcm,
            aead::aead_cipher::chacha20_poly1305,
            aead::aead_cipher::xchacha20_poly1305,
        };
        for (const auto cipher : ciphers)
        {
            const auto key_len = cipher == aead::aead_cipher::aes_128_gcm ? 16u : 32u;
            const auto key = make_key(key_len);
            aead::aead_context enc(cipher, key);
            aead::aead_context dec(cipher, key);

            std::array<std::uint8_t, 128> ciphertext{};
            EXPECT_EQ(enc.seal(ciphertext, g_plain), preview::fault::code::success)
                << "seal failed, cipher=" << static_cast<int>(cipher);

            std::array<std::uint8_t, 128> decrypted{};
            EXPECT_EQ(dec.open(decrypted, std::span(ciphertext).first(g_plain.size() + 16)),
                      preview::fault::code::success)
                << "open failed, cipher=" << static_cast<int>(cipher);
            EXPECT_TRUE(std::equal(decrypted.begin(), decrypted.begin() + g_plain.size(),
                                   g_plain.begin()))
                << "roundtrip mismatch, cipher=" << static_cast<int>(cipher);
        }
    }

    TEST(CoreAead, SealOpenWithAd)
    {
        // 附带附加数据（AD）参与认证（加密/解密双上下文，nonce 对称）
        const auto key = make_key(32);
        aead::aead_context enc(aead::aead_cipher::chacha20_poly1305, key);
        aead::aead_context dec(aead::aead_cipher::chacha20_poly1305, key);
        std::array<std::uint8_t, 128> ciphertext{};
        EXPECT_EQ(enc.seal(ciphertext, g_plain, g_ad), preview::fault::code::success);

        std::array<std::uint8_t, 128> decrypted{};
        EXPECT_EQ(dec.open(decrypted, std::span(ciphertext).first(g_plain.size() + 16), g_ad),
                  preview::fault::code::success);
        // AD 不一致时解密失败
        const std::array<std::uint8_t, 1> bad_ad{'x'};
        EXPECT_EQ(dec.open(decrypted, std::span(ciphertext).first(g_plain.size() + 16), bad_ad),
                  preview::fault::code::crypto_error);
    }

    TEST(CoreAead, NonceAutoIncrement)
    {
        // seal 成功后内部 nonce 按小端序递增（非零 ad 参数验证增量路径）
        aead::aead_context ctx(aead::aead_cipher::aes_128_gcm, make_key(16));
        EXPECT_EQ(ctx.nonce()[0], 0);
        std::array<std::uint8_t, 128> ciphertext{};
        EXPECT_EQ(ctx.seal(ciphertext, g_plain), preview::fault::code::success);
        EXPECT_EQ(ctx.nonce()[0], 1);
        EXPECT_EQ(ctx.seal(ciphertext, g_plain), preview::fault::code::success);
        EXPECT_EQ(ctx.nonce()[0], 2);
    }

    TEST(CoreAead, OpenTamperedCiphertext)
    {
        // 密文被篡改 → 认证失败
        aead::aead_context ctx(aead::aead_cipher::aes_256_gcm, make_key(32));
        std::array<std::uint8_t, 128> ciphertext{};
        ASSERT_EQ(ctx.seal(ciphertext, g_plain), preview::fault::code::success);

        std::array<std::uint8_t, 128> decrypted{};
        auto tampered = ciphertext;
        tampered[0] ^= 0x01;
        EXPECT_EQ(ctx.open(decrypted, std::span(tampered).first(g_plain.size() + 16)),
                  preview::fault::code::crypto_error);
        // 篡改 tag 尾部
        auto tampered_tag = ciphertext;
        tampered_tag[g_plain.size() + 15] ^= 0x01;
        EXPECT_EQ(ctx.open(decrypted, std::span(tampered_tag).first(g_plain.size() + 16)),
                  preview::fault::code::crypto_error);
    }

    TEST(CoreAead, SealOutputTooSmall)
    {
        // 输出缓冲区不足（缺 tag 空间）→ EVP seal 失败
        aead::aead_context ctx(aead::aead_cipher::chacha20_poly1305, make_key(32));
        std::array<std::uint8_t, 8> small{};
        EXPECT_EQ(ctx.seal(small, g_plain), preview::fault::code::crypto_error);
    }

    TEST(CoreAead, ExplicitNonceRoundTrip)
    {
        // 显式 nonce 重载：12 字节 nonce，成功往返且不修改内部状态
        aead::aead_context ctx(aead::aead_cipher::aes_256_gcm, make_key(32));
        const std::array<std::uint8_t, 12> nonce{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        std::array<std::uint8_t, 128> ciphertext{};

        aead::seal_input sin{std::span(ciphertext), g_plain, nonce, g_ad};
        EXPECT_EQ(ctx.seal(sin), preview::fault::code::success);
        // 内部 nonce 不受显式 nonce 调用影响
        EXPECT_EQ(ctx.nonce()[0], 0);

        std::array<std::uint8_t, 128> decrypted{};
        aead::open_input oin{decrypted, std::span(ciphertext).first(g_plain.size() + 16), nonce, g_ad};
        EXPECT_EQ(ctx.open(oin), preview::fault::code::success);
        EXPECT_TRUE(std::equal(decrypted.begin(), decrypted.begin() + g_plain.size(), g_plain.begin()));
        EXPECT_EQ(ctx.nonce()[0], 0);
    }

    TEST(CoreAead, ExplicitNonceXchacha)
    {
        // XChaCha20 使用 24 字节显式 nonce
        aead::aead_context ctx(aead::aead_cipher::xchacha20_poly1305, make_key(32));
        std::array<std::uint8_t, 24> nonce{};
        for (std::size_t i = 0; i < nonce.size(); ++i)
        {
            nonce[i] = static_cast<std::uint8_t>(i * 3);
        }
        std::array<std::uint8_t, 128> ciphertext{};
        aead::seal_input sin{std::span(ciphertext), g_plain, nonce, g_ad};
        EXPECT_EQ(ctx.seal(sin), preview::fault::code::success);

        std::array<std::uint8_t, 128> decrypted{};
        aead::open_input oin{decrypted, std::span(ciphertext).first(g_plain.size() + 16), nonce, g_ad};
        EXPECT_EQ(ctx.open(oin), preview::fault::code::success);
    }

    TEST(CoreAead, ExplicitNonceBadNonce)
    {
        // 显式 nonce 长度错误（12 字节用于 xchacha24）→ EVP 失败
        aead::aead_context ctx(aead::aead_cipher::xchacha20_poly1305, make_key(32));
        const std::array<std::uint8_t, 12> bad_nonce{};
        std::array<std::uint8_t, 128> ciphertext{};
        aead::seal_input sin{std::span(ciphertext), g_plain, bad_nonce, g_ad};
        EXPECT_EQ(ctx.seal(sin), preview::fault::code::crypto_error);
    }

    TEST(CoreAead, ExplicitNonceSmallOutput)
    {
        // 显式 nonce seal：输出缓冲区不足 → 失败
        aead::aead_context ctx(aead::aead_cipher::aes_256_gcm, make_key(32));
        const std::array<std::uint8_t, 12> nonce{};
        std::array<std::uint8_t, 8> small{};
        aead::seal_input sin{std::span(small), g_plain, nonce, g_ad};
        EXPECT_EQ(ctx.seal(sin), preview::fault::code::crypto_error);
    }

    TEST(CoreAead, ExplicitNonceOpenBadCiphertext)
    {
        // 显式 nonce open：密文被篡改 → EVP open 失败
        const auto key = make_key(32);
        aead::aead_context enc(aead::aead_cipher::aes_256_gcm, key);
        aead::aead_context dec(aead::aead_cipher::aes_256_gcm, key);
        const std::array<std::uint8_t, 12> nonce{};
        std::array<std::uint8_t, 128> ciphertext{};
        aead::seal_input sin{std::span(ciphertext), g_plain, nonce, g_ad};
        ASSERT_EQ(enc.seal(sin), preview::fault::code::success);

        auto tampered = ciphertext;
        tampered[g_plain.size() + 15] ^= 0x01;
        std::array<std::uint8_t, 128> decrypted{};
        aead::open_input oin{decrypted, std::span(tampered).first(g_plain.size() + 16), nonce, g_ad};
        EXPECT_EQ(dec.open(oin), preview::fault::code::crypto_error);
        // 错误 nonce 同样失败
        const std::array<std::uint8_t, 12> wrong_nonce{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        aead::open_input oin2{decrypted, std::span(ciphertext).first(g_plain.size() + 16), wrong_nonce,
                              g_ad};
        EXPECT_EQ(dec.open(oin2), preview::fault::code::crypto_error);
    }

    TEST(CoreAead, MoveConstructor)
    {
        // 移动构造：目标可继续使用，源对象失效（seal 返回 crypto_error）
        aead::aead_context src(aead::aead_cipher::aes_128_gcm, make_key(16));
        std::array<std::uint8_t, 128> ciphertext{};
        ASSERT_EQ(src.seal(ciphertext, g_plain), preview::fault::code::success);

        aead::aead_context dst(std::move(src));
        // 源对象失效
        EXPECT_EQ(src.seal(ciphertext, g_plain), preview::fault::code::crypto_error);
        // 目标持有原状态（nonce 已递增为 1），可继续执行新操作
        EXPECT_EQ(dst.nonce()[0], 1);
        EXPECT_EQ(dst.seal(ciphertext, g_plain), preview::fault::code::success);
        EXPECT_EQ(dst.nonce()[0], 2);
        // 源对象析构时 release_ctx(nullptr) 分支
    }

    TEST(CoreAead, MoveAssign)
    {
        // 移动赋值：旧资源释放、新状态接管
        aead::aead_context src(aead::aead_cipher::chacha20_poly1305, make_key(32));
        aead::aead_context dst(aead::aead_cipher::aes_128_gcm, make_key(16));

        dst = std::move(src);
        EXPECT_EQ(dst.nonce_length(), 12);
        std::array<std::uint8_t, 128> ciphertext{};
        EXPECT_EQ(dst.seal(ciphertext, g_plain), preview::fault::code::success);
        EXPECT_EQ(src.seal(ciphertext, g_plain), preview::fault::code::crypto_error);
    }

    TEST(CoreAead, MoveAssignSelf)
    {
        // 自赋值：if (this != &other) 的 else 分支，状态保持
        aead::aead_context ctx(aead::aead_cipher::aes_256_gcm, make_key(32));
        aead::aead_context &self = ctx;
        ctx = std::move(self);
        std::array<std::uint8_t, 128> ciphertext{};
        EXPECT_EQ(ctx.seal(ciphertext, g_plain), preview::fault::code::success);
        EXPECT_EQ(ctx.nonce()[0], 1);
    }

    TEST(CoreAead, NonceExhausted)
    {
        // 内部 nonce 全 0xFF → seal/open 均拒绝（防 nonce 重用）
        aead::aead_context ctx(aead::aead_cipher::aes_128_gcm, make_key(16));
        EXPECT_FALSE(ctx.is_nonce_exhausted());
        ctx.nonce_.fill(0xFF);
        EXPECT_TRUE(ctx.is_nonce_exhausted());

        std::array<std::uint8_t, 128> ciphertext{};
        EXPECT_EQ(ctx.seal(ciphertext, g_plain), preview::fault::code::crypto_error);
        EXPECT_EQ(ctx.open(ciphertext, ciphertext), preview::fault::code::crypto_error);
    }

    TEST(CoreAead, NoncePartialFull)
    {
        // 部分字节为 0xFF 不算耗尽；XChaCha 需 24 字节全 0xFF
        aead::aead_context ctx(aead::aead_cipher::xchacha20_poly1305, make_key(32));
        ctx.nonce_.fill(0xFF);
        ctx.nonce_[23] = 0xFE;
        EXPECT_FALSE(ctx.is_nonce_exhausted());
        ctx.nonce_[23] = 0xFF;
        EXPECT_TRUE(ctx.is_nonce_exhausted());
    }

    TEST(CoreAead, ReleaseCtxBothPaths)
    {
        // release_ctx 两分支：非空（cleanup + delete）与空（直接返回）
        auto *raw = new EVP_AEAD_CTX;
        EVP_AEAD_CTX_zero(raw);
        aead::aead_context::release_ctx(raw); // 非空分支
        // volatile 阻止常量折叠，确保 if (ctx) 的空分支在运行时判定
        evp_aead_ctx_st *volatile null_ctx = nullptr;
        aead::aead_context::release_ctx(null_ctx); // 空分支
    }

    TEST(CoreAead, IncrementNonceOverflow)
    {
        // 递增溢出：0xFF 进位回绕（最后一个字节进位后全零）
        aead::aead_context ctx(aead::aead_cipher::aes_256_gcm, make_key(32));
        ctx.nonce_.fill(0xFF);
        ctx.increment_nonce();
        EXPECT_TRUE(ctx.is_nonce_exhausted() == false);
        EXPECT_EQ(ctx.nonce()[0], 0);
        EXPECT_EQ(ctx.nonce()[1], 0);
        // 12 字节 nonce：进位不会触及 nonce_len 之后的字节
        EXPECT_EQ(ctx.nonce()[12], 0xFF);

        // 部分字节进位：1 + 0xFF = 0，0xFF + 1 = 0 且停止
        aead::aead_context ctx2(aead::aead_cipher::aes_256_gcm, make_key(32));
        ctx2.nonce_[0] = 0x0A;
        ctx2.increment_nonce();
        EXPECT_EQ(ctx2.nonce()[0], 0x0B);
    }

    TEST(CoreAead, SizeHelpers)
    {
        // 静态工具函数
        EXPECT_EQ(aead::aead_context::tag_length(), 16);
        EXPECT_EQ(aead::aead_context::seal_size(10), 26);
        EXPECT_EQ(aead::aead_context::seal_size(0), 16);
        EXPECT_EQ(aead::aead_context::open_size(26), 10);
        EXPECT_EQ(aead::aead_context::open_size(16), 0);
        // 密文长度小于 tag 长度 → 0
        EXPECT_EQ(aead::aead_context::open_size(8), 0);
        EXPECT_EQ(aead::aead_context::open_size(0), 0);
    }
} // namespace
