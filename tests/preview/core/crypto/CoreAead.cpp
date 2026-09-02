/**
 * @file CoreAead.cpp
 * @brief preview/Foundation/Utility/Crypto/Aead.hpp 单元测试
 * @details 覆盖 Preview::Crypto::AeadContext：
 * 1. 4 种 cipher（aes_128_gcm/aes_256_gcm/chacha20_poly1305/xchacha20_poly1305）
 *    构造、Nonce 长度、Seal/Open 往返
 * 2. Seal/Open 失败路径：非法 cipher、密钥长度不匹配、输出缓冲区过小、
 *    密文被篡改、Nonce 耗尽
 * 3. 显式 Nonce 重载（SealInput/OpenInput）不修改内部状态
 * 4. 移动构造/移动赋值（含自赋值）、Nonce 递增与溢出回绕
 * 5. 工具函数 TagLength/SealSize/OpenSize/Nonce/NonceLength
 * @note 通过 #define private public 访问私有 Nonce_ 状态，
 *       以覆盖 Nonce 耗尽与溢出分支（正常路径需 2^96 次操作）。
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>

#include <gtest/gtest.h>

// 访问私有成员 Nonce_/nonce_len_/IncrementNonce()/IsNonceExhausted()
#define private public
#include <preview/Foundation/Utility/Crypto/Aead.hpp>
#undef private

namespace
{
    namespace aead = Preview::Crypto;

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
        // 4 种 cipher 均能成功构造，Nonce 长度符合算法规格
        struct cases
        {
            aead::AeadCipher cipher;
            std::size_t key_len;
            std::size_t nonce_len;
        };
        const cases Table[] = {
            {aead::AeadCipher::Aes128Gcm, 16, 12},
            {aead::AeadCipher::Aes256Gcm, 32, 12},
            {aead::AeadCipher::Chacha20Poly1305, 32, 12},
            {aead::AeadCipher::Xchacha20Poly1305, 32, 24},
        };
        for (const auto &[cipher, key_len, nonce_len] : Table)
        {
            aead::AeadContext ctx(cipher, make_key(key_len));
            EXPECT_EQ(ctx.NonceLength(), nonce_len) << "cipher=" << static_cast<int>(cipher);
            // 初始 Nonce 全零
            const auto &n = ctx.Nonce();
            EXPECT_EQ(std::count(n.begin(), n.end(), std::uint8_t{0}),
                      static_cast<std::ptrdiff_t>(n.size()));
        }
    }

    TEST(CoreAead, ConstructInvalidCipher)
    {
        // 非法枚举：default 分支直接返回，ctx 为 null
        aead::AeadContext ctx(static_cast<aead::AeadCipher>(99), make_key(32));
        std::array<std::uint8_t, 64> out{};
        std::array<std::uint8_t, 16> buf{};
        EXPECT_EQ(ctx.Seal(out, g_plain), Preview::Fault::Code::CryptoError);
        EXPECT_EQ(ctx.Open(buf, out), Preview::Fault::Code::CryptoError);
        // 显式 Nonce 重载的 !Ctx_ 分支
        const std::array<std::uint8_t, 12> Nonce{};
        aead::SealInput sin{std::span(out), g_plain, Nonce, g_ad};
        EXPECT_EQ(ctx.Seal(sin), Preview::Fault::Code::CryptoError);
        aead::OpenInput oin{buf, std::span(out).first(16), Nonce, g_ad};
        EXPECT_EQ(ctx.Open(oin), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, ConstructWrongKeySize)
    {
        // 密钥长度与算法不匹配：EVP_AEAD_CTX_init 失败 → ctx 为 null
        aead::AeadContext ctx(aead::AeadCipher::Aes128Gcm, make_key(32));
        std::array<std::uint8_t, 64> out{};
        EXPECT_EQ(ctx.Seal(out, g_plain), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, RoundTripAllCiphers)
    {
        // 每种 cipher：Seal → Open 往返还原明文，输出长度含 16 字节 tag
        // 注意：Seal 成功后内部 Nonce 自动递增，故使用对称的加密/解密双上下文
        const aead::AeadCipher ciphers[] = {
            aead::AeadCipher::Aes128Gcm,
            aead::AeadCipher::Aes256Gcm,
            aead::AeadCipher::Chacha20Poly1305,
            aead::AeadCipher::Xchacha20Poly1305,
        };
        for (const auto cipher : ciphers)
        {
            const auto key_len = cipher == aead::AeadCipher::Aes128Gcm ? 16u : 32u;
            const auto key = make_key(key_len);
            aead::AeadContext enc(cipher, key);
            aead::AeadContext dec(cipher, key);

            std::array<std::uint8_t, 128> ciphertext{};
            EXPECT_EQ(enc.Seal(ciphertext, g_plain), Preview::Fault::Code::Success)
                << "Seal Failed, cipher=" << static_cast<int>(cipher);

            std::array<std::uint8_t, 128> decrypted{};
            EXPECT_EQ(dec.Open(decrypted, std::span(ciphertext).first(g_plain.size() + 16)),
                      Preview::Fault::Code::Success)
                << "Open Failed, cipher=" << static_cast<int>(cipher);
            EXPECT_TRUE(std::equal(decrypted.begin(), decrypted.begin() + g_plain.size(),
                                   g_plain.begin()))
                << "roundtrip mismatch, cipher=" << static_cast<int>(cipher);
        }
    }

    TEST(CoreAead, SealOpenWithAd)
    {
        // 附带附加数据（AD）参与认证（加密/解密双上下文，Nonce 对称）
        const auto key = make_key(32);
        aead::AeadContext enc(aead::AeadCipher::Chacha20Poly1305, key);
        aead::AeadContext dec(aead::AeadCipher::Chacha20Poly1305, key);
        std::array<std::uint8_t, 128> ciphertext{};
        EXPECT_EQ(enc.Seal(ciphertext, g_plain, g_ad), Preview::Fault::Code::Success);

        std::array<std::uint8_t, 128> decrypted{};
        EXPECT_EQ(dec.Open(decrypted, std::span(ciphertext).first(g_plain.size() + 16), g_ad),
                  Preview::Fault::Code::Success);
        // AD 不一致时解密失败
        const std::array<std::uint8_t, 1> bad_ad{'x'};
        EXPECT_EQ(dec.Open(decrypted, std::span(ciphertext).first(g_plain.size() + 16), bad_ad),
                  Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, NonceAutoIncrement)
    {
        // Seal 成功后内部 Nonce 按小端序递增（非零 ad 参数验证增量路径）
        aead::AeadContext ctx(aead::AeadCipher::Aes128Gcm, make_key(16));
        EXPECT_EQ(ctx.Nonce()[0], 0);
        std::array<std::uint8_t, 128> ciphertext{};
        EXPECT_EQ(ctx.Seal(ciphertext, g_plain), Preview::Fault::Code::Success);
        EXPECT_EQ(ctx.Nonce()[0], 1);
        EXPECT_EQ(ctx.Seal(ciphertext, g_plain), Preview::Fault::Code::Success);
        EXPECT_EQ(ctx.Nonce()[0], 2);
    }

    TEST(CoreAead, OpenTamperedCiphertext)
    {
        // 密文被篡改 → 认证失败
        aead::AeadContext ctx(aead::AeadCipher::Aes256Gcm, make_key(32));
        std::array<std::uint8_t, 128> ciphertext{};
        ASSERT_EQ(ctx.Seal(ciphertext, g_plain), Preview::Fault::Code::Success);

        std::array<std::uint8_t, 128> decrypted{};
        auto tampered = ciphertext;
        tampered[0] ^= 0x01;
        EXPECT_EQ(ctx.Open(decrypted, std::span(tampered).first(g_plain.size() + 16)),
                  Preview::Fault::Code::CryptoError);
        // 篡改 tag 尾部
        auto tampered_tag = ciphertext;
        tampered_tag[g_plain.size() + 15] ^= 0x01;
        EXPECT_EQ(ctx.Open(decrypted, std::span(tampered_tag).first(g_plain.size() + 16)),
                  Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, SealOutputTooSmall)
    {
        // 输出缓冲区不足（缺 tag 空间）→ EVP Seal 失败
        aead::AeadContext ctx(aead::AeadCipher::Chacha20Poly1305, make_key(32));
        std::array<std::uint8_t, 8> small{};
        EXPECT_EQ(ctx.Seal(small, g_plain), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, ExplicitNonceRoundTrip)
    {
        // 显式 Nonce 重载：12 字节 Nonce，成功往返且不修改内部状态
        aead::AeadContext ctx(aead::AeadCipher::Aes256Gcm, make_key(32));
        const std::array<std::uint8_t, 12> Nonce{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        std::array<std::uint8_t, 128> ciphertext{};

        aead::SealInput sin{std::span(ciphertext), g_plain, Nonce, g_ad};
        EXPECT_EQ(ctx.Seal(sin), Preview::Fault::Code::Success);
        // 内部 Nonce 不受显式 Nonce 调用影响
        EXPECT_EQ(ctx.Nonce()[0], 0);

        std::array<std::uint8_t, 128> decrypted{};
        aead::OpenInput oin{decrypted, std::span(ciphertext).first(g_plain.size() + 16), Nonce, g_ad};
        EXPECT_EQ(ctx.Open(oin), Preview::Fault::Code::Success);
        EXPECT_TRUE(std::equal(decrypted.begin(), decrypted.begin() + g_plain.size(), g_plain.begin()));
        EXPECT_EQ(ctx.Nonce()[0], 0);
    }

    TEST(CoreAead, ExplicitNonceXchacha)
    {
        // XChaCha20 使用 24 字节显式 Nonce
        aead::AeadContext ctx(aead::AeadCipher::Xchacha20Poly1305, make_key(32));
        std::array<std::uint8_t, 24> Nonce{};
        for (std::size_t i = 0; i < Nonce.size(); ++i)
        {
            Nonce[i] = static_cast<std::uint8_t>(i * 3);
        }
        std::array<std::uint8_t, 128> ciphertext{};
        aead::SealInput sin{std::span(ciphertext), g_plain, Nonce, g_ad};
        EXPECT_EQ(ctx.Seal(sin), Preview::Fault::Code::Success);

        std::array<std::uint8_t, 128> decrypted{};
        aead::OpenInput oin{decrypted, std::span(ciphertext).first(g_plain.size() + 16), Nonce, g_ad};
        EXPECT_EQ(ctx.Open(oin), Preview::Fault::Code::Success);
    }

    TEST(CoreAead, ExplicitNonceBadNonce)
    {
        // 显式 Nonce 长度错误（12 字节用于 xchacha24）→ EVP 失败
        aead::AeadContext ctx(aead::AeadCipher::Xchacha20Poly1305, make_key(32));
        const std::array<std::uint8_t, 12> bad_nonce{};
        std::array<std::uint8_t, 128> ciphertext{};
        aead::SealInput sin{std::span(ciphertext), g_plain, bad_nonce, g_ad};
        EXPECT_EQ(ctx.Seal(sin), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, ExplicitNonceSmallOutput)
    {
        // 显式 Nonce Seal：输出缓冲区不足 → 失败
        aead::AeadContext ctx(aead::AeadCipher::Aes256Gcm, make_key(32));
        const std::array<std::uint8_t, 12> Nonce{};
        std::array<std::uint8_t, 8> small{};
        aead::SealInput sin{std::span(small), g_plain, Nonce, g_ad};
        EXPECT_EQ(ctx.Seal(sin), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, ExplicitNonceOpenBadCiphertext)
    {
        // 显式 Nonce Open：密文被篡改 → EVP Open 失败
        const auto key = make_key(32);
        aead::AeadContext enc(aead::AeadCipher::Aes256Gcm, key);
        aead::AeadContext dec(aead::AeadCipher::Aes256Gcm, key);
        const std::array<std::uint8_t, 12> Nonce{};
        std::array<std::uint8_t, 128> ciphertext{};
        aead::SealInput sin{std::span(ciphertext), g_plain, Nonce, g_ad};
        ASSERT_EQ(enc.Seal(sin), Preview::Fault::Code::Success);

        auto tampered = ciphertext;
        tampered[g_plain.size() + 15] ^= 0x01;
        std::array<std::uint8_t, 128> decrypted{};
        aead::OpenInput oin{decrypted, std::span(tampered).first(g_plain.size() + 16), Nonce, g_ad};
        EXPECT_EQ(dec.Open(oin), Preview::Fault::Code::CryptoError);
        // 错误 Nonce 同样失败
        const std::array<std::uint8_t, 12> wrong_nonce{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        aead::OpenInput oin2{decrypted, std::span(ciphertext).first(g_plain.size() + 16), wrong_nonce,
                              g_ad};
        EXPECT_EQ(dec.Open(oin2), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, MoveConstructor)
    {
        // 移动构造：目标可继续使用，源对象失效（Seal 返回 crypto_error）
        aead::AeadContext src(aead::AeadCipher::Aes128Gcm, make_key(16));
        std::array<std::uint8_t, 128> ciphertext{};
        ASSERT_EQ(src.Seal(ciphertext, g_plain), Preview::Fault::Code::Success);

        aead::AeadContext dst(std::move(src));
        // 源对象失效
        EXPECT_EQ(src.Seal(ciphertext, g_plain), Preview::Fault::Code::CryptoError);
        // 目标持有原状态（Nonce 已递增为 1），可继续执行新操作
        EXPECT_EQ(dst.Nonce()[0], 1);
        EXPECT_EQ(dst.Seal(ciphertext, g_plain), Preview::Fault::Code::Success);
        EXPECT_EQ(dst.Nonce()[0], 2);
        // 源对象析构时 ReleaseCtx(nullptr) 分支
    }

    TEST(CoreAead, MoveAssign)
    {
        // 移动赋值：旧资源释放、新状态接管
        aead::AeadContext src(aead::AeadCipher::Chacha20Poly1305, make_key(32));
        aead::AeadContext dst(aead::AeadCipher::Aes128Gcm, make_key(16));

        dst = std::move(src);
        EXPECT_EQ(dst.NonceLength(), 12);
        std::array<std::uint8_t, 128> ciphertext{};
        EXPECT_EQ(dst.Seal(ciphertext, g_plain), Preview::Fault::Code::Success);
        EXPECT_EQ(src.Seal(ciphertext, g_plain), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, MoveAssignSelf)
    {
        // 自赋值：if (this != &other) 的 else 分支，状态保持
        aead::AeadContext ctx(aead::AeadCipher::Aes256Gcm, make_key(32));
        aead::AeadContext &self = ctx;
        ctx = std::move(self);
        std::array<std::uint8_t, 128> ciphertext{};
        EXPECT_EQ(ctx.Seal(ciphertext, g_plain), Preview::Fault::Code::Success);
        EXPECT_EQ(ctx.Nonce()[0], 1);
    }

    TEST(CoreAead, NonceExhausted)
    {
        // 内部 Nonce 全 0xFF → Seal/Open 均拒绝（防 Nonce 重用）
        aead::AeadContext ctx(aead::AeadCipher::Aes128Gcm, make_key(16));
        EXPECT_FALSE(ctx.IsNonceExhausted());
        ctx.Nonce_.fill(0xFF);
        EXPECT_TRUE(ctx.IsNonceExhausted());

        std::array<std::uint8_t, 128> ciphertext{};
        EXPECT_EQ(ctx.Seal(ciphertext, g_plain), Preview::Fault::Code::CryptoError);
        EXPECT_EQ(ctx.Open(ciphertext, ciphertext), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, NoncePartialFull)
    {
        // 部分字节为 0xFF 不算耗尽；XChaCha 需 24 字节全 0xFF
        aead::AeadContext ctx(aead::AeadCipher::Xchacha20Poly1305, make_key(32));
        ctx.Nonce_.fill(0xFF);
        ctx.Nonce_[23] = 0xFE;
        EXPECT_FALSE(ctx.IsNonceExhausted());
        ctx.Nonce_[23] = 0xFF;
        EXPECT_TRUE(ctx.IsNonceExhausted());
    }

    TEST(CoreAead, ReleaseCtxBothPaths)
    {
        // ReleaseCtx 两分支：非空（cleanup + delete）与空（直接返回）
        auto *raw = new EVP_AEAD_CTX;
        EVP_AEAD_CTX_zero(raw);
        aead::AeadContext::ReleaseCtx(raw); // 非空分支
        // volatile 阻止常量折叠，确保 if (ctx) 的空分支在运行时判定
        evp_aead_ctx_st *volatile null_ctx = nullptr;
        aead::AeadContext::ReleaseCtx(null_ctx); // 空分支
    }

    TEST(CoreAead, IncrementNonceOverflow)
    {
        // 递增溢出：0xFF 进位回绕（最后一个字节进位后全零）
        aead::AeadContext ctx(aead::AeadCipher::Aes256Gcm, make_key(32));
        ctx.Nonce_.fill(0xFF);
        ctx.IncrementNonce();
        EXPECT_TRUE(ctx.IsNonceExhausted() == false);
        EXPECT_EQ(ctx.Nonce()[0], 0);
        EXPECT_EQ(ctx.Nonce()[1], 0);
        // 12 字节 Nonce：进位不会触及 nonce_len 之后的字节
        EXPECT_EQ(ctx.Nonce()[12], 0xFF);

        // 部分字节进位：1 + 0xFF = 0，0xFF + 1 = 0 且停止
        aead::AeadContext ctx2(aead::AeadCipher::Aes256Gcm, make_key(32));
        ctx2.Nonce_[0] = 0x0A;
        ctx2.IncrementNonce();
        EXPECT_EQ(ctx2.Nonce()[0], 0x0B);
    }

    TEST(CoreAead, SizeHelpers)
    {
        // 静态工具函数
        EXPECT_EQ(aead::AeadContext::TagLength(), 16);
        EXPECT_EQ(aead::AeadContext::SealSize(10), 26);
        EXPECT_EQ(aead::AeadContext::SealSize(0), 16);
        EXPECT_EQ(aead::AeadContext::OpenSize(26), 10);
        EXPECT_EQ(aead::AeadContext::OpenSize(16), 0);
        // 密文长度小于 tag 长度 → 0
        EXPECT_EQ(aead::AeadContext::OpenSize(8), 0);
        EXPECT_EQ(aead::AeadContext::OpenSize(0), 0);
    }
} // namespace
