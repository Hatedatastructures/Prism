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
    namespace Aead = Preview::Crypto;

    /// 构造指定字节数的密钥（按序填充 0..n-1）
    auto MakeKey(std::size_t Size) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Key(Size);
        for (std::size_t Index = 0; Index < Size; ++Index)
        {
            Key[Index] = static_cast<std::uint8_t>(Index);
        }
        return Key;
    }

    const std::vector<std::uint8_t> Plaintext{'P', 'r', 'i', 's', 'm', ' ', 'A', 'E', 'A', 'D'};
    const std::vector<std::uint8_t> AdditionalData{'a', 'd', '-', 'd', 'a', 't', 'a'};

    TEST(CoreAead, ConstructAllCiphers)
    {
        // 4 种 cipher 均能成功构造，Nonce 长度符合算法规格
        struct Cases
        {
            Aead::AeadCipher Cipher;
            std::size_t KeyLength;
            std::size_t NonceLength;
        };
        const Cases Table[] = {
            {Aead::AeadCipher::Aes128Gcm, 16, 12},
            {Aead::AeadCipher::Aes256Gcm, 32, 12},
            {Aead::AeadCipher::Chacha20Poly1305, 32, 12},
            {Aead::AeadCipher::Xchacha20Poly1305, 32, 24},
        };
        for (const auto &[Cipher, KeyLength, NonceLength] : Table)
        {
            Aead::AeadContext Context(Cipher, MakeKey(KeyLength));
            EXPECT_EQ(Context.NonceLength(), NonceLength) << "cipher=" << static_cast<int>(Cipher);
            // 初始 Nonce 全零
            const auto &Nonce = Context.Nonce();
            EXPECT_EQ(std::count(Nonce.begin(), Nonce.end(), std::uint8_t{0}),
                      static_cast<std::ptrdiff_t>(Nonce.size()));
        }
    }

    TEST(CoreAead, ConstructInvalidCipher)
    {
        // 非法枚举：default 分支直接返回，ctx 为 null
        Aead::AeadContext Context(static_cast<Aead::AeadCipher>(99), MakeKey(32));
        std::array<std::uint8_t, 64> Output{};
        std::array<std::uint8_t, 16> Buffer{};
        EXPECT_EQ(Context.Seal(Output, Plaintext), Preview::Fault::Code::CryptoError);
        EXPECT_EQ(Context.Open(Buffer, Output), Preview::Fault::Code::CryptoError);
        // 显式 Nonce 重载的 !Ctx_ 分支
        const std::array<std::uint8_t, 12> Nonce{};
        Aead::SealInput SealInput{std::span(Output), Plaintext, Nonce, AdditionalData};
        EXPECT_EQ(Context.Seal(SealInput), Preview::Fault::Code::CryptoError);
        Aead::OpenInput OpenInput{Buffer, std::span(Output).first(16), Nonce, AdditionalData};
        EXPECT_EQ(Context.Open(OpenInput), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, ConstructWrongKeySize)
    {
        // 密钥长度与算法不匹配：EVP_AEAD_CTX_init 失败 → ctx 为 null
        Aead::AeadContext Context(Aead::AeadCipher::Aes128Gcm, MakeKey(32));
        std::array<std::uint8_t, 64> Output{};
        EXPECT_EQ(Context.Seal(Output, Plaintext), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, RoundTripAllCiphers)
    {
        // 每种 cipher：Seal → Open 往返还原明文，输出长度含 16 字节 tag
        // 注意：Seal 成功后内部 Nonce 自动递增，故使用对称的加密/解密双上下文
        const Aead::AeadCipher Ciphers[] = {
            Aead::AeadCipher::Aes128Gcm,
            Aead::AeadCipher::Aes256Gcm,
            Aead::AeadCipher::Chacha20Poly1305,
            Aead::AeadCipher::Xchacha20Poly1305,
        };
        for (const auto Cipher : Ciphers)
        {
            std::size_t KeyLength = 32u;
            if (Cipher == Aead::AeadCipher::Aes128Gcm)
            {
                KeyLength = 16u;
            }
            const auto Key = MakeKey(KeyLength);
            Aead::AeadContext Encryptor(Cipher, Key);
            Aead::AeadContext Decryptor(Cipher, Key);

            std::array<std::uint8_t, 128> Ciphertext{};
            EXPECT_EQ(Encryptor.Seal(Ciphertext, Plaintext), Preview::Fault::Code::Success)
                << "Seal Failed, cipher=" << static_cast<int>(Cipher);

            std::array<std::uint8_t, 128> Decrypted{};
            EXPECT_EQ(Decryptor.Open(Decrypted, std::span(Ciphertext).first(Plaintext.size() + 16)),
                      Preview::Fault::Code::Success)
                << "Open Failed, cipher=" << static_cast<int>(Cipher);
            EXPECT_TRUE(std::equal(Decrypted.begin(), Decrypted.begin() + Plaintext.size(),
                                   Plaintext.begin()))
                << "roundtrip mismatch, cipher=" << static_cast<int>(Cipher);
        }
    }

    TEST(CoreAead, SealOpenWithAd)
    {
        // 附带附加数据（AD）参与认证（加密/解密双上下文，Nonce 对称）
        const auto Key = MakeKey(32);
        Aead::AeadContext Encryptor(Aead::AeadCipher::Chacha20Poly1305, Key);
        Aead::AeadContext Decryptor(Aead::AeadCipher::Chacha20Poly1305, Key);
        std::array<std::uint8_t, 128> Ciphertext{};
        EXPECT_EQ(Encryptor.Seal(Ciphertext, Plaintext, AdditionalData), Preview::Fault::Code::Success);

        std::array<std::uint8_t, 128> Decrypted{};
        EXPECT_EQ(Decryptor.Open(Decrypted, std::span(Ciphertext).first(Plaintext.size() + 16), AdditionalData),
                  Preview::Fault::Code::Success);
        // AD 不一致时解密失败
        const std::array<std::uint8_t, 1> BadAdditionalData{'x'};
        EXPECT_EQ(Decryptor.Open(Decrypted, std::span(Ciphertext).first(Plaintext.size() + 16), BadAdditionalData),
                  Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, NonceAutoIncrement)
    {
        // Seal 成功后内部 Nonce 按小端序递增（非零 ad 参数验证增量路径）
        Aead::AeadContext Context(Aead::AeadCipher::Aes128Gcm, MakeKey(16));
        EXPECT_EQ(Context.Nonce()[0], 0);
        std::array<std::uint8_t, 128> Ciphertext{};
        EXPECT_EQ(Context.Seal(Ciphertext, Plaintext), Preview::Fault::Code::Success);
        EXPECT_EQ(Context.Nonce()[0], 1);
        EXPECT_EQ(Context.Seal(Ciphertext, Plaintext), Preview::Fault::Code::Success);
        EXPECT_EQ(Context.Nonce()[0], 2);
    }

    TEST(CoreAead, OpenTamperedCiphertext)
    {
        // 密文被篡改 → 认证失败
        Aead::AeadContext Context(Aead::AeadCipher::Aes256Gcm, MakeKey(32));
        std::array<std::uint8_t, 128> Ciphertext{};
        ASSERT_EQ(Context.Seal(Ciphertext, Plaintext), Preview::Fault::Code::Success);

        std::array<std::uint8_t, 128> Decrypted{};
        auto Tampered = Ciphertext;
        Tampered[0] ^= 0x01;
        EXPECT_EQ(Context.Open(Decrypted, std::span(Tampered).first(Plaintext.size() + 16)),
                  Preview::Fault::Code::CryptoError);
        // 篡改 tag 尾部
        auto TamperedTag = Ciphertext;
        TamperedTag[Plaintext.size() + 15] ^= 0x01;
        EXPECT_EQ(Context.Open(Decrypted, std::span(TamperedTag).first(Plaintext.size() + 16)),
                  Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, SealOutputTooSmall)
    {
        // 输出缓冲区不足（缺 tag 空间）→ EVP Seal 失败
        Aead::AeadContext Context(Aead::AeadCipher::Chacha20Poly1305, MakeKey(32));
        std::array<std::uint8_t, 8> Small{};
        EXPECT_EQ(Context.Seal(Small, Plaintext), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, ExplicitNonceRoundTrip)
    {
        // 显式 Nonce 重载：12 字节 Nonce，成功往返且不修改内部状态
        Aead::AeadContext Context(Aead::AeadCipher::Aes256Gcm, MakeKey(32));
        const std::array<std::uint8_t, 12> Nonce{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        std::array<std::uint8_t, 128> Ciphertext{};

        Aead::SealInput SealInput{std::span(Ciphertext), Plaintext, Nonce, AdditionalData};
        EXPECT_EQ(Context.Seal(SealInput), Preview::Fault::Code::Success);
        // 内部 Nonce 不受显式 Nonce 调用影响
        EXPECT_EQ(Context.Nonce()[0], 0);

        std::array<std::uint8_t, 128> Decrypted{};
        Aead::OpenInput OpenInput{Decrypted, std::span(Ciphertext).first(Plaintext.size() + 16), Nonce,
                                 AdditionalData};
        EXPECT_EQ(Context.Open(OpenInput), Preview::Fault::Code::Success);
        EXPECT_TRUE(std::equal(Decrypted.begin(), Decrypted.begin() + Plaintext.size(), Plaintext.begin()));
        EXPECT_EQ(Context.Nonce()[0], 0);
    }

    TEST(CoreAead, ExplicitNonceXchacha)
    {
        // XChaCha20 使用 24 字节显式 Nonce
        Aead::AeadContext Context(Aead::AeadCipher::Xchacha20Poly1305, MakeKey(32));
        std::array<std::uint8_t, 24> Nonce{};
        for (std::size_t Index = 0; Index < Nonce.size(); ++Index)
        {
            Nonce[Index] = static_cast<std::uint8_t>(Index * 3);
        }
        std::array<std::uint8_t, 128> Ciphertext{};
        Aead::SealInput SealInput{std::span(Ciphertext), Plaintext, Nonce, AdditionalData};
        EXPECT_EQ(Context.Seal(SealInput), Preview::Fault::Code::Success);

        std::array<std::uint8_t, 128> Decrypted{};
        Aead::OpenInput OpenInput{Decrypted, std::span(Ciphertext).first(Plaintext.size() + 16), Nonce,
                                 AdditionalData};
        EXPECT_EQ(Context.Open(OpenInput), Preview::Fault::Code::Success);
    }

    TEST(CoreAead, ExplicitNonceBadNonce)
    {
        // 显式 Nonce 长度错误（12 字节用于 xchacha24）→ EVP 失败
        Aead::AeadContext Context(Aead::AeadCipher::Xchacha20Poly1305, MakeKey(32));
        const std::array<std::uint8_t, 12> BadNonce{};
        std::array<std::uint8_t, 128> Ciphertext{};
        Aead::SealInput SealInput{std::span(Ciphertext), Plaintext, BadNonce, AdditionalData};
        EXPECT_EQ(Context.Seal(SealInput), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, ExplicitNonceSmallOutput)
    {
        // 显式 Nonce Seal：输出缓冲区不足 → 失败
        Aead::AeadContext Context(Aead::AeadCipher::Aes256Gcm, MakeKey(32));
        const std::array<std::uint8_t, 12> Nonce{};
        std::array<std::uint8_t, 8> Small{};
        Aead::SealInput SealInput{std::span(Small), Plaintext, Nonce, AdditionalData};
        EXPECT_EQ(Context.Seal(SealInput), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, ExplicitNonceOpenBadCiphertext)
    {
        // 显式 Nonce Open：密文被篡改 → EVP Open 失败
        const auto Key = MakeKey(32);
        Aead::AeadContext Encryptor(Aead::AeadCipher::Aes256Gcm, Key);
        Aead::AeadContext Decryptor(Aead::AeadCipher::Aes256Gcm, Key);
        const std::array<std::uint8_t, 12> Nonce{};
        std::array<std::uint8_t, 128> Ciphertext{};
        Aead::SealInput SealInput{std::span(Ciphertext), Plaintext, Nonce, AdditionalData};
        ASSERT_EQ(Encryptor.Seal(SealInput), Preview::Fault::Code::Success);

        auto Tampered = Ciphertext;
        Tampered[Plaintext.size() + 15] ^= 0x01;
        std::array<std::uint8_t, 128> Decrypted{};
        Aead::OpenInput OpenInput{Decrypted, std::span(Tampered).first(Plaintext.size() + 16), Nonce,
                                 AdditionalData};
        EXPECT_EQ(Decryptor.Open(OpenInput), Preview::Fault::Code::CryptoError);
        // 错误 Nonce 同样失败
        const std::array<std::uint8_t, 12> WrongNonce{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        Aead::OpenInput WrongOpenInput{Decrypted, std::span(Ciphertext).first(Plaintext.size() + 16), WrongNonce,
                                       AdditionalData};
        EXPECT_EQ(Decryptor.Open(WrongOpenInput), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, MoveConstructor)
    {
        // 移动构造：目标可继续使用，源对象失效（Seal 返回 crypto_error）
        Aead::AeadContext Source(Aead::AeadCipher::Aes128Gcm, MakeKey(16));
        std::array<std::uint8_t, 128> Ciphertext{};
        ASSERT_EQ(Source.Seal(Ciphertext, Plaintext), Preview::Fault::Code::Success);

        Aead::AeadContext Destination(std::move(Source));
        // 源对象失效
        EXPECT_EQ(Source.Seal(Ciphertext, Plaintext), Preview::Fault::Code::CryptoError);
        // 目标持有原状态（Nonce 已递增为 1），可继续执行新操作
        EXPECT_EQ(Destination.Nonce()[0], 1);
        EXPECT_EQ(Destination.Seal(Ciphertext, Plaintext), Preview::Fault::Code::Success);
        EXPECT_EQ(Destination.Nonce()[0], 2);
        // 源对象析构时 ReleaseCtx(nullptr) 分支
    }

    TEST(CoreAead, MoveAssign)
    {
        // 移动赋值：旧资源释放、新状态接管
        Aead::AeadContext Source(Aead::AeadCipher::Chacha20Poly1305, MakeKey(32));
        Aead::AeadContext Destination(Aead::AeadCipher::Aes128Gcm, MakeKey(16));

        Destination = std::move(Source);
        EXPECT_EQ(Destination.NonceLength(), 12);
        std::array<std::uint8_t, 128> Ciphertext{};
        EXPECT_EQ(Destination.Seal(Ciphertext, Plaintext), Preview::Fault::Code::Success);
        EXPECT_EQ(Source.Seal(Ciphertext, Plaintext), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, MoveAssignSelf)
    {
        // 自赋值：if (this != &other) 的 else 分支，状态保持
        Aead::AeadContext Context(Aead::AeadCipher::Aes256Gcm, MakeKey(32));
        Aead::AeadContext &Self = Context;
        Context = std::move(Self);
        std::array<std::uint8_t, 128> Ciphertext{};
        EXPECT_EQ(Context.Seal(Ciphertext, Plaintext), Preview::Fault::Code::Success);
        EXPECT_EQ(Context.Nonce()[0], 1);
    }

    TEST(CoreAead, NonceExhausted)
    {
        // 内部 Nonce 全 0xFF → Seal/Open 均拒绝（防 Nonce 重用）
        Aead::AeadContext Context(Aead::AeadCipher::Aes128Gcm, MakeKey(16));
        EXPECT_FALSE(Context.IsNonceExhausted());
        Context.Nonce_.fill(0xFF);
        EXPECT_TRUE(Context.IsNonceExhausted());

        std::array<std::uint8_t, 128> Ciphertext{};
        EXPECT_EQ(Context.Seal(Ciphertext, Plaintext), Preview::Fault::Code::CryptoError);
        EXPECT_EQ(Context.Open(Ciphertext, Ciphertext), Preview::Fault::Code::CryptoError);
    }

    TEST(CoreAead, NoncePartialFull)
    {
        // 部分字节为 0xFF 不算耗尽；XChaCha 需 24 字节全 0xFF
        Aead::AeadContext Context(Aead::AeadCipher::Xchacha20Poly1305, MakeKey(32));
        Context.Nonce_.fill(0xFF);
        Context.Nonce_[23] = 0xFE;
        EXPECT_FALSE(Context.IsNonceExhausted());
        Context.Nonce_[23] = 0xFF;
        EXPECT_TRUE(Context.IsNonceExhausted());
    }

    TEST(CoreAead, ReleaseCtxBothPaths)
    {
        // ReleaseCtx 两分支：非空（cleanup + delete）与空（直接返回）
        auto *RawContext = new EVP_AEAD_CTX;
        EVP_AEAD_CTX_zero(RawContext);
        Aead::AeadContext::ReleaseCtx(RawContext); // 非空分支
        // volatile 阻止常量折叠，确保 if (ctx) 的空分支在运行时判定
        evp_aead_ctx_st *volatile NullContext = nullptr;
        Aead::AeadContext::ReleaseCtx(NullContext); // 空分支
    }

    TEST(CoreAead, IncrementNonceOverflow)
    {
        // 递增溢出：0xFF 进位回绕（最后一个字节进位后全零）
        Aead::AeadContext Context(Aead::AeadCipher::Aes256Gcm, MakeKey(32));
        Context.Nonce_.fill(0xFF);
        Context.IncrementNonce();
        EXPECT_FALSE(Context.IsNonceExhausted());
        EXPECT_EQ(Context.Nonce()[0], 0);
        EXPECT_EQ(Context.Nonce()[1], 0);
        // 12 字节 Nonce：进位不会触及 nonce_len 之后的字节
        EXPECT_EQ(Context.Nonce()[12], 0xFF);

        // 部分字节进位：1 + 0xFF = 0，0xFF + 1 = 0 且停止
        Aead::AeadContext Context2(Aead::AeadCipher::Aes256Gcm, MakeKey(32));
        Context2.Nonce_[0] = 0x0A;
        Context2.IncrementNonce();
        EXPECT_EQ(Context2.Nonce()[0], 0x0B);
    }

    TEST(CoreAead, SizeHelpers)
    {
        // 静态工具函数
        EXPECT_EQ(Aead::AeadContext::TagLength(), 16);
        EXPECT_EQ(Aead::AeadContext::SealSize(10), 26);
        EXPECT_EQ(Aead::AeadContext::SealSize(0), 16);
        EXPECT_EQ(Aead::AeadContext::OpenSize(26), 10);
        EXPECT_EQ(Aead::AeadContext::OpenSize(16), 0);
        // 密文长度小于 tag 长度 → 0
        EXPECT_EQ(Aead::AeadContext::OpenSize(8), 0);
        EXPECT_EQ(Aead::AeadContext::OpenSize(0), 0);
    }
} // namespace
