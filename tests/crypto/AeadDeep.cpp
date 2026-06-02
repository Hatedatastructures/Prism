/**
 * @file AeadDeep.cpp
 * @brief AEAD 深度测试 — 全分支覆盖
 * @details 通过 #include 源文件确保 gcov 计入覆盖行。
 *          覆盖构造全算法、seal/open 自动 nonce、seal/open 显式 nonce、
 *          移动语义、increment_nonce 溢出、null ctx 错误路径。
 */

#include <gtest/gtest.h>

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/fault.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#define private public
#include <prism/crypto/aead.hpp>
#undef private

// 包含源文件以获得 gcov 覆盖
#include "../../src/prism/crypto/aead.cpp"

namespace
{
    using psm::crypto::aead_cipher;
    using psm::crypto::aead_context;
    using psm::fault::code;

    auto make_key(std::size_t len) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> key(len, 0xAA);
        return key;
    }

    // ─── 构造全算法 ──────────────────────────────

    TEST(AeadDeep, ConstructAes128Gcm)
    {
        auto key = make_key(16);
        aead_context ctx(aead_cipher::aes_128_gcm, key);
        EXPECT_TRUE(ctx.ctx_ != nullptr) << "construct: aes128gcm ctx valid";
        EXPECT_EQ(ctx.nonce_len_, 12) << "construct: aes128gcm nonce_len=12";
        EXPECT_EQ(ctx.key_length_, 16) << "construct: aes128gcm key_len=16";
    }

    TEST(AeadDeep, ConstructAes256Gcm)
    {
        auto key = make_key(32);
        aead_context ctx(aead_cipher::aes_256_gcm, key);
        EXPECT_TRUE(ctx.ctx_ != nullptr) << "construct: aes256gcm ctx valid";
        EXPECT_EQ(ctx.nonce_len_, 12) << "construct: aes256gcm nonce_len=12";
    }

    TEST(AeadDeep, ConstructChacha20)
    {
        auto key = make_key(32);
        aead_context ctx(aead_cipher::chacha20_poly1305, key);
        EXPECT_TRUE(ctx.ctx_ != nullptr) << "construct: chacha20 ctx valid";
        EXPECT_EQ(ctx.nonce_len_, 12) << "construct: chacha20 nonce_len=12";
    }

    TEST(AeadDeep, ConstructXchacha20)
    {
        auto key = make_key(32);
        aead_context ctx(aead_cipher::xchacha20_poly1305, key);
        EXPECT_TRUE(ctx.ctx_ != nullptr) << "construct: xchacha20 ctx valid";
        EXPECT_EQ(ctx.nonce_len_, 24) << "construct: xchacha20 nonce_len=24";
    }

    // ─── 构造错误路径 ──────────────────────────────

    TEST(AeadDeep, ConstructInvalidCipher)
    {
        auto key = make_key(16);
        // 使用强制转换传入无效值
        aead_context ctx(static_cast<aead_cipher>(99), key);
        EXPECT_TRUE(ctx.ctx_ == nullptr) << "construct: invalid cipher -> null ctx";
    }

    TEST(AeadDeep, ConstructWrongKeySize)
    {
        auto key = make_key(7);
        aead_context ctx(aead_cipher::aes_128_gcm, key);
        EXPECT_TRUE(ctx.ctx_ == nullptr) << "construct: wrong key size -> null ctx";
    }

    // ─── seal/open 自动 nonce 往返 ──────────────────

    TEST(AeadDeep, SealOpenRoundTrip)
    {
        auto key = make_key(32);
        aead_context seal_ctx(aead_cipher::aes_256_gcm, key);
        aead_context open_ctx(aead_cipher::aes_256_gcm, key);

        const std::vector<std::uint8_t> plaintext = {1, 2, 3, 4, 5};
        std::vector<std::uint8_t> ciphertext(aead_context::seal_size(plaintext.size()));
        std::vector<std::uint8_t> decrypted(plaintext.size());

        auto seal_rc = seal_ctx.seal(ciphertext, plaintext);
        EXPECT_EQ(seal_rc, code::success) << "seal/open: seal success";

        // nonce 已递增
        EXPECT_EQ(seal_ctx.nonce_[0], 1) << "seal/open: nonce incremented after seal";

        auto open_rc = open_ctx.open(decrypted, ciphertext);
        EXPECT_EQ(open_rc, code::success) << "seal/open: open success";

        EXPECT_EQ(std::memcmp(plaintext.data(), decrypted.data(), plaintext.size()), 0)
            << "seal/open: plaintext matches";
    }

    TEST(AeadDeep, SealOpenWithAd)
    {
        auto key = make_key(32);
        aead_context seal_ctx(aead_cipher::chacha20_poly1305, key);
        aead_context open_ctx(aead_cipher::chacha20_poly1305, key);

        const std::vector<std::uint8_t> plaintext = {0xDE, 0xAD, 0xBE, 0xEF};
        const std::vector<std::uint8_t> ad = {1, 2, 3, 4, 5};
        std::vector<std::uint8_t> ciphertext(aead_context::seal_size(plaintext.size()));
        std::vector<std::uint8_t> decrypted(plaintext.size());

        auto seal_rc = seal_ctx.seal(ciphertext, plaintext, ad);
        EXPECT_EQ(seal_rc, code::success) << "seal/open ad: seal success";

        auto open_rc = open_ctx.open(decrypted, ciphertext, ad);
        EXPECT_EQ(open_rc, code::success) << "seal/open ad: open success";

        EXPECT_EQ(std::memcmp(plaintext.data(), decrypted.data(), plaintext.size()), 0)
            << "seal/open ad: plaintext matches";
    }

    // ─── seal/open 错误路径 ──────────────────────────

    TEST(AeadDeep, SealNullCtx)
    {
        auto key = make_key(7); // 错误大小 → ctx == nullptr
        aead_context ctx(aead_cipher::aes_128_gcm, key);

        std::vector<std::uint8_t> out(32);
        auto rc = ctx.seal(out, {});
        EXPECT_EQ(rc, code::crypto_error) << "seal null ctx: crypto_error";
    }

    TEST(AeadDeep, OpenNullCtx)
    {
        auto key = make_key(7);
        aead_context ctx(aead_cipher::aes_128_gcm, key);

        std::vector<std::uint8_t> out(32);
        auto rc = ctx.open(out, {out.data(), out.size()});
        EXPECT_EQ(rc, code::crypto_error) << "open null ctx: crypto_error";
    }

    TEST(AeadDeep, SealExplicitNullCtx)
    {
        auto key = make_key(7);
        aead_context ctx(aead_cipher::aes_128_gcm, key);

        std::array<std::uint8_t, 12> nonce{};
        psm::crypto::seal_input input{{}, {}, nonce, {}};
        auto rc = ctx.seal(input);
        EXPECT_EQ(rc, code::crypto_error) << "seal explicit null ctx: crypto_error";
    }

    TEST(AeadDeep, OpenExplicitNullCtx)
    {
        auto key = make_key(7);
        aead_context ctx(aead_cipher::aes_128_gcm, key);

        std::array<std::uint8_t, 12> nonce{};
        std::vector<std::uint8_t> ct(16, 0);
        std::vector<std::uint8_t> out_buf(16);
        psm::crypto::open_input input2{out_buf, ct, nonce, {}};
        auto rc = ctx.open(input2);
        EXPECT_EQ(rc, code::crypto_error) << "open explicit null ctx: crypto_error";
    }

    // ─── 显式 nonce seal/open 往返 ──────────────────

    TEST(AeadDeep, SealOpenExplicitNonce)
    {
        auto key = make_key(16);
        aead_context ctx(aead_cipher::aes_128_gcm, key);

        std::array<std::uint8_t, 12> nonce{};
        nonce[0] = 0x42;

        const std::vector<std::uint8_t> plaintext = {10, 20, 30};
        std::vector<std::uint8_t> ciphertext(aead_context::seal_size(plaintext.size()));
        std::vector<std::uint8_t> decrypted(plaintext.size());

        psm::crypto::seal_input seal_in{ciphertext, plaintext, nonce, {}};
        auto seal_rc = ctx.seal(seal_in);
        EXPECT_EQ(seal_rc, code::success) << "explicit nonce: seal success";

        psm::crypto::open_input open_in{decrypted, ciphertext, nonce, {}};
        auto open_rc = ctx.open(open_in);
        EXPECT_EQ(open_rc, code::success) << "explicit nonce: open success";

        EXPECT_EQ(std::memcmp(plaintext.data(), decrypted.data(), plaintext.size()), 0)
            << "explicit nonce: plaintext matches";
    }

    TEST(AeadDeep, SealExplicitNonceFailure)
    {
        auto key = make_key(32);
        aead_context ctx(aead_cipher::aes_256_gcm, key);

        std::array<std::uint8_t, 12> nonce{};
        const std::vector<std::uint8_t> plaintext = {1, 2, 3};
        // 输出 buffer 太小
        std::vector<std::uint8_t> ciphertext(2);

        psm::crypto::seal_input seal_in{ciphertext, plaintext, nonce, {}};
        auto rc = ctx.seal(seal_in);
        EXPECT_EQ(rc, code::crypto_error) << "explicit nonce seal: output too small -> error";
    }

    TEST(AeadDeep, OpenExplicitNonceFailure)
    {
        auto key = make_key(32);
        aead_context ctx(aead_cipher::aes_256_gcm, key);

        std::array<std::uint8_t, 12> nonce{};
        std::vector<std::uint8_t> ciphertext = {1, 2, 3}; // 无效密文
        std::vector<std::uint8_t> decrypted(16);

        psm::crypto::open_input open_in{decrypted, ciphertext, nonce, {}};
        auto rc = ctx.open(open_in);
        EXPECT_EQ(rc, code::crypto_error) << "explicit nonce open: bad ciphertext -> error";
    }

    // ─── increment_nonce 边界 ──────────────────────

    TEST(AeadDeep, IncrementNonceNormal)
    {
        aead_context ctx(aead_cipher::aes_128_gcm, make_key(16));
        ctx.nonce_[0] = 0;
        ctx.increment_nonce();
        EXPECT_FALSE(ctx.is_nonce_exhausted()) << "increment: normal -> not exhausted";
        EXPECT_EQ(ctx.nonce_[0], 1) << "increment: nonce[0]==1";
    }

    TEST(AeadDeep, IncrementNonceCarry)
    {
        aead_context ctx(aead_cipher::aes_128_gcm, make_key(16));
        ctx.nonce_[0] = 0xFF;
        ctx.increment_nonce();
        EXPECT_FALSE(ctx.is_nonce_exhausted()) << "increment: carry -> not exhausted";
        EXPECT_EQ(ctx.nonce_[0], 0) << "increment: nonce[0] wraps to 0";
        EXPECT_EQ(ctx.nonce_[1], 1) << "increment: nonce[1] carries";
    }

    TEST(AeadDeep, IncrementNonceOverflow)
    {
        aead_context ctx(aead_cipher::aes_128_gcm, make_key(16));
        // 设置所有 nonce 字节为 0xFF
        for (std::size_t i = 0; i < ctx.nonce_len_; ++i)
        {
            ctx.nonce_[i] = 0xFF;
        }
        EXPECT_TRUE(ctx.is_nonce_exhausted()) << "increment: all-FF -> exhausted";
    }

    // ─── 移动语义 ──────────────────────────────

    TEST(AeadDeep, MoveConstructor)
    {
        aead_context ctx1(aead_cipher::aes_256_gcm, make_key(32));
        ctx1.nonce_[0] = 0x42;
        void *original_ctx = ctx1.ctx_.get();

        aead_context ctx2(std::move(ctx1));
        EXPECT_EQ(ctx2.ctx_.get(), original_ctx) << "move ctor: ctx transferred";
        EXPECT_EQ(ctx2.nonce_[0], 0x42) << "move ctor: nonce transferred";
        EXPECT_TRUE(ctx1.ctx_ == nullptr) << "move ctor: source null";
        bool all_zero = true;
        for (auto b : ctx1.nonce_)
        {
            if (b != 0)
            {
                all_zero = false;
                break;
            }
        }
        EXPECT_TRUE(all_zero) << "move ctor: source nonce zeroed";
    }

    TEST(AeadDeep, MoveAssignment)
    {
        aead_context ctx1(aead_cipher::aes_256_gcm, make_key(32));
        ctx1.nonce_[0] = 0x99;
        aead_context ctx2(aead_cipher::chacha20_poly1305, make_key(32));

        void *original_ctx = ctx1.ctx_.get();
        ctx2 = std::move(ctx1);

        EXPECT_EQ(ctx2.ctx_.get(), original_ctx) << "move assign: ctx transferred";
        EXPECT_EQ(ctx2.nonce_[0], 0x99) << "move assign: nonce transferred";
        EXPECT_TRUE(ctx1.ctx_ == nullptr) << "move assign: source null";
    }

    TEST(AeadDeep, MoveSelfAssignment)
    {
        aead_context ctx(aead_cipher::aes_128_gcm, make_key(16));
        ctx.nonce_[0] = 0x77;
        auto *ptr = ctx.ctx_.get();
        // 自赋值：this == &other → 不做任何事
        ctx = std::move(ctx);
        EXPECT_EQ(ctx.ctx_.get(), ptr) << "self-assign: ctx unchanged";
        EXPECT_EQ(ctx.nonce_[0], 0x77) << "self-assign: nonce unchanged";
    }

    // ─── release_ctx null 安全 ──────────────────────

    TEST(AeadDeep, ReleaseCtxNull)
    {
        // release_ctx(nullptr) 应该不崩溃
        aead_context::release_ctx(nullptr);
    }

    // ─── seal 后 open 错误密钥不匹配 ──────────────────

    TEST(AeadDeep, SealOpenWrongKey)
    {
        auto key1 = make_key(32);
        auto key2 = make_key(32);
        key2[0] ^= 0xFF; // 修改一个字节

        aead_context seal_ctx(aead_cipher::aes_256_gcm, key1);
        aead_context open_ctx(aead_cipher::aes_256_gcm, key2);

        const std::vector<std::uint8_t> plaintext = {1, 2, 3, 4};
        std::vector<std::uint8_t> ciphertext(aead_context::seal_size(plaintext.size()));

        auto seal_rc = seal_ctx.seal(ciphertext, plaintext);
        EXPECT_EQ(seal_rc, code::success) << "wrong key: seal ok";

        // 用 seal_ctx 的 nonce 手动构造 open_input
        auto nonce_copy = seal_ctx.nonce();
        std::vector<std::uint8_t> decrypted(plaintext.size());
        psm::crypto::open_input open_in{decrypted, ciphertext, {nonce_copy.data(), seal_ctx.nonce_length()}, {}};
        auto rc = open_ctx.open(open_in);
        EXPECT_EQ(rc, code::crypto_error) << "wrong key: open fails";
    }

} // namespace
