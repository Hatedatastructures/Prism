/**
 * @file AeadDeep.cpp
 * @brief AEAD 深度测试 — 全分支覆盖
 * @details 通过 #include 源文件确保 gcov 计入覆盖行。
 *          覆盖构造全算法、seal/open 自动 nonce、seal/open 显式 nonce、
 *          移动语义、increment_nonce 溢出、null ctx 错误路径。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/fault.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#define private public
#include <prism/crypto/aead.hpp>
#undef private

// 包含源文件以获得 gcov 覆盖
#include "../src/prism/crypto/aead.cpp"

using psm::testing::TestRunner;

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

    void TestConstructAes128Gcm(TestRunner &runner)
    {
        auto key = make_key(16);
        aead_context ctx(aead_cipher::aes_128_gcm, key);
        runner.Check(ctx.ctx_ != nullptr, "construct: aes128gcm ctx valid");
        runner.Check(ctx.nonce_len_ == 12, "construct: aes128gcm nonce_len=12");
        runner.Check(ctx.key_length_ == 16, "construct: aes128gcm key_len=16");
    }

    void TestConstructAes256Gcm(TestRunner &runner)
    {
        auto key = make_key(32);
        aead_context ctx(aead_cipher::aes_256_gcm, key);
        runner.Check(ctx.ctx_ != nullptr, "construct: aes256gcm ctx valid");
        runner.Check(ctx.nonce_len_ == 12, "construct: aes256gcm nonce_len=12");
    }

    void TestConstructChacha20(TestRunner &runner)
    {
        auto key = make_key(32);
        aead_context ctx(aead_cipher::chacha20_poly1305, key);
        runner.Check(ctx.ctx_ != nullptr, "construct: chacha20 ctx valid");
        runner.Check(ctx.nonce_len_ == 12, "construct: chacha20 nonce_len=12");
    }

    void TestConstructXchacha20(TestRunner &runner)
    {
        auto key = make_key(32);
        aead_context ctx(aead_cipher::xchacha20_poly1305, key);
        runner.Check(ctx.ctx_ != nullptr, "construct: xchacha20 ctx valid");
        runner.Check(ctx.nonce_len_ == 24, "construct: xchacha20 nonce_len=24");
    }

    // ─── 构造错误路径 ──────────────────────────────

    void TestConstructInvalidCipher(TestRunner &runner)
    {
        auto key = make_key(16);
        // 使用强制转换传入无效值
        aead_context ctx(static_cast<aead_cipher>(99), key);
        runner.Check(ctx.ctx_ == nullptr, "construct: invalid cipher -> null ctx");
    }

    void TestConstructWrongKeySize(TestRunner &runner)
    {
        auto key = make_key(7);
        aead_context ctx(aead_cipher::aes_128_gcm, key);
        runner.Check(ctx.ctx_ == nullptr, "construct: wrong key size -> null ctx");
    }

    // ─── seal/open 自动 nonce 往返 ──────────────────

    void TestSealOpenRoundTrip(TestRunner &runner)
    {
        auto key = make_key(32);
        aead_context seal_ctx(aead_cipher::aes_256_gcm, key);
        aead_context open_ctx(aead_cipher::aes_256_gcm, key);

        const std::vector<std::uint8_t> plaintext = {1, 2, 3, 4, 5};
        std::vector<std::uint8_t> ciphertext(aead_context::seal_size(plaintext.size()));
        std::vector<std::uint8_t> decrypted(plaintext.size());

        auto seal_rc = seal_ctx.seal(ciphertext, plaintext);
        runner.Check(seal_rc == code::success, "seal/open: seal success");

        // nonce 已递增
        runner.Check(seal_ctx.nonce_[0] == 1, "seal/open: nonce incremented after seal");

        auto open_rc = open_ctx.open(decrypted, ciphertext);
        runner.Check(open_rc == code::success, "seal/open: open success");

        runner.Check(std::memcmp(plaintext.data(), decrypted.data(), plaintext.size()) == 0,
                     "seal/open: plaintext matches");
    }

    void TestSealOpenWithAd(TestRunner &runner)
    {
        auto key = make_key(32);
        aead_context seal_ctx(aead_cipher::chacha20_poly1305, key);
        aead_context open_ctx(aead_cipher::chacha20_poly1305, key);

        const std::vector<std::uint8_t> plaintext = {0xDE, 0xAD, 0xBE, 0xEF};
        const std::vector<std::uint8_t> ad = {1, 2, 3, 4, 5};
        std::vector<std::uint8_t> ciphertext(aead_context::seal_size(plaintext.size()));
        std::vector<std::uint8_t> decrypted(plaintext.size());

        auto seal_rc = seal_ctx.seal(ciphertext, plaintext, ad);
        runner.Check(seal_rc == code::success, "seal/open ad: seal success");

        auto open_rc = open_ctx.open(decrypted, ciphertext, ad);
        runner.Check(open_rc == code::success, "seal/open ad: open success");

        runner.Check(std::memcmp(plaintext.data(), decrypted.data(), plaintext.size()) == 0,
                     "seal/open ad: plaintext matches");
    }

    // ─── seal/open 错误路径 ──────────────────────────

    void TestSealNullCtx(TestRunner &runner)
    {
        auto key = make_key(7); // 错误大小 → ctx == nullptr
        aead_context ctx(aead_cipher::aes_128_gcm, key);

        std::vector<std::uint8_t> out(32);
        auto rc = ctx.seal(out, {});
        runner.Check(rc == code::crypto_error, "seal null ctx: crypto_error");
    }

    void TestOpenNullCtx(TestRunner &runner)
    {
        auto key = make_key(7);
        aead_context ctx(aead_cipher::aes_128_gcm, key);

        std::vector<std::uint8_t> out(32);
        auto rc = ctx.open(out, {out.data(), out.size()});
        runner.Check(rc == code::crypto_error, "open null ctx: crypto_error");
    }

    void TestSealExplicitNullCtx(TestRunner &runner)
    {
        auto key = make_key(7);
        aead_context ctx(aead_cipher::aes_128_gcm, key);

        std::array<std::uint8_t, 12> nonce{};
        psm::crypto::seal_input input{{}, {}, nonce, {}};
        auto rc = ctx.seal(input);
        runner.Check(rc == code::crypto_error, "seal explicit null ctx: crypto_error");
    }

    void TestOpenExplicitNullCtx(TestRunner &runner)
    {
        auto key = make_key(7);
        aead_context ctx(aead_cipher::aes_128_gcm, key);

        std::array<std::uint8_t, 12> nonce{};
        std::vector<std::uint8_t> ct(16, 0);
        std::vector<std::uint8_t> out_buf(16);
        psm::crypto::open_input input2{out_buf, ct, nonce, {}};
        auto rc = ctx.open(input2);
        runner.Check(rc == code::crypto_error, "open explicit null ctx: crypto_error");
    }

    // ─── 显式 nonce seal/open 往返 ──────────────────

    void TestSealOpenExplicitNonce(TestRunner &runner)
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
        runner.Check(seal_rc == code::success, "explicit nonce: seal success");

        psm::crypto::open_input open_in{decrypted, ciphertext, nonce, {}};
        auto open_rc = ctx.open(open_in);
        runner.Check(open_rc == code::success, "explicit nonce: open success");

        runner.Check(std::memcmp(plaintext.data(), decrypted.data(), plaintext.size()) == 0,
                     "explicit nonce: plaintext matches");
    }

    void TestSealExplicitNonceFailure(TestRunner &runner)
    {
        auto key = make_key(32);
        aead_context ctx(aead_cipher::aes_256_gcm, key);

        std::array<std::uint8_t, 12> nonce{};
        const std::vector<std::uint8_t> plaintext = {1, 2, 3};
        // 输出 buffer 太小
        std::vector<std::uint8_t> ciphertext(2);

        psm::crypto::seal_input seal_in{ciphertext, plaintext, nonce, {}};
        auto rc = ctx.seal(seal_in);
        runner.Check(rc == code::crypto_error, "explicit nonce seal: output too small -> error");
    }

    void TestOpenExplicitNonceFailure(TestRunner &runner)
    {
        auto key = make_key(32);
        aead_context ctx(aead_cipher::aes_256_gcm, key);

        std::array<std::uint8_t, 12> nonce{};
        std::vector<std::uint8_t> ciphertext = {1, 2, 3}; // 无效密文
        std::vector<std::uint8_t> decrypted(16);

        psm::crypto::open_input open_in{decrypted, ciphertext, nonce, {}};
        auto rc = ctx.open(open_in);
        runner.Check(rc == code::crypto_error, "explicit nonce open: bad ciphertext -> error");
    }

    // ─── increment_nonce 边界 ──────────────────────

    void TestIncrementNonceNormal(TestRunner &runner)
    {
        aead_context ctx(aead_cipher::aes_128_gcm, make_key(16));
        ctx.nonce_[0] = 0;
        ctx.increment_nonce();
        runner.Check(!ctx.is_nonce_exhausted(), "increment: normal -> not exhausted");
        runner.Check(ctx.nonce_[0] == 1, "increment: nonce[0]==1");
    }

    void TestIncrementNonceCarry(TestRunner &runner)
    {
        aead_context ctx(aead_cipher::aes_128_gcm, make_key(16));
        ctx.nonce_[0] = 0xFF;
        ctx.increment_nonce();
        runner.Check(!ctx.is_nonce_exhausted(), "increment: carry -> not exhausted");
        runner.Check(ctx.nonce_[0] == 0, "increment: nonce[0] wraps to 0");
        runner.Check(ctx.nonce_[1] == 1, "increment: nonce[1] carries");
    }

    void TestIncrementNonceOverflow(TestRunner &runner)
    {
        aead_context ctx(aead_cipher::aes_128_gcm, make_key(16));
        // 设置所有 nonce 字节为 0xFF
        for (std::size_t i = 0; i < ctx.nonce_len_; ++i)
        {
            ctx.nonce_[i] = 0xFF;
        }
        runner.Check(ctx.is_nonce_exhausted(), "increment: all-FF -> exhausted");
    }

    // ─── 移动语义 ──────────────────────────────

    void TestMoveConstructor(TestRunner &runner)
    {
        aead_context ctx1(aead_cipher::aes_256_gcm, make_key(32));
        ctx1.nonce_[0] = 0x42;
        void *original_ctx = ctx1.ctx_.get();

        aead_context ctx2(std::move(ctx1));
        runner.Check(ctx2.ctx_.get() == original_ctx, "move ctor: ctx transferred");
        runner.Check(ctx2.nonce_[0] == 0x42, "move ctor: nonce transferred");
        runner.Check(ctx1.ctx_ == nullptr, "move ctor: source null");
        bool all_zero = true;
        for (auto b : ctx1.nonce_)
        {
            if (b != 0)
            {
                all_zero = false;
                break;
            }
        }
        runner.Check(all_zero, "move ctor: source nonce zeroed");
    }

    void TestMoveAssignment(TestRunner &runner)
    {
        aead_context ctx1(aead_cipher::aes_256_gcm, make_key(32));
        ctx1.nonce_[0] = 0x99;
        aead_context ctx2(aead_cipher::chacha20_poly1305, make_key(32));

        void *original_ctx = ctx1.ctx_.get();
        ctx2 = std::move(ctx1);

        runner.Check(ctx2.ctx_.get() == original_ctx, "move assign: ctx transferred");
        runner.Check(ctx2.nonce_[0] == 0x99, "move assign: nonce transferred");
        runner.Check(ctx1.ctx_ == nullptr, "move assign: source null");
    }

    void TestMoveSelfAssignment(TestRunner &runner)
    {
        aead_context ctx(aead_cipher::aes_128_gcm, make_key(16));
        ctx.nonce_[0] = 0x77;
        auto *ptr = ctx.ctx_.get();
        // 自赋值：this == &other → 不做任何事
        ctx = std::move(ctx);
        runner.Check(ctx.ctx_.get() == ptr, "self-assign: ctx unchanged");
        runner.Check(ctx.nonce_[0] == 0x77, "self-assign: nonce unchanged");
    }

    // ─── release_ctx null 安全 ──────────────────────

    void TestReleaseCtxNull(TestRunner &runner)
    {
        // release_ctx(nullptr) 应该不崩溃
        aead_context::release_ctx(nullptr);
        runner.Check(true, "release_ctx: null -> no crash");
    }

    // ─── seal 后 open 错误密钥不匹配 ──────────────────

    void TestSealOpenWrongKey(TestRunner &runner)
    {
        auto key1 = make_key(32);
        auto key2 = make_key(32);
        key2[0] ^= 0xFF; // 修改一个字节

        aead_context seal_ctx(aead_cipher::aes_256_gcm, key1);
        aead_context open_ctx(aead_cipher::aes_256_gcm, key2);

        const std::vector<std::uint8_t> plaintext = {1, 2, 3, 4};
        std::vector<std::uint8_t> ciphertext(aead_context::seal_size(plaintext.size()));

        auto seal_rc = seal_ctx.seal(ciphertext, plaintext);
        runner.Check(seal_rc == code::success, "wrong key: seal ok");

        // 用 seal_ctx 的 nonce 手动构造 open_input
        auto nonce_copy = seal_ctx.nonce();
        std::vector<std::uint8_t> decrypted(plaintext.size());
        psm::crypto::open_input open_in{decrypted, ciphertext, {nonce_copy.data(), seal_ctx.nonce_length()}, {}};
        auto rc = open_ctx.open(open_in);
        runner.Check(rc == code::crypto_error, "wrong key: open fails");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("AeadDeep");

    TestConstructAes128Gcm(runner);
    TestConstructAes256Gcm(runner);
    TestConstructChacha20(runner);
    TestConstructXchacha20(runner);

    TestConstructInvalidCipher(runner);
    TestConstructWrongKeySize(runner);

    TestSealOpenRoundTrip(runner);
    TestSealOpenWithAd(runner);

    TestSealNullCtx(runner);
    TestOpenNullCtx(runner);
    TestSealExplicitNullCtx(runner);
    TestOpenExplicitNullCtx(runner);

    TestSealOpenExplicitNonce(runner);
    TestSealExplicitNonceFailure(runner);
    TestOpenExplicitNonceFailure(runner);

    TestIncrementNonceNormal(runner);
    TestIncrementNonceCarry(runner);
    TestIncrementNonceOverflow(runner);

    TestMoveConstructor(runner);
    TestMoveAssignment(runner);
    TestMoveSelfAssignment(runner);

    TestReleaseCtxNull(runner);

    TestSealOpenWrongKey(runner);

    return runner.Summary();
}
