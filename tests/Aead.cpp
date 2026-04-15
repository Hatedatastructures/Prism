/**
 * @file Aead.cpp
 * @brief AEAD 加密解密单元测试
 * @details 测试 psm::crypto::aead_context 的 AES-128/256-GCM 加解密功能，
 * 覆盖 seal/open 往返、错误密钥、篡改密文、AD 不匹配、nonce 自动递增、
 * 空明文、大载荷、移动语义、输出尺寸验证等场景。
 */

#include <prism/crypto/aead.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/fault.hpp>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace
{
    int passed = 0;
    int failed = 0;

    auto log_info(const std::string_view msg) -> void
    {
        psm::trace::info("[Aead] {}", msg);
    }

    auto log_pass(const std::string_view msg) -> void
    {
        ++passed;
        psm::trace::info("[Aead] PASS: {}", msg);
    }

    auto log_fail(const std::string_view msg) -> void
    {
        ++failed;
        psm::trace::error("[Aead] FAIL: {}", msg);
    }
}

/**
 * @brief 测试 AES-128-GCM seal/open 往返
 */
void TestAeadSealOpenRoundtripAes128()
{
    log_info("=== TestAeadSealOpenRoundtripAes128 ===");

    const std::array<std::uint8_t, 16> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_128_gcm, key);

    const std::string plaintext = "Hello AES-128-GCM!";
    const auto pt_span = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(plaintext.data()), plaintext.size());

    // 使用显式 nonce 避免自增导致 seal/open nonce 不匹配
    const std::array<std::uint8_t, 12> nonce{};

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_output_size(pt_span.size()));
    auto ec = ctx.seal(ciphertext, pt_span, nonce, {});
    if (psm::fault::failed(ec))
    {
        log_fail("seal failed");
        return;
    }

    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_output_size(ciphertext.size()));
    ec = ctx.open(decrypted, ciphertext, nonce, {});
    if (psm::fault::failed(ec))
    {
        log_fail("open failed");
        return;
    }

    if (std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()) != 0)
    {
        log_fail("decrypted data does not match original");
        return;
    }

    log_pass("AeadSealOpenRoundtripAes128");
}

/**
 * @brief 测试 AES-256-GCM seal/open 往返
 */
void TestAeadSealOpenRoundtripAes256()
{
    log_info("=== TestAeadSealOpenRoundtripAes256 ===");

    const std::array<std::uint8_t, 32> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_256_gcm, key);

    const std::string plaintext = "Hello AES-256-GCM!";
    const auto pt_span = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(plaintext.data()), plaintext.size());

    // 使用显式 nonce 避免自增导致 seal/open nonce 不匹配
    const std::array<std::uint8_t, 12> nonce{};

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_output_size(pt_span.size()));
    auto ec = ctx.seal(ciphertext, pt_span, nonce, {});
    if (psm::fault::failed(ec))
    {
        log_fail("seal failed");
        return;
    }

    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_output_size(ciphertext.size()));
    ec = ctx.open(decrypted, ciphertext, nonce, {});
    if (psm::fault::failed(ec))
    {
        log_fail("open failed");
        return;
    }

    if (std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()) != 0)
    {
        log_fail("decrypted data does not match original");
        return;
    }

    log_pass("AeadSealOpenRoundtripAes256");
}

/**
 * @brief 测试错误密钥导致解密失败
 */
void TestAeadWrongKey()
{
    log_info("=== TestAeadWrongKey ===");

    const std::array<std::uint8_t, 16> key_a = {};
    const std::array<std::uint8_t, 16> key_b = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    psm::crypto::aead_context ctx_a(psm::crypto::aead_cipher::aes_128_gcm, key_a);

    const std::string plaintext = "secret data";
    const auto pt_span = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(plaintext.data()), plaintext.size());

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_output_size(pt_span.size()));
    ctx_a.seal(ciphertext, pt_span);

    // 使用不同密钥解密
    psm::crypto::aead_context ctx_b(psm::crypto::aead_cipher::aes_128_gcm, key_b);
    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_output_size(ciphertext.size()));
    auto ec = ctx_b.open(decrypted, ciphertext);

    if (psm::fault::succeeded(ec))
    {
        log_fail("wrong key should produce crypto_error");
        return;
    }

    log_pass("AeadWrongKey");
}

/**
 * @brief 测试篡改密文导致解密失败
 */
void TestAeadTamperedCiphertext()
{
    log_info("=== TestAeadTamperedCiphertext ===");

    const std::array<std::uint8_t, 16> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_128_gcm, key);

    const std::string plaintext = "tamper test data here";
    const auto pt_span = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(plaintext.data()), plaintext.size());

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_output_size(pt_span.size()));
    ctx.seal(ciphertext, pt_span);

    // 篡改密文中的一个字节（跳过最后 16 字节的 tag，修改密文区域）
    ciphertext[0] ^= 0xFF;

    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_output_size(ciphertext.size()));
    auto ec = ctx.open(decrypted, ciphertext);

    if (psm::fault::succeeded(ec))
    {
        log_fail("tampered ciphertext should produce crypto_error");
        return;
    }

    log_pass("AeadTamperedCiphertext");
}

/**
 * @brief 测试 AD 不匹配导致解密失败
 */
void TestAeadMissingAd()
{
    log_info("=== TestAeadMissingAd ===");

    const std::array<std::uint8_t, 16> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_128_gcm, key);

    const std::string plaintext = "test with AD";
    const auto pt_span = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(plaintext.data()), plaintext.size());
    const std::array<std::uint8_t, 4> ad = {1, 2, 3, 4};

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_output_size(pt_span.size()));
    ctx.seal(ciphertext, pt_span, ad);

    // 不带 AD 解密
    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_output_size(ciphertext.size()));
    auto ec = ctx.open(decrypted, ciphertext);

    if (psm::fault::succeeded(ec))
    {
        log_fail("missing AD should produce crypto_error");
        return;
    }

    log_pass("AeadMissingAd");
}

/**
 * @brief 测试 nonce 自动递增
 */
void TestAeadNonceAutoIncrement()
{
    log_info("=== TestAeadNonceAutoIncrement ===");

    const std::array<std::uint8_t, 16> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_128_gcm, key);

    const std::array<std::uint8_t, 4> plaintext = {0x01, 0x02, 0x03, 0x04};

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_output_size(plaintext.size()));
    std::vector<std::uint8_t> dummy(psm::crypto::aead_context::open_output_size(ciphertext.size()));

    // 验证 seal 自动递增 nonce
    auto nonce0 = ctx.nonce();
    ctx.seal(ciphertext, plaintext);
    auto nonce1 = ctx.nonce();

    if (nonce0 == nonce1)
    {
        log_fail("nonce should change after first seal");
        return;
    }

    // 验证 open 自动递增 nonce
    // 用显式 nonce（匹配当前内部 nonce）seal 新密文，使 auto-nonce open 能成功并递增
    std::array<std::uint8_t, 12> seal_nonce;
    std::memcpy(seal_nonce.data(), nonce1.data(), 12);

    std::vector<std::uint8_t> ct2(psm::crypto::aead_context::seal_output_size(plaintext.size()));
    std::vector<std::uint8_t> dec2(psm::crypto::aead_context::open_output_size(ct2.size()));

    ctx.seal(ct2, plaintext, seal_nonce, {});
    ctx.open(dec2, ct2);
    auto nonce2 = ctx.nonce();

    if (nonce1 == nonce2)
    {
        log_fail("nonce should change after open");
        return;
    }

    log_pass("AeadNonceAutoIncrement");
}

/**
 * @brief 测试空明文 seal/open
 */
void TestAeadEmptyPlaintext()
{
    log_info("=== TestAeadEmptyPlaintext ===");

    const std::array<std::uint8_t, 16> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_128_gcm, key);

    const std::span<const std::uint8_t> empty_pt;
    const std::array<std::uint8_t, 12> nonce{};

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_output_size(0));
    auto ec = ctx.seal(ciphertext, empty_pt, nonce, {});
    if (psm::fault::failed(ec))
    {
        log_fail("seal empty plaintext failed");
        return;
    }

    // 空明文的密文应该只有 tag（16 字节）
    if (ciphertext.size() != 16)
    {
        log_fail("empty plaintext ciphertext should be 16 bytes (tag only), got " + std::to_string(ciphertext.size()));
        return;
    }

    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_output_size(ciphertext.size()));
    ec = ctx.open(decrypted, ciphertext, nonce, {});
    if (psm::fault::failed(ec))
    {
        log_fail("open empty ciphertext failed");
        return;
    }

    if (!decrypted.empty())
    {
        log_fail("decrypted empty plaintext should be empty");
        return;
    }

    log_pass("AeadEmptyPlaintext");
}

/**
 * @brief 测试大载荷 seal/open
 */
void TestAeadLargePayload()
{
    log_info("=== TestAeadLargePayload ===");

    const std::array<std::uint8_t, 16> key = {};
    psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_128_gcm, key);

    // 16KB 载荷
    std::vector<std::uint8_t> plaintext(16384);
    for (std::size_t i = 0; i < plaintext.size(); ++i)
    {
        plaintext[i] = static_cast<std::uint8_t>(i & 0xFF);
    }

    const std::array<std::uint8_t, 12> nonce{};

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_output_size(plaintext.size()));
    auto ec = ctx.seal(ciphertext, plaintext, nonce, {});
    if (psm::fault::failed(ec))
    {
        log_fail("seal large payload failed");
        return;
    }

    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_output_size(ciphertext.size()));
    ec = ctx.open(decrypted, ciphertext, nonce, {});
    if (psm::fault::failed(ec))
    {
        log_fail("open large payload failed");
        return;
    }

    if (decrypted != plaintext)
    {
        log_fail("large payload roundtrip mismatch");
        return;
    }

    log_pass("AeadLargePayload");
}

/**
 * @brief 测试移动语义
 */
void TestAeadMoveSemantics()
{
    log_info("=== TestAeadMoveSemantics ===");

    const std::array<std::uint8_t, 16> key = {};
    auto ctx1 = std::make_unique<psm::crypto::aead_context>(psm::crypto::aead_cipher::aes_128_gcm, key);

    const std::string plaintext = "move test";
    const auto pt_span = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(plaintext.data()), plaintext.size());
    const std::array<std::uint8_t, 12> nonce{};

    // 移动构造
    psm::crypto::aead_context ctx2(std::move(*ctx1));
    ctx1.reset();

    std::vector<std::uint8_t> ciphertext(psm::crypto::aead_context::seal_output_size(pt_span.size()));
    auto ec = ctx2.seal(ciphertext, pt_span, nonce, {});
    if (psm::fault::failed(ec))
    {
        log_fail("seal after move-construct failed");
        return;
    }

    std::vector<std::uint8_t> decrypted(psm::crypto::aead_context::open_output_size(ciphertext.size()));
    ec = ctx2.open(decrypted, ciphertext, nonce, {});
    if (psm::fault::failed(ec))
    {
        log_fail("open after move-construct failed");
        return;
    }

    // 移动赋值
    const std::array<std::uint8_t, 16> key2 = {0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD,
                                                 0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD};
    psm::crypto::aead_context ctx3(psm::crypto::aead_cipher::aes_128_gcm, key2);
    ctx3 = std::move(ctx2);

    // ctx3 应该继承 ctx2 的密钥，继续正常工作
    std::array<std::uint8_t, 12> nonce2{};
    nonce2[11] = 1;
    std::vector<std::uint8_t> ct2(psm::crypto::aead_context::seal_output_size(pt_span.size()));
    ec = ctx3.seal(ct2, pt_span, nonce2, {});
    if (psm::fault::failed(ec))
    {
        log_fail("seal after move-assign failed");
        return;
    }

    log_pass("AeadMoveSemantics");
}

/**
 * @brief 测试输出尺寸计算
 */
void TestAeadOutputSizeValidation()
{
    log_info("=== TestAeadOutputSizeValidation ===");

    // seal_output_size(n) = n + 16
    if (psm::crypto::aead_context::seal_output_size(100) != 116)
    {
        log_fail("seal_output_size(100) should be 116");
        return;
    }

    // open_output_size(n + 16) = n
    if (psm::crypto::aead_context::open_output_size(116) != 100)
    {
        log_fail("open_output_size(116) should be 100");
        return;
    }

    // tag_length = 16
    if (psm::crypto::aead_context::tag_length() != 16)
    {
        log_fail("tag_length should be 16");
        return;
    }

    // nonce_length = 12 (AES-GCM)
    const std::array<std::uint8_t, 16> tmp_key{};
    psm::crypto::aead_context ctx128(psm::crypto::aead_cipher::aes_128_gcm, tmp_key);
    if (ctx128.nonce_length() != 12)
    {
        log_fail("nonce_length should be 12 for AES-GCM");
        return;
    }

    log_pass("AeadOutputSizeValidation");
}

/**
 * @brief 测试入口
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    log_info("Starting AEAD tests...");

    TestAeadSealOpenRoundtripAes128();
    TestAeadSealOpenRoundtripAes256();
    TestAeadWrongKey();
    TestAeadTamperedCiphertext();
    TestAeadMissingAd();
    TestAeadNonceAutoIncrement();
    TestAeadEmptyPlaintext();
    TestAeadLargePayload();
    TestAeadMoveSemantics();
    TestAeadOutputSizeValidation();

    psm::trace::info("[Aead] Results: {} passed, {} failed", passed, failed);

    return failed > 0 ? 1 : 0;
}
