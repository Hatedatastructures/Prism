/**
 * @file CryptoErrorPaths.cpp
 * @brief 加密模块错误路径与边界条件测试
 */

#include <prism/crypto/aead.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/crypto/block.hpp>
#include <prism/crypto/hkdf.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    void TestBlake3KeyedHash(TestRunner &runner)
    {
        std::array<std::uint8_t, 32> key{};
        for (int i = 0; i < 32; ++i)
        {
            key[i] = static_cast<std::uint8_t>(i);
        }

        const std::uint8_t data[] = {1, 2, 3, 4, 5};
        auto h = psm::crypto::keyed_hash(key, data);
        runner.Check(h.size() == 32, "keyed_hash: output 32 bytes");

        auto h2 = psm::crypto::keyed_hash(key, data);
        runner.Check(std::memcmp(h.data(), h2.data(), 32) == 0,
                     "keyed_hash: deterministic");
    }

    void TestBlake3KeyedHasher(TestRunner &runner)
    {
        std::array<std::uint8_t, 32> key{};
        for (int i = 0; i < 32; ++i)
        {
            key[i] = static_cast<std::uint8_t>(i);
        }

        auto hasher = psm::crypto::keyed_hasher(key);
        const std::uint8_t chunk1[] = {0xAA, 0xBB};
        const std::uint8_t chunk2[] = {0xCC, 0xDD};
        blake3_hasher_update(&hasher, chunk1, sizeof(chunk1));
        blake3_hasher_update(&hasher, chunk2, sizeof(chunk2));

        std::array<std::uint8_t, 32> out{};
        blake3_hasher_finalize(&hasher, out.data(), out.size());
        runner.Check(out.size() == 32, "keyed_hasher: finalize 32 bytes");
    }

    void TestBlake3Hash(TestRunner &runner)
    {
        const std::uint8_t data[] = "hello world";
        auto h = psm::crypto::hash(data);
        runner.Check(h.size() == 32, "hash: output 32 bytes");

        auto h2 = psm::crypto::hash(data);
        runner.Check(std::memcmp(h.data(), h2.data(), 32) == 0,
                     "hash: deterministic");
    }

    void TestAeadShortCiphertext(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> key{};
        psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_128_gcm, key);

        std::vector<std::uint8_t> short_ct(4, 0xAA);
        std::vector<std::uint8_t> pt(ctx.open_size(short_ct.size()));
        auto ec = ctx.open(pt, short_ct);
        runner.Check(ec != psm::fault::code::success,
                     "aead: short ciphertext fails open");
    }

    void TestBlockWrongKeyDecrypt(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> input{};
        for (int i = 0; i < 16; ++i)
        {
            input[i] = static_cast<std::uint8_t>(i);
        }

        std::array<std::uint8_t, 16> key1{};
        key1.fill(0x01);
        std::array<std::uint8_t, 16> key2{};
        key2.fill(0x02);

        auto ct = psm::crypto::ecb_encrypt(input, key1);
        auto pt = psm::crypto::ecb_decrypt(ct, key2);
        runner.Check(std::memcmp(input.data(), pt.data(), 16) != 0,
                     "block: wrong key decrypt differs");
    }

    void TestHkdfExtractExpand(TestRunner &runner)
    {
        std::array<std::uint8_t, 32> ikm{};
        ikm.fill(0x42);

        auto prk = psm::crypto::hkdf_extract({}, ikm);
        runner.Check(prk.size() == 32, "hkdf_extract: 32 bytes");

        auto [ec, expanded] = psm::crypto::hkdf_expand(prk, {}, 32);
        runner.Check(ec == psm::fault::code::success, "hkdf_expand: success");
        runner.Check(expanded.size() == 32, "hkdf_expand: 32 bytes");
    }

    void TestHmacSha256(TestRunner &runner)
    {
        std::array<std::uint8_t, 32> key{};
        key.fill(0x0A);
        const std::uint8_t data[] = {1, 2, 3};

        auto mac = psm::crypto::hmac_sha256(key, data);
        runner.Check(mac.size() == 32, "hmac_sha256: 32 bytes");

        auto mac2 = psm::crypto::hmac_sha256(key, data);
        runner.Check(std::memcmp(mac.data(), mac2.data(), 32) == 0,
                     "hmac_sha256: deterministic");
    }

    void TestSha256MultiSpan(TestRunner &runner)
    {
        const std::uint8_t part1[] = {1, 2, 3};
        const std::uint8_t part2[] = {4, 5, 6};
        const std::uint8_t all[] = {1, 2, 3, 4, 5, 6};

        auto digest1 = psm::crypto::sha256(part1, part2);
        auto digest2 = psm::crypto::sha256(all);
        runner.Check(std::memcmp(digest1.data(), digest2.data(), 32) == 0,
                     "sha256: two-span == single-span (same concatenated input)");
    }

    void TestBase64EdgeCases(TestRunner &runner)
    {
        // 空输入
        auto encoded = psm::crypto::base64_encode({});
        runner.Check(encoded.empty(), "base64: empty input -> empty output");

        // 单字节
        const std::uint8_t one[] = {0x00};
        auto enc_one = psm::crypto::base64_encode(one);
        runner.Check(!enc_one.empty(), "base64: 1 byte encodes non-empty");

        // 解码空串
        auto decoded = psm::crypto::base64_decode("");
        runner.Check(decoded.empty(), "base64: decode empty -> empty");

        // 编码后解码往返
        const std::uint8_t raw[] = {0xDE, 0xAD, 0xBE, 0xEF};
        auto enc = psm::crypto::base64_encode(raw);
        auto dec = psm::crypto::base64_decode(std::string_view(enc.data(), enc.size()));
        runner.Check(dec.size() == 4, "base64: roundtrip size=4");
        runner.Check(std::memcmp(dec.data(), raw, 4) == 0, "base64: roundtrip matches");
    }
} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("CryptoErrorPaths");

    TestBlake3KeyedHash(runner);
    TestBlake3KeyedHasher(runner);
    TestBlake3Hash(runner);
    TestAeadShortCiphertext(runner);
    TestBlockWrongKeyDecrypt(runner);
    TestHkdfExtractExpand(runner);
    TestHmacSha256(runner);
    TestSha256MultiSpan(runner);
    TestBase64EdgeCases(runner);

    return runner.Summary();
}
