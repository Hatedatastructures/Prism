/**
 * @file BlockDeep.cpp
 * @brief AES-ECB 深度测试 — gcov 覆盖
 * @details 通过 #include 源文件确保 gcov 计入覆盖行。
 *          覆盖 ecb_encrypt/ecb_decrypt 的 AES-128/AES-256 全路径。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <span>

// 包含源文件以获得 gcov 覆盖
#include "../src/prism/crypto/block.cpp"

using psm::testing::TestRunner;

namespace
{
    using psm::crypto::ecb_encrypt;
    using psm::crypto::ecb_decrypt;

    // ─── AES-128-ECB 往返 ──────────────────────────────

    void TestAes128RoundTrip(TestRunner &runner)
    {
        constexpr std::array<std::uint8_t, 16> key = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        constexpr std::array<std::uint8_t, 16> plain = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

        auto ct = ecb_encrypt(std::span<const std::uint8_t, 16>{plain},
                              std::span<const std::uint8_t>{key.data(), key.size()});
        auto pt = ecb_decrypt(std::span<const std::uint8_t, 16>{ct},
                              std::span<const std::uint8_t>{key.data(), key.size()});

        runner.Check(pt == plain, "aes128: encrypt-decrypt roundtrip");
    }

    // ─── AES-256-ECB 往返 ──────────────────────────────

    void TestAes256RoundTrip(TestRunner &runner)
    {
        constexpr std::array<std::uint8_t, 32> key = {
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
        constexpr std::array<std::uint8_t, 16> plain = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

        auto ct = ecb_encrypt(std::span<const std::uint8_t, 16>{plain},
                              std::span<const std::uint8_t>{key.data(), key.size()});
        auto pt = ecb_decrypt(std::span<const std::uint8_t, 16>{ct},
                              std::span<const std::uint8_t>{key.data(), key.size()});

        runner.Check(pt == plain, "aes256: encrypt-decrypt roundtrip");
    }

    // ─── NIST SP 800-38A 已知向量 ──────────────────────

    void TestAes128NistEncrypt(TestRunner &runner)
    {
        constexpr std::array<std::uint8_t, 16> key = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        constexpr std::array<std::uint8_t, 16> plain = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
        constexpr std::array<std::uint8_t, 16> expected = {
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};

        auto ct = ecb_encrypt(std::span<const std::uint8_t, 16>{plain},
                              std::span<const std::uint8_t>{key.data(), key.size()});
        runner.Check(ct == expected, "nist: aes128 encrypt vector match");
    }

    void TestAes256NistEncrypt(TestRunner &runner)
    {
        constexpr std::array<std::uint8_t, 32> key = {
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
        constexpr std::array<std::uint8_t, 16> plain = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
        constexpr std::array<std::uint8_t, 16> expected = {
            0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
            0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8};

        auto ct = ecb_encrypt(std::span<const std::uint8_t, 16>{plain},
                              std::span<const std::uint8_t>{key.data(), key.size()});
        runner.Check(ct == expected, "nist: aes256 encrypt vector match");
    }

    void TestAes128NistDecrypt(TestRunner &runner)
    {
        constexpr std::array<std::uint8_t, 16> key = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        constexpr std::array<std::uint8_t, 16> ct = {
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
        constexpr std::array<std::uint8_t, 16> expected = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

        auto pt = ecb_decrypt(std::span<const std::uint8_t, 16>{ct},
                              std::span<const std::uint8_t>{key.data(), key.size()});
        runner.Check(pt == expected, "nist: aes128 decrypt vector match");
    }

    // ─── 全零输入 ──────────────────────────────────

    void TestZeroInput(TestRunner &runner)
    {
        constexpr std::array<std::uint8_t, 16> key{};
        constexpr std::array<std::uint8_t, 16> plain{};

        auto ct = ecb_encrypt(std::span<const std::uint8_t, 16>{plain},
                              std::span<const std::uint8_t>{key.data(), key.size()});
        auto pt = ecb_decrypt(std::span<const std::uint8_t, 16>{ct},
                              std::span<const std::uint8_t>{key.data(), key.size()});
        runner.Check(pt == plain, "zero: all-zero roundtrip");
    }

    // ─── AES-256 解密 NIST 向量 ──────────────────────

    void TestAes256NistDecrypt(TestRunner &runner)
    {
        constexpr std::array<std::uint8_t, 32> key = {
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
        constexpr std::array<std::uint8_t, 16> ct = {
            0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
            0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8};
        constexpr std::array<std::uint8_t, 16> expected = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

        auto pt = ecb_decrypt(std::span<const std::uint8_t, 16>{ct},
                              std::span<const std::uint8_t>{key.data(), key.size()});
        runner.Check(pt == expected, "nist: aes256 decrypt vector match");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("BlockDeep");

    TestAes128RoundTrip(runner);
    TestAes256RoundTrip(runner);
    TestAes128NistEncrypt(runner);
    TestAes256NistEncrypt(runner);
    TestAes128NistDecrypt(runner);
    TestAes256NistDecrypt(runner);
    TestZeroInput(runner);

    return runner.Summary();
}
