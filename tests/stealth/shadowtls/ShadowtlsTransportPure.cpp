/**
 * @file ShadowtlsTransportPure.cpp
 * @brief ShadowTLS transport 纯函数测试
 * @details 测试 transport.cpp 中匿名命名空间的纯函数：
 *          compute_write_key。
 *          通过 #include 源文件覆盖编译行。
 */

#include <gtest/gtest.h>

#include <prism/foundation/foundation.hpp>

// #include 源文件增加覆盖率计数
#include "../../src/prism/stealth/facade/shadowtls/transport.cpp"

namespace
{
    using namespace psm::stealth::shadowtls;

    // ─── compute_write_key ─────────────────────────

    TEST(ShadowtlsTransportPure, ComputeWriteKeyBasic)
    {
        const char *password = "test_password";
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i)
            server_random[i] = std::byte{i};

        auto key = compute_write_key(password, server_random);
        EXPECT_TRUE(key.size() == 32) << "compute_write_key: size=32";
    }

    TEST(ShadowtlsTransportPure, ComputeWriteKeyDeterministic)
    {
        const char *password = "mypassword";
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i)
            server_random[i] = std::byte{i + 1};

        auto k1 = compute_write_key(password, server_random);
        auto k2 = compute_write_key(password, server_random);
        EXPECT_TRUE(k1.size() == k2.size()) << "compute_write_key: same sizes";
        bool identical = true;
        for (std::size_t i = 0; i < k1.size(); ++i)
            if (k1[i] != k2[i]) identical = false;
        EXPECT_TRUE(identical) << "compute_write_key: deterministic";
    }

    TEST(ShadowtlsTransportPure, ComputeWriteKeyDifferentPassword)
    {
        std::array<std::byte, 32> server_random{};

        auto k1 = compute_write_key("password1", server_random);
        auto k2 = compute_write_key("password2", server_random);
        EXPECT_TRUE(k1 != k2) << "compute_write_key: different password -> different key";
    }

    TEST(ShadowtlsTransportPure, ComputeWriteKeyDifferentRandom)
    {
        std::array<std::byte, 32> sr1{};
        std::array<std::byte, 32> sr2{};
        sr2[0] = std::byte{0x01};

        auto k1 = compute_write_key("password", sr1);
        auto k2 = compute_write_key("password", sr2);
        EXPECT_TRUE(k1 != k2) << "compute_write_key: different random -> different key";
    }

    TEST(ShadowtlsTransportPure, ComputeWriteKeyEmptyPassword)
    {
        std::array<std::byte, 32> server_random{};
        auto key = compute_write_key("", server_random);
        EXPECT_TRUE(key.size() == 32) << "compute_write_key: empty password -> size=32";
        // 非全零
        bool all_zero = true;
        for (auto b : key)
            if (b != 0) all_zero = false;
        EXPECT_TRUE(!all_zero) << "compute_write_key: empty password -> non-zero key";
    }

    TEST(ShadowtlsTransportPure, ComputeWriteKeyEmptyRandom)
    {
        std::span<const std::byte> empty_random;
        auto key = compute_write_key("password", empty_random);
        EXPECT_TRUE(key.size() == 32) << "compute_write_key: empty random -> size=32";
    }

    TEST(ShadowtlsTransportPure, ComputeWriteKeyLongPassword)
    {
        std::string long_pw(256, 'A');
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i)
            server_random[i] = std::byte{i};

        auto key = compute_write_key(long_pw, server_random);
        EXPECT_TRUE(key.size() == 32) << "compute_write_key: long password -> size=32";
    }

} // namespace
