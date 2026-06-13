/**
 * @file ShadowtlsTransportPure2.cpp
 * @brief shadowtls transport 纯函数测试
 * @details 通过 #include 源文件访问匿名命名空间中的 compute_write_key 函数。
 */

#include <gtest/gtest.h>

#include <prism/core/core.hpp>

#include "../../src/prism/stealth/facade/shadowtls/transport.cpp"

using psm::stealth::shadowtls::compute_write_key;

namespace
{
    TEST(ShadowtlsTransportPure2, ComputeWriteKeyBasic)
    {
        const char *password = "test_password";
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i)
            server_random[i] = static_cast<std::byte>(i);

        auto key = compute_write_key(password, server_random);
        EXPECT_TRUE(key.size() == 32) << "compute_write_key: size=32";

        // 相同输入产生相同输出
        auto key2 = compute_write_key(password, server_random);
        bool identical = true;
        for (std::size_t i = 0; i < 32; ++i)
            if (key[i] != key2[i]) identical = false;
        EXPECT_TRUE(identical) << "compute_write_key: deterministic";
    }

    TEST(ShadowtlsTransportPure2, ComputeWriteKeyEmptyPassword)
    {
        std::string_view password;
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i)
            server_random[i] = static_cast<std::byte>(i);

        auto key = compute_write_key(password, server_random);
        EXPECT_TRUE(key.size() == 32) << "compute_write_key: empty password -> size=32";
    }

    TEST(ShadowtlsTransportPure2, ComputeWriteKeyEmptyRandom)
    {
        const char *password = "test_password";
        std::span<const std::byte> server_random;

        auto key = compute_write_key(password, server_random);
        EXPECT_TRUE(key.size() == 32) << "compute_write_key: empty random -> size=32";
    }

    TEST(ShadowtlsTransportPure2, ComputeWriteKeyDifferentPasswords)
    {
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i)
            server_random[i] = static_cast<std::byte>(i);

        auto key1 = compute_write_key("password_a", server_random);
        auto key2 = compute_write_key("password_b", server_random);

        bool different = false;
        for (std::size_t i = 0; i < 32; ++i)
            if (key1[i] != key2[i]) different = true;
        EXPECT_TRUE(different) << "compute_write_key: different passwords -> different keys";
    }

    TEST(ShadowtlsTransportPure2, ComputeWriteKeyDifferentRandom)
    {
        std::array<std::byte, 32> random1{};
        std::array<std::byte, 32> random2{};
        for (std::size_t i = 0; i < 32; ++i)
        {
            random1[i] = static_cast<std::byte>(i);
            random2[i] = static_cast<std::byte>(i + 1);
        }

        auto key1 = compute_write_key("same_password", random1);
        auto key2 = compute_write_key("same_password", random2);

        bool different = false;
        for (std::size_t i = 0; i < 32; ++i)
            if (key1[i] != key2[i]) different = true;
        EXPECT_TRUE(different) << "compute_write_key: different random -> different keys";
    }

} // namespace
