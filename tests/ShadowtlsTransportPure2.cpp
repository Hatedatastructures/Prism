/**
 * @file ShadowtlsTransportPure2.cpp
 * @brief shadowtls transport 纯函数测试
 * @details 通过 #include 源文件访问匿名命名空间中的 compute_write_key 函数。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include "../src/prism/stealth/facade/shadowtls/transport.cpp"

using psm::testing::TestRunner;

using psm::stealth::shadowtls::compute_write_key;

namespace
{
    void TestComputeWriteKeyBasic(TestRunner &runner)
    {
        const char *password = "test_password";
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i)
            server_random[i] = static_cast<std::byte>(i);

        auto key = compute_write_key(password, server_random);
        runner.Check(key.size() == 32, "compute_write_key: size=32");

        // 相同输入产生相同输出
        auto key2 = compute_write_key(password, server_random);
        bool identical = true;
        for (std::size_t i = 0; i < 32; ++i)
            if (key[i] != key2[i]) identical = false;
        runner.Check(identical, "compute_write_key: deterministic");
    }

    void TestComputeWriteKeyEmptyPassword(TestRunner &runner)
    {
        std::string_view password;
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i)
            server_random[i] = static_cast<std::byte>(i);

        auto key = compute_write_key(password, server_random);
        runner.Check(key.size() == 32, "compute_write_key: empty password -> size=32");
    }

    void TestComputeWriteKeyEmptyRandom(TestRunner &runner)
    {
        const char *password = "test_password";
        std::span<const std::byte> server_random;

        auto key = compute_write_key(password, server_random);
        runner.Check(key.size() == 32, "compute_write_key: empty random -> size=32");
    }

    void TestComputeWriteKeyDifferentPasswords(TestRunner &runner)
    {
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i)
            server_random[i] = static_cast<std::byte>(i);

        auto key1 = compute_write_key("password_a", server_random);
        auto key2 = compute_write_key("password_b", server_random);

        bool different = false;
        for (std::size_t i = 0; i < 32; ++i)
            if (key1[i] != key2[i]) different = true;
        runner.Check(different, "compute_write_key: different passwords -> different keys");
    }

    void TestComputeWriteKeyDifferentRandom(TestRunner &runner)
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
        runner.Check(different, "compute_write_key: different random -> different keys");
    }
} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ShadowtlsTransportPure2");

    TestComputeWriteKeyBasic(runner);
    TestComputeWriteKeyEmptyPassword(runner);
    TestComputeWriteKeyEmptyRandom(runner);
    TestComputeWriteKeyDifferentPasswords(runner);
    TestComputeWriteKeyDifferentRandom(runner);

    return runner.Summary();
}
