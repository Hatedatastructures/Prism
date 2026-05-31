/**
 * @file ShadowtlsTransportPure.cpp
 * @brief ShadowTLS transport 纯函数测试
 * @details 测试 transport.cpp 中匿名命名空间的纯函数：
 *          compute_write_key。
 *          通过 #include 源文件覆盖编译行。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// #include 源文件增加覆盖率计数
#include "../src/prism/stealth/facade/shadowtls/transport.cpp"

using psm::testing::TestRunner;

namespace
{
    using namespace psm::stealth::shadowtls;

    // ─── compute_write_key ─────────────────────────

    void TestComputeWriteKeyBasic(TestRunner &runner)
    {
        const char *password = "test_password";
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i)
            server_random[i] = std::byte{i};

        auto key = compute_write_key(password, server_random);
        runner.Check(key.size() == 32, "compute_write_key: size=32");
    }

    void TestComputeWriteKeyDeterministic(TestRunner &runner)
    {
        const char *password = "mypassword";
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i)
            server_random[i] = std::byte{i + 1};

        auto k1 = compute_write_key(password, server_random);
        auto k2 = compute_write_key(password, server_random);
        runner.Check(k1.size() == k2.size(), "compute_write_key: same sizes");
        bool identical = true;
        for (std::size_t i = 0; i < k1.size(); ++i)
            if (k1[i] != k2[i]) identical = false;
        runner.Check(identical, "compute_write_key: deterministic");
    }

    void TestComputeWriteKeyDifferentPassword(TestRunner &runner)
    {
        std::array<std::byte, 32> server_random{};

        auto k1 = compute_write_key("password1", server_random);
        auto k2 = compute_write_key("password2", server_random);
        runner.Check(k1 != k2, "compute_write_key: different password -> different key");
    }

    void TestComputeWriteKeyDifferentRandom(TestRunner &runner)
    {
        std::array<std::byte, 32> sr1{};
        std::array<std::byte, 32> sr2{};
        sr2[0] = std::byte{0x01};

        auto k1 = compute_write_key("password", sr1);
        auto k2 = compute_write_key("password", sr2);
        runner.Check(k1 != k2, "compute_write_key: different random -> different key");
    }

    void TestComputeWriteKeyEmptyPassword(TestRunner &runner)
    {
        std::array<std::byte, 32> server_random{};
        auto key = compute_write_key("", server_random);
        runner.Check(key.size() == 32, "compute_write_key: empty password -> size=32");
        // 非全零
        bool all_zero = true;
        for (auto b : key)
            if (b != 0) all_zero = false;
        runner.Check(!all_zero, "compute_write_key: empty password -> non-zero key");
    }

    void TestComputeWriteKeyEmptyRandom(TestRunner &runner)
    {
        std::span<const std::byte> empty_random;
        auto key = compute_write_key("password", empty_random);
        runner.Check(key.size() == 32, "compute_write_key: empty random -> size=32");
    }

    void TestComputeWriteKeyLongPassword(TestRunner &runner)
    {
        std::string long_pw(256, 'A');
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i)
            server_random[i] = std::byte{i};

        auto key = compute_write_key(long_pw, server_random);
        runner.Check(key.size() == 32, "compute_write_key: long password -> size=32");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ShadowtlsTransportPure");

    // compute_write_key
    TestComputeWriteKeyBasic(runner);
    TestComputeWriteKeyDeterministic(runner);
    TestComputeWriteKeyDifferentPassword(runner);
    TestComputeWriteKeyDifferentRandom(runner);
    TestComputeWriteKeyEmptyPassword(runner);
    TestComputeWriteKeyEmptyRandom(runner);
    TestComputeWriteKeyLongPassword(runner);

    return runner.Summary();
}
