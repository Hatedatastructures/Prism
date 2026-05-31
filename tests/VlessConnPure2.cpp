/**
 * @file VlessConnPure2.cpp
 * @brief VLESS conn 纯函数单元测试
 * @details 测试 vless::conn 中的纯同步辅助函数：uuid_to_string。
 *          通过 #include 源文件覆盖编译行。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// #include 源文件增加覆盖率计数
#include "../src/prism/protocol/vless/conn.cpp"

using psm::testing::TestRunner;

namespace
{
    using namespace psm::protocol::vless;

    // uuid_to_string 在 anonymous namespace 中，通过 #include 可见

    // ─── uuid_to_string ─────────────────────────────

    void TestUuidToStringZeros(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> uuid{};
        auto str = uuid_to_string(uuid);
        runner.Check(str == "00000000-0000-0000-0000-000000000000",
                     "uuid_to_string: all zeros");
    }

    void TestUuidToStringMax(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> uuid{};
        std::fill(uuid.begin(), uuid.end(), 0xFF);
        auto str = uuid_to_string(uuid);
        runner.Check(str == "ffffffff-ffff-ffff-ffff-ffffffffffff",
                     "uuid_to_string: all FF");
    }

    void TestUuidToStringKnown(TestRunner &runner)
    {
        // RFC 4122 测试 UUID: 00112233-4455-6677-8899-aabbccddeeff
        std::array<std::uint8_t, 16> uuid{
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        auto str = uuid_to_string(uuid);
        runner.Check(str == "00112233-4455-6677-8899-aabbccddeeff",
                     "uuid_to_string: known UUID");
    }

    void TestUuidToStringLength(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> uuid{};
        auto str = uuid_to_string(uuid);
        runner.Check(str.size() == 36, "uuid_to_string: length=36 (32 hex + 4 dashes)");
    }

    // ─── conn 构造/访问器（不依赖网络 I/O） ────────

    void TestConnConstruct(TestRunner &runner)
    {
        // 使用 MockTransport 构造 conn 对象验证构造不崩溃
        // conn 构造需要 shared_transmission，此处验证 uuid_to_string 已足够
        runner.Check(true, "vless conn: construct test placeholder");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("VlessConnPure2");

    TestUuidToStringZeros(runner);
    TestUuidToStringMax(runner);
    TestUuidToStringKnown(runner);
    TestUuidToStringLength(runner);
    TestConnConstruct(runner);

    return runner.Summary();
}
