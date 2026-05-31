/**
 * @file VlessConnPure.cpp
 * @brief VLESS conn 纯函数测试
 * @details 测试 uuid_to_string 格式化
 */

#include <prism/memory.hpp>
#include "../src/prism/protocol/vless/conn.cpp"
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    void TestUuidAllZeros(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> uuid{};
        auto str = psm::protocol::vless::uuid_to_string(uuid);
        runner.Check(str == "00000000-0000-0000-0000-000000000000", "uuid: all zeros");
    }

    void TestUuidAllFF(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> uuid;
        uuid.fill(0xFF);
        auto str = psm::protocol::vless::uuid_to_string(uuid);
        runner.Check(str == "ffffffff-ffff-ffff-ffff-ffffffffffff", "uuid: all 0xFF");
    }

    void TestUuidKnownPattern(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> uuid = {
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef};
        auto str = psm::protocol::vless::uuid_to_string(uuid);
        runner.Check(str == "01234567-89ab-cdef-0123-456789abcdef", "uuid: known pattern");
    }

    void TestUuidLength(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> uuid{};
        auto str = psm::protocol::vless::uuid_to_string(uuid);
        runner.Check(str.size() == 36, "uuid: length=36");
    }

    void TestUuidDashPositions(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> uuid = {
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef};
        auto str = psm::protocol::vless::uuid_to_string(uuid);
        runner.Check(str[8] == '-', "uuid: dash at 8");
        runner.Check(str[13] == '-', "uuid: dash at 13");
        runner.Check(str[18] == '-', "uuid: dash at 18");
        runner.Check(str[23] == '-', "uuid: dash at 23");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("VlessConnPure");

    TestUuidAllZeros(runner);
    TestUuidAllFF(runner);
    TestUuidKnownPattern(runner);
    TestUuidLength(runner);
    TestUuidDashPositions(runner);

    return runner.Summary();
}
