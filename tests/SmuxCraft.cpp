/**
 * @file SmuxCraft.cpp
 * @brief Smux 帧构建单元测试
 */

#include <prism/multiplex/smux/craft.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include "common/TestRunner.hpp"

#ifdef WIN32
#include <windows.h>
#endif

namespace
{
    psm::testing::TestRunner runner("SmuxCraft");
}

void TestSmuxCraftDataFrame()
{
    runner.LogInfo("=== TestSmuxCraftDataFrame ===");

    std::array<std::byte, 4> payload = {std::byte(0xAA), std::byte(0xBB), std::byte(0xCC), std::byte(0xDD)};
    auto frame = psm::multiplex::smux::make_data_frame(42, std::span<const std::byte>(payload.data(), payload.size()));

    runner.Check(frame.size() == 12, "data frame = 8 header + 4 payload");

    auto* raw = reinterpret_cast<const std::uint8_t*>(frame.data());
    runner.Check(raw[0] == 1, "version byte = 1");
    runner.Check(raw[1] == 2, "cmd byte = PSH(2)");
    runner.Check(raw[2] == 4 && raw[3] == 0, "length = 4 (little-endian)");
    runner.Check(raw[4] == 42 && raw[5] == 0 && raw[6] == 0 && raw[7] == 0,
                 "stream_id = 42 (little-endian)");
    runner.Check(raw[8] == 0xAA && raw[9] == 0xBB && raw[10] == 0xCC && raw[11] == 0xDD,
                 "payload matches input");
}

void TestSmuxCraftSynFrame()
{
    runner.LogInfo("=== TestSmuxCraftSynFrame ===");

    auto frame = psm::multiplex::smux::make_syn_frame(100);

    runner.Check(frame.size() == 8, "syn frame = 8 bytes (header only)");

    auto* raw = frame.data();
    runner.Check(raw[0] == std::byte(1), "version = 1");
    runner.Check(raw[1] == std::byte(0), "cmd = SYN(0)");
    runner.Check(raw[2] == std::byte(0) && raw[3] == std::byte(0), "length = 0");
    runner.Check(raw[4] == std::byte(100) && raw[5] == std::byte(0) &&
                 raw[6] == std::byte(0) && raw[7] == std::byte(0),
                 "stream_id = 100 (little-endian)");
}

void TestSmuxCraftFinFrame()
{
    runner.LogInfo("=== TestSmuxCraftFinFrame ===");

    auto frame = psm::multiplex::smux::make_fin_frame(200);

    runner.Check(frame.size() == 8, "fin frame = 8 bytes (header only)");

    auto* raw = frame.data();
    runner.Check(raw[0] == std::byte(1), "version = 1");
    runner.Check(raw[1] == std::byte(1), "cmd = FIN(1)");
    runner.Check(raw[2] == std::byte(0) && raw[3] == std::byte(0), "length = 0");
    runner.Check(raw[4] == std::byte(200) && raw[5] == std::byte(0) &&
                 raw[6] == std::byte(0) && raw[7] == std::byte(0),
                 "stream_id = 200 (little-endian)");
}

int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    runner.LogInfo("========== SmuxCraft Tests ==========");

    TestSmuxCraftDataFrame();
    TestSmuxCraftSynFrame();
    TestSmuxCraftFinFrame();

    return runner.Summary();
}
