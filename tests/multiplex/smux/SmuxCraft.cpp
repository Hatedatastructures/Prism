/**
 * @file SmuxCraft.cpp
 * @brief Smux 帧构建单元测试
 */

#include <prism/protocol/multiplex/smux/craft.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>

TEST(SmuxCraft, DataFrame)
{
    std::array<std::byte, 4> payload = {std::byte(0xAA), std::byte(0xBB), std::byte(0xCC), std::byte(0xDD)};
    auto frame = psm::multiplex::smux::make_data_frame(42, std::span<const std::byte>(payload.data(), payload.size()));

    EXPECT_TRUE(frame.size() == 12) << "data frame = 8 header + 4 payload";

    auto* raw = reinterpret_cast<const std::uint8_t*>(frame.data());
    EXPECT_TRUE(raw[0] == 1) << "version byte = 1";
    EXPECT_TRUE(raw[1] == 2) << "cmd byte = PSH(2)";
    EXPECT_TRUE(raw[2] == 4 && raw[3] == 0) << "length = 4 (little-endian)";
    EXPECT_TRUE(raw[4] == 42 && raw[5] == 0 && raw[6] == 0 && raw[7] == 0)
        << "stream_id = 42 (little-endian)";
    EXPECT_TRUE(raw[8] == 0xAA && raw[9] == 0xBB && raw[10] == 0xCC && raw[11] == 0xDD)
        << "payload matches input";
}

TEST(SmuxCraft, SynFrame)
{
    auto frame = psm::multiplex::smux::make_syn(100);

    EXPECT_TRUE(frame.size() == 8) << "syn frame = 8 bytes (header only)";

    auto* raw = frame.data();
    EXPECT_TRUE(raw[0] == std::byte(1)) << "version = 1";
    EXPECT_TRUE(raw[1] == std::byte(0)) << "cmd = SYN(0)";
    EXPECT_TRUE(raw[2] == std::byte(0) && raw[3] == std::byte(0)) << "length = 0";
    EXPECT_TRUE(raw[4] == std::byte(100) && raw[5] == std::byte(0) &&
                raw[6] == std::byte(0) && raw[7] == std::byte(0))
        << "stream_id = 100 (little-endian)";
}

TEST(SmuxCraft, FinFrame)
{
    auto frame = psm::multiplex::smux::make_fin(200);

    EXPECT_TRUE(frame.size() == 8) << "fin frame = 8 bytes (header only)";

    auto* raw = frame.data();
    EXPECT_TRUE(raw[0] == std::byte(1)) << "version = 1";
    EXPECT_TRUE(raw[1] == std::byte(1)) << "cmd = FIN(1)";
    EXPECT_TRUE(raw[2] == std::byte(0) && raw[3] == std::byte(0)) << "length = 0";
    EXPECT_TRUE(raw[4] == std::byte(200) && raw[5] == std::byte(0) &&
                raw[6] == std::byte(0) && raw[7] == std::byte(0))
        << "stream_id = 200 (little-endian)";
}
