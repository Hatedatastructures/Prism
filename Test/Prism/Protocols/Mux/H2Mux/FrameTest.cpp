/**
 * @file FrameTest.cpp
 * @brief H2Mux 帧构造与解析值测试。
 */

#include <cstdint>
#include <span>
#include <string>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Mux/H2Mux/H2Mux.hpp>
#include <gtest/gtest.h>

namespace
{

    namespace H2Mux = Prism::Mux::H2Mux;
    using Prism::Error;

TEST(MuxBeast, H2muxFrame)
    {
        const std::string payload = "h2mux Data";
        const auto wire = H2Mux::BuildData(
            3, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(payload.data()),
                                             payload.size()));
        H2Mux::FrameHeader out{};
        EXPECT_EQ(H2Mux::ParseHeader(std::span<const std::uint8_t>(wire), out), Error::None);
        EXPECT_EQ(out.Type, H2Mux::FrameType::Data);
        EXPECT_EQ(out.StreamId, 3u);
        EXPECT_EQ(out.length, payload.size());

        // 未知类型必须在帧头阶段拒绝（P-H02）
        const auto BadWire = H2Mux::Build(
            static_cast<H2Mux::FrameType>(0x0A), 3,
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(payload.data()),
                                          payload.size()));
        EXPECT_EQ(H2Mux::ParseHeader(std::span<const std::uint8_t>(BadWire), out), Error::BadMessage);
    }

} // namespace
