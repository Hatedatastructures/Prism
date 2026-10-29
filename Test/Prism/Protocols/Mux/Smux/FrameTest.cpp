/**
 * @file FrameTest.cpp
 * @brief Smux 帧构造与解析值测试。
 */

#include <cstdint>
#include <span>
#include <string>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Mux/Smux/Smux.hpp>
#include <gtest/gtest.h>

namespace
{

    namespace Smux = Prism::Mux::Smux;
    using Prism::Error;

    TEST(SmuxFrame, BuildPushRoundtrip)
    {
        const std::string payload = "smux Data";
        const auto wire =
            Smux::Detail::BuildPush(42, std::span<const std::uint8_t>(
                                     reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
        Smux::FrameHeader out{};
        EXPECT_EQ(Smux::Detail::ParseHeader(std::span<const std::uint8_t>(wire), out), Error::None);
        EXPECT_EQ(out.cmd, Smux::Command::Push);
        EXPECT_EQ(out.StreamId, 42u);
        EXPECT_EQ(
            std::string(reinterpret_cast<const char *>(wire.data() + Smux::FrameHdrsize), payload.size()),
            payload);
    }

} // namespace
