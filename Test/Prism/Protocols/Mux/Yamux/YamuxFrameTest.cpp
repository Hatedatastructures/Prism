/**
 * @file YamuxFrameTest.cpp
 * @brief Yamux 帧构造与解析值测试。
 */

#include <cstdint>
#include <span>
#include <string>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Mux/Yamux/Yamux.hpp>
#include <gtest/gtest.h>

namespace
{

    namespace Yamux = Prism::Mux::Yamux;
    using Prism::Error;

    TEST(YamuxFrame, BuildDataRoundtrip)
    {
        const std::string payload = "yamux Data";
        const auto wire =
            Yamux::Detail::BuildData(Yamux::Flags::Ack, 7,
                              std::span<const std::uint8_t>(
                                  reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
        Yamux::FrameHeader out{};
        EXPECT_EQ(Yamux::Detail::ParseHeader(std::span<const std::uint8_t>(wire), out), Error::None);
        EXPECT_EQ(out.Type, Yamux::MessageType::Data);
        EXPECT_TRUE(Yamux::HasFlag(out.flag, Yamux::Flags::Ack));
        EXPECT_EQ(out.StreamId, 7u);
    }

} // namespace
