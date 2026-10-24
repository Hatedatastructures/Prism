/**
 * @file TuicCodecRoundtripTest.cpp
 * @brief TUIC connect、packet 与 heartbeat 编解码测试。
 */

#include <Prism/Protocols/Tuic/Tuic.hpp>
#include <gtest/gtest.h>

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstdint>
#include <system_error>

namespace Net = boost::asio;

namespace
{
    using TuicAddressType = Prism::Tuic::AddressType;
    using TuicMessage = Prism::Tuic::Message;
    using TuicParser = Prism::Tuic::Parser;
    using TuicSerializer = Prism::Tuic::Serializer;

    TEST(TuicBeast, ConnectRoundtrip)
    {
        TuicMessage Message;
        Message.Cmd = Prism::Tuic::CmdConnect;
        Message.dst.Type = TuicAddressType::Ipv4;
        Message.dst.Host = "127.0.0.1";
        Message.dst.Port = 8080;

        TuicSerializer Serializer;
        Serializer.Reset(Message);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 128> Wire{};
        const auto OutputBuffer = Net::mutable_buffer(
            Wire.data(), Wire.size());
        const auto Total = Serializer.Get(OutputBuffer, ErrorCode);
        EXPECT_FALSE(ErrorCode);

        TuicParser Parser;
        const auto InputBuffer = Net::const_buffer(Wire.data(), Total);
        const auto Parsed = Parser.Put(InputBuffer, ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(Parsed, Total);
        ASSERT_TRUE(Parser.IsDone());
        const auto &Result = Parser.Get();
        EXPECT_EQ(Result.Cmd, Prism::Tuic::CmdConnect);
        EXPECT_EQ(Result.dst.Host, "127.0.0.1");
        EXPECT_EQ(Result.dst.Port, 8080);
    }

    TEST(TuicBeast, PacketRoundtrip)
    {
        TuicMessage Message;
        Message.Cmd = Prism::Tuic::CmdPacket;
        Message.AssocId = 3;
        Message.PktId = 9;
        Message.dst.Type = TuicAddressType::Ipv4;
        Message.dst.Host = "8.8.8.8";
        Message.dst.Port = 53;
        Message.payload = "dns payload";

        TuicSerializer Serializer;
        Serializer.Reset(Message);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 256> Wire{};
        const auto OutputBuffer = Net::mutable_buffer(
            Wire.data(), Wire.size());
        const auto Total = Serializer.Get(OutputBuffer, ErrorCode);
        EXPECT_FALSE(ErrorCode);

        TuicParser Parser;
        const auto InputBuffer = Net::const_buffer(Wire.data(), Total);
        const auto Parsed = Parser.Put(InputBuffer, ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(Parsed, Total);
        ASSERT_TRUE(Parser.IsDone());
        const auto &Result = Parser.Get();
        EXPECT_EQ(Result.Cmd, Prism::Tuic::CmdPacket);
        EXPECT_EQ(Result.AssocId, 3);
        EXPECT_EQ(Result.PktId, 9);
        EXPECT_EQ(Result.dst.Host, "8.8.8.8");
        EXPECT_EQ(Result.payload, "dns payload");
    }

    TEST(TuicBeast, Heartbeat)
    {
        TuicMessage Message;
        Message.Cmd = Prism::Tuic::CmdHeartbeat;
        TuicSerializer Serializer;
        Serializer.Reset(Message);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 8> Wire{};
        const auto OutputBuffer = Net::mutable_buffer(
            Wire.data(), Wire.size());
        const auto Total = Serializer.Get(OutputBuffer, ErrorCode);
        EXPECT_FALSE(ErrorCode);

        TuicParser Parser;
        const auto InputBuffer = Net::const_buffer(Wire.data(), Total);
        const auto Parsed = Parser.Put(InputBuffer, ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(Parsed, Total);
        ASSERT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().Cmd, Prism::Tuic::CmdHeartbeat);
    }
} // namespace
