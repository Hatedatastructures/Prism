/**
 * @file VmessBeastTest.cpp
 * @brief VMess Beast 风格组件测试
 */

#include <ctime>

#include <boost/asio/buffer.hpp>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include <preview/Protocols/Vmess/Vmess.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Vmess = Preview::Vmess;
    using Preview::Error;
    using Preview::make_error_code;

    constexpr std::array<std::uint8_t, 16> Uuid{0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
                                                0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};

    TEST(VmessBeast, HandshakeRoundtrip)
    {
        Vmess::Message Message;
        Message.uuid = Uuid;
        Message.RequestNonce.fill(0x11);
        Message.RequestKey.fill(0x22);
        Message.Cmd = Vmess::CmdTcp;
        Message.dst.Type = Vmess::AddressType::Ipv4;
        Message.dst.Host = "127.0.0.1";
        Message.dst.Port = 8080;

        Vmess::Serializer Serializer(Uuid);
        Serializer.Reset(Message, static_cast<std::uint64_t>(std::time(nullptr)));
        std::error_code ErrorCode;
        std::array<std::uint8_t, 256> Wire{};
        const auto Total = Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_TRUE(Serializer.IsDone());

        Vmess::Parser Parser(Uuid);
        const auto Parsed = Parser.Put(Net::const_buffer(Wire.data(), Total), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(Parsed, Total);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().Cmd, Vmess::CmdTcp);
        EXPECT_EQ(Parser.Get().dst.Host, "127.0.0.1");
        EXPECT_EQ(Parser.Get().dst.Port, 8080);
    }

    TEST(VmessBeast, SerializerReportsRandomSourceFailure)
    {
        Vmess::Message Message;
        Message.uuid = Uuid;
        Message.Cmd = Vmess::CmdTcp;
        Message.dst.Type = Vmess::AddressType::Ipv4;
        Message.dst.Host = "127.0.0.1";
        Message.dst.Port = 8080;
        Vmess::Serializer SerializerInstance(Uuid, [](std::uint8_t *, int) { return 0; });
        SerializerInstance.Reset(Message, static_cast<std::uint64_t>(std::time(nullptr)));
        std::array<std::uint8_t, 256> Wire{};
        std::error_code ErrorCode;
        EXPECT_EQ(SerializerInstance.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode), 0U);
        EXPECT_EQ(ErrorCode, make_error_code(Error::IoError));
        EXPECT_FALSE(SerializerInstance.IsDone());
    }

    TEST(VmessBeast, WrongUuidRejected)
    {
        constexpr std::array<std::uint8_t, 16> OtherUuid{0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22,
                                                         0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44};
        Vmess::Message Message;
        Message.uuid = OtherUuid;
        Message.RequestNonce.fill(0x11);
        Message.RequestKey.fill(0x22);
        Message.Cmd = static_cast<std::uint8_t>(static_cast<std::uint8_t>(Vmess::Command::Tcp));
        Message.dst.Type = Vmess::AddressType::Ipv4;
        Message.dst.Host = "127.0.0.1";
        Message.dst.Port = 8080;

        Vmess::Serializer Serializer(OtherUuid);
        Serializer.Reset(Message, static_cast<std::uint64_t>(std::time(nullptr)));
        std::error_code ErrorCode;
        std::array<std::uint8_t, 256> Wire{};
        const auto Total = Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);

        Vmess::Parser Parser(Uuid);
        Parser.Put(Net::const_buffer(Wire.data(), Total), ErrorCode);
        EXPECT_EQ(ErrorCode, Error::AuthFailed);
    }

    TEST(VmessBeast, ParseUuidRejectsMisplacedSeparators)
    {
        // 保持 36 字符和 32 个十六进制字符，但破坏标准 8-4-4-4-12 分组。
        constexpr std::string_view Malformed = "123456-789abc-def012-345678-9abcdef0";
        std::array<std::uint8_t, 16> ParsedUuid{};
        EXPECT_FALSE(Vmess::ParseUuid(Malformed, ParsedUuid));
    }

    TEST(VmessBeast, ChunkStreamRoundtrip)
    {
        std::array<std::uint8_t, 16> Key{};
        Key.fill(0x11);
        std::array<std::uint8_t, 16> Iv{};
        Iv.fill(0x22);

        Vmess::ChunkStream Encoder;
        Encoder.Init(Key, Iv);
        Vmess::ChunkStream Decoder;
        Decoder.Init(Key, Iv);

        const std::string Payload = "vmess chunk payload";
        std::string Wire;
        EXPECT_FALSE(Encoder.Encrypt(std::span<const std::uint8_t>(
                                         reinterpret_cast<const std::uint8_t *>(Payload.data()), Payload.size()),
                                     Wire));

        std::string Plain;
        const auto Result = Decoder.Decrypt(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(Wire.data()), Wire.size()),
            Plain);
        EXPECT_FALSE(Result.Ec);
        EXPECT_EQ(Result.Consumed, Wire.size());
        EXPECT_EQ(Plain, Payload);
    }

    TEST(VmessBeast, ResponseHeader)
    {
        Vmess::Message Message{};
        Message.RequestKey.fill(0x11);
        Message.RequestNonce.fill(0x22);
        Message.RespHeader = 0x77;
        std::string Response;
        EXPECT_FALSE(Vmess::MakeResponse(Message, Response));
        EXPECT_EQ(Response.size(), 38);
    }

} // namespace
