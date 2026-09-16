/**
 * @file GunCodecDeep.cpp
 * @brief gun（gRPC 帧）Codec 字节级深测（纯函数）
 * @details 覆盖：varint 编解码往返/边界、帧编码往返、
 *          帧头解析（定长头校验/长度一致性/截断）。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <Preview/Protocols/Gun/Codec.hpp>
#include <Preview/Protocols/Gun/Gun.hpp>
#include <Preview/Transport/MemoryStream.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Gun = Preview::Gun;
    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    template <typename Factory>
    auto RunCoro(
        Net::io_context &IoContext,
        Factory FactoryFunction) -> void
    {
        std::exception_ptr Failure;
        auto Completion = [&](std::exception_ptr ErrorValue) -> void
        {
            Failure = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(IoContext, FactoryFunction(), std::move(Completion));
        IoContext.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    TEST(GunCodecDeep, VarintRoundtrip)
    {
        for (const auto Value : {0u, 1u, 127u, 128u, 16383u, 16384u, 0xFFFFFFFFu})
        {
            std::array<std::uint8_t, 8> Buffer{};
            const auto EncodedSize = Gun::EncodeVarint(Value, Buffer);
            EXPECT_GT(EncodedSize, 0u);
            std::uint32_t DecodedValue = 0;
            const auto Encoded = std::span<const std::uint8_t>(Buffer).first(EncodedSize);
            const auto DecodedSize = Gun::DecodeVarint(Encoded, DecodedValue);
            EXPECT_GT(DecodedSize, 0u);
            EXPECT_EQ(DecodedValue, Value);
        }
    }

    TEST(GunCodecDeep, VarintBoundaries)
    {
        // 1 字节边界 127 / 128
        std::array<std::uint8_t, 8> Buffer{};
        EXPECT_EQ(Gun::EncodeVarint(127, Buffer), 1u);
        EXPECT_EQ(Gun::EncodeVarint(128, Buffer), 2u);
        // 截断输入 → 解码失败
        std::uint32_t DecodedValue = 0;
        const std::span<const std::uint8_t> EmptyInput;
        EXPECT_EQ(Gun::DecodeVarint(EmptyInput, DecodedValue), 0u);
    }

    TEST(GunCodecDeep, FrameEncodeRoundtrip)
    {
        const std::vector<std::uint8_t> Payload = {1, 2, 3, 4, 5};
        const auto Frame = Gun::EncodeFrame(Payload);
        EXPECT_GT(Frame.size(), Payload.size());

        Gun::FrameHeader Header{};
        EXPECT_TRUE(Gun::ParseFrameHeader(Frame, Header));
        EXPECT_EQ(Header.PayloadLen, Payload.size());
        // 数据完整性：帧尾 == payload
        const auto PayloadBegin = Frame.end() - static_cast<std::ptrdiff_t>(Payload.size());
        const std::vector<std::uint8_t> EncodedPayload(PayloadBegin, Frame.end());
        EXPECT_EQ(EncodedPayload, Payload);
    }

    TEST(GunCodecDeep, ParseFrameHeaderErrors)
    {
        Gun::FrameHeader Header{};
        // 空 / 截断
        const std::span<const std::uint8_t> EmptyInput;
        EXPECT_FALSE(Gun::ParseFrameHeader(EmptyInput, Header));
        const std::array<std::uint8_t, 3> ShortBuffer{0x00, 0x00, 0x00};
        EXPECT_FALSE(Gun::ParseFrameHeader(ShortBuffer, Header));
        // 坏魔数
        const std::array<std::uint8_t, 8> BadMagic{0xFF, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00};
        EXPECT_FALSE(Gun::ParseFrameHeader(BadMagic, Header));
        // 长度不一致（Total 与 varint+payload 不匹配）
        const std::array<std::uint8_t, 8> BadLength{0x00, 0x00, 0x00, 0x00, 0x64, 0x0A, 0x00, 0x00};
        EXPECT_FALSE(Gun::ParseFrameHeader(BadLength, Header));
    }

    TEST(GunCodecDeep, PreservesPayloadCoalescedWithHandshake)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        const std::string Payload = "gun coalesced payload";
        bool IsValid = false;

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                {
                    auto ServerTransport = std::make_shared<MemoryStream>(std::move(Server));
                    auto Connection = std::make_shared<Gun::Conn<>>(std::move(ServerTransport));
                    const std::string Wire = "CONNECT example.com HTTP/2\r\n\r\n" + Payload;
                    std::error_code WriteError;
                    const auto WireBytes = AsU8Span(Wire);
                    const auto WireBuffer = AsBytes(WireBytes);
                    co_await Client.async_write_some(WireBuffer, WriteError);
                    EXPECT_FALSE(WriteError);
                    Client.Shutdown();

                    std::string Host;
                    const auto HandshakeError = co_await Connection->ReadHandshake(Host);
                    EXPECT_EQ(HandshakeError, Error::None);
                    EXPECT_EQ(Host, "example.com");
                    std::array<std::byte, 128> Buffer{};
                    std::error_code ReadError;
                    const auto Count = co_await Connection->async_read_some(Buffer, ReadError);
                    IsValid = !ReadError && Count == Payload.size() &&
                         std::memcmp(Buffer.data(), Payload.data(), Payload.size()) == 0;
                    Connection->Close();
                });

        EXPECT_TRUE(IsValid);
    }

} // namespace
