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

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Prism/Foundation/Utility/Crypto/Blake3.hpp>
#include <Prism/Protocols/Gun/Codec.hpp>
#include <Prism/Protocols/Gun/Gun.hpp>
#include <Prism/Transport/MemoryStream.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Gun = Prism::Gun;
    using Prism::AsBytes;
    using Prism::AsU8Span;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;

    template <typename Awaitable>
    auto RunCoro(
        Net::io_context &IoContext,
        Awaitable Operation) -> void
    {
        std::exception_ptr Failure;
        auto Completion = [&](std::exception_ptr ErrorValue) -> void
        {
            Failure = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(IoContext, std::move(Operation), std::move(Completion));
        IoContext.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    struct GunFactoryExchangeState final
    {
        Prism::Fault::Failure ClientFailure;
        Prism::Fault::Failure ServerFailure;
        std::string Host;
        bool ClientCompleted{false};
        bool ServerCompleted{false};
        bool ClientEcho{false};
        bool ServerEcho{false};
        std::array<std::uint8_t, 32> ClientHash{};
        std::array<std::uint8_t, 32> ServerHash{};
    };

    constexpr std::string_view GunFactoryPayload{"gun-owned-input-payload"};

    auto RunGunClientFactoryExchange(
        Prism::SharedTransmission Transport,
        std::shared_ptr<GunFactoryExchangeState> State) -> Net::awaitable<void>
    {
        auto Operation = Gun::Connect(Gun::ConnectRequest{
            std::move(Transport), "dynamic.example",
            Gun::Config{"/GunService/Tun", "GunService"}});
        auto Connected = co_await std::move(Operation);
        if (!Connected)
        {
            State->ClientFailure = Connected.error();
            State->ClientCompleted = true;
            co_return;
        }
        auto Connection = std::move(*Connected);

        const auto Data = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(GunFactoryPayload.data()),
            GunFactoryPayload.size());
        std::error_code WriteError;
        const auto Write = co_await Connection->WriteSome(Data);
        WriteError = Prism::Fault::ToNative(Write.Failure);
        const auto Written = Write.Bytes;
        if (!WriteError && Written == Data.size())
        {
            std::array<std::byte, 128> Echo{};
            std::error_code ReadError;
            const auto ReadResult = co_await Connection->ReadSome(Echo);
            ReadError = Prism::Fault::ToNative(ReadResult.Failure);
            const auto Read = ReadResult.Bytes;
            if (!ReadError && Read == Data.size() &&
                std::equal(Data.begin(), Data.end(), Echo.begin()))
            {
                State->ClientEcho = true;
                State->ClientHash = Prism::Crypto::Hash(
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(Echo.data()), Read));
            }
        }
        (void)Connection->Close();
        State->ClientCompleted = true;
    }

    auto RunGunServerFactoryExchange(
        Prism::SharedTransmission Transport,
        std::shared_ptr<GunFactoryExchangeState> State) -> Net::awaitable<void>
    {
        auto Operation = Gun::Accept(
            std::move(Transport),
            Gun::Config{"/GunService/Tun", "GunService"});
        auto Accepted = co_await std::move(Operation);
        if (!Accepted)
        {
            State->ServerFailure = Accepted.error();
            State->ServerCompleted = true;
            co_return;
        }
        State->Host = std::move(Accepted->Host);
        auto Connection = std::move(Accepted->Connection);

        std::array<std::byte, 128> Buffer{};
        std::error_code ReadError;
        const auto ReadResult = co_await Connection->ReadSome(Buffer);
        ReadError = Prism::Fault::ToNative(ReadResult.Failure);
        const auto Read = ReadResult.Bytes;
        if (!ReadError && Read == GunFactoryPayload.size())
        {
            const auto Data = std::span<const std::byte>(Buffer.data(), Read);
            std::error_code WriteError;
            const auto Write = co_await Connection->WriteSome(Data);
            WriteError = Prism::Fault::ToNative(Write.Failure);
            const auto Written = Write.Bytes;
            if (!WriteError && Written == Data.size())
            {
                State->ServerEcho = std::equal(
                    Data.begin(), Data.end(),
                    reinterpret_cast<const std::byte *>(GunFactoryPayload.data()));
                State->ServerHash = Prism::Crypto::Hash(
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(Buffer.data()), Read));
            }
        }
        (void)Connection->Close();
        State->ServerCompleted = true;
    }

    struct GunCoalescedPayloadRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
        std::string Payload;
        bool *IsValid;
    };

    /**
     * @brief 驱动 Gun 握手并验证与首包合并到达的 payload。
     * @param Request 双端传输、payload 和结果输出。
     */
    auto RunGunCoalescedPayload(GunCoalescedPayloadRequest Request)
        -> Net::awaitable<void>
    {
        auto Connection = std::make_shared<Gun::Conn<>>(std::move(Request.Server));
        const std::string Wire = "CONNECT example.com HTTP/2\r\n\r\n" + Request.Payload;
        std::error_code WriteError;
        const auto WireBytes = AsU8Span(Wire);
        const auto Write = co_await Request.Client->WriteSome(AsBytes(WireBytes));
        WriteError = Prism::Fault::ToNative(Write.Failure);
        EXPECT_FALSE(WriteError);
        (void)co_await Request.Client->WriteShutdown();

        std::string Host;
        const auto HandshakeResult = co_await Connection->ReadHandshake(Host);
        EXPECT_TRUE(HandshakeResult.has_value());
        EXPECT_EQ(Host, "example.com");
        std::array<std::byte, 128> Buffer{};
        std::error_code ReadError;
        const auto Read = co_await Connection->ReadSome(Buffer);
        ReadError = Prism::Fault::ToNative(Read.Failure);
        const auto Count = Read.Bytes;
        *Request.IsValid = !ReadError && Count == Request.Payload.size() &&
                           std::memcmp(Buffer.data(), Request.Payload.data(), Request.Payload.size()) == 0;
        (void)Connection->Close();
    }

    struct GunConfiguredHandshakeRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
        bool *IsValid;
    };

    /**
     * @brief 验证配置 path/service header 的 Gun 握手边界。
     * @param Request 双端传输和结果输出。
     */
    auto RunGunConfiguredHandshake(GunConfiguredHandshakeRequest Request)
        -> Net::awaitable<void>
    {
        auto Connection = std::make_shared<Gun::Conn<>>(
            std::move(Request.Server), Gun::Config{"/GunService/Tun", "GunService"});
        const std::string Wire =
            "CONNECT example.com HTTP/2\r\n"
            ":path: /GunService/Tun\r\n"
            ":service: GunService\r\n\r\n";
        std::error_code WriteError;
        const auto WireBytes = AsU8Span(Wire);
        const auto Write = co_await Request.Client->WriteSome(AsBytes(WireBytes));
        WriteError = Prism::Fault::ToNative(Write.Failure);
        EXPECT_FALSE(WriteError);
        (void)co_await Request.Client->WriteShutdown();

        std::string Host;
        const auto HandshakeResult = co_await Connection->ReadHandshake(Host);
        *Request.IsValid = HandshakeResult.has_value() && Host == "example.com";
        (void)Connection->Close();
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
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(IoContext.get_executor());
        auto Client = std::make_shared<MemoryStream>(std::move(ClientEndpoint));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
        const std::string Payload = "gun coalesced payload";
        bool IsValid = false;

        RunCoro(IoContext, RunGunCoalescedPayload(GunCoalescedPayloadRequest{
            Client, Server, Payload, &IsValid}));

        EXPECT_TRUE(IsValid);
    }

    TEST(GunCodecDeep, EnforcesConfiguredPathAndServiceHeaders)
    {
        Net::io_context IoContext;
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(IoContext.get_executor());
        auto Client = std::make_shared<MemoryStream>(std::move(ClientEndpoint));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
        bool IsValid = false;

        RunCoro(IoContext, RunGunConfiguredHandshake(GunConfiguredHandshakeRequest{
            Client, Server, &IsValid}));

        EXPECT_TRUE(IsValid);
    }

    TEST(GunCodecDeep, FactoryOwnsTemporaryConfigAndDynamicHostAcrossHandshake)
    {
        Net::io_context IoContext;
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(IoContext.get_executor());
        auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientEndpoint));
        auto ServerTransport = std::make_shared<MemoryStream>(std::move(ServerEndpoint));

        const auto ExpectedHash = Prism::Crypto::Hash(AsU8Span(GunFactoryPayload));
        auto State = std::make_shared<GunFactoryExchangeState>();
        auto ClientOwner = ClientTransport;
        auto ServerOwner = ServerTransport;

        std::exception_ptr Failure;
        std::size_t Completed = 0;
        auto Completion = [&](std::exception_ptr ErrorValue) mutable
        {
            if (ErrorValue && !Failure)
            {
                Failure = ErrorValue;
                (void)ClientOwner->Close();
                (void)ServerOwner->Close();
            }
            ++Completed;
        };
        Net::co_spawn(
            IoContext,
            RunGunClientFactoryExchange(std::move(ClientTransport), State),
            Completion);
        Net::co_spawn(
            IoContext,
            RunGunServerFactoryExchange(std::move(ServerTransport), State),
            Completion);
        IoContext.run();

        ASSERT_EQ(Completed, 2U);
        ASSERT_FALSE(Failure);
        EXPECT_TRUE(State->ClientFailure.Succeeded());
        EXPECT_TRUE(State->ServerFailure.Succeeded());
        EXPECT_EQ(State->Host, "dynamic.example");
        EXPECT_TRUE(State->ClientEcho);
        EXPECT_TRUE(State->ServerEcho);
        EXPECT_TRUE(State->ClientCompleted);
        EXPECT_TRUE(State->ServerCompleted);
        EXPECT_EQ(State->ClientHash, ExpectedHash);
        EXPECT_EQ(State->ServerHash, ExpectedHash);
    }

} // namespace
