/**
 * @file Ss2022ConnDatagramTest.cpp
 * @brief SS2022 Conn 数据报长度帧、SIP022 packet 与读取终态契约。
 */
#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/this_coro.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Shadowsocks2022/Conn.hpp>
#include <Prism/Protocols/Shadowsocks2022/ConnOptions.hpp>
#include <Prism/Protocols/Shadowsocks2022/ConnRecord.hpp>
#include <Prism/Protocols/Shadowsocks2022/ConnSession.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestState.hpp>
#include <Prism/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace SS2022 = Prism::Shadowsocks2022;
    namespace Fault = Prism::Fault;
    using Key = std::array<std::uint8_t, 16>;

    inline constexpr std::size_t ConnDatagramLengthPrefixBytes = 4U;
    inline constexpr std::size_t ConnDatagramReadBufferBytes = 512U;

    [[nodiscard]] auto TestKey() -> Key
    {
        return {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
                0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50};
    }

    [[nodiscard]] auto TestSalt() -> Key
    {
        return {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    }

    auto FillDeterministicSalt(std::uint8_t *Output, const int Size) -> int
    {
        const auto Salt = TestSalt();
        if (Size != static_cast<int>(Salt.size()))
        {
            return 0;
        }
        std::memcpy(Output, Salt.data(), Salt.size());
        return 1;
    }

    struct ConnDatagramHandshake final
    {
        Key Psk;
        std::vector<std::byte> Request;
    };

    [[nodiscard]] auto MakeConnDatagramHandshake() -> ConnDatagramHandshake
    {
        const auto Psk = TestKey();
        SS2022::Message Message;
        Message.dst.Type = SS2022::AddressType::Domain;
        Message.dst.Host = "example.com";
        Message.dst.Port = 443;
        SS2022::Serializer Serializer(Psk, FillDeterministicSalt);
        const auto Now = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        Serializer.Reset(Message, Now);
        std::array<std::uint8_t, 2048> Wire{};
        std::error_code Failure;
        const auto Size = Serializer.Get(boost::asio::buffer(Wire), Failure);
        if (Failure || Size == 0U || !Serializer.IsDone())
        {
            return {Psk, {}};
        }
        std::vector<std::byte> Request;
        Request.reserve(Size);
        for (std::size_t Index = 0; Index < Size; ++Index)
        {
            Request.push_back(static_cast<std::byte>(Wire[Index]));
        }
        return {Psk, std::move(Request)};
    }

    class ConnScriptedTransmission final : public Prism::Transmission
    {
    public:
        ConnScriptedTransmission(
            Net::any_io_executor Executor,
            std::vector<std::uint8_t> Input)
            : Prism::Transmission(std::move(Executor)), Input_(std::move(Input))
        {
        }

        auto InjectBytes(std::vector<std::uint8_t> Bytes) -> void
        {
            Input_.insert(Input_.end(), Bytes.begin(), Bytes.end());
        }

        auto InjectTerminalBytes(
            std::vector<std::uint8_t> Bytes,
            Fault::Failure Terminal) -> void
        {
            InjectBytes(std::move(Bytes));
            Terminal_ = std::move(Terminal);
        }

        auto SetMaxReadChunk(std::size_t Size) noexcept -> void
        {
            MaxReadChunk_ = Size;
        }

        auto ClearReadObservations() -> void
        {
            ReadsDone_ = 0;
            ReadSizes_.clear();
        }

        [[nodiscard]] auto ReadsDone() const noexcept -> std::size_t
        {
            return ReadsDone_;
        }

        [[nodiscard]] auto ReadSizes() const noexcept
            -> const std::vector<std::size_t> &
        {
            return ReadSizes_;
        }

        [[nodiscard]] auto BytesRemaining() const noexcept -> std::size_t
        {
            return Input_.size() - Offset_;
        }

        [[nodiscard]] auto Written() const noexcept
            -> const std::vector<std::uint8_t> &
        {
            return Written_;
        }

        auto ClearWritten() -> void
        {
            Written_.clear();
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadsDone_;
            const auto Count = (std::min)(
                (std::min)(Buffer.size(), Input_.size() - Offset_), MaxReadChunk_);
            ReadSizes_.push_back(Count);
            if (Count != 0U)
            {
                std::memcpy(Buffer.data(), Input_.data() + Offset_, Count);
                Offset_ += Count;
            }
            const auto Failure = Offset_ == Input_.size() && Terminal_
                ? *Terminal_ : Fault::Failure{};
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Count, Failure});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            for (const auto Byte : Buffer)
            {
                Written_.push_back(std::to_integer<std::uint8_t>(Byte));
            }
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        std::vector<std::uint8_t> Input_;
        std::vector<std::uint8_t> Written_;
        std::vector<std::size_t> ReadSizes_;
        std::optional<Fault::Failure> Terminal_{};
        std::size_t Offset_{0};
        std::size_t ReadsDone_{0};
        std::size_t MaxReadChunk_{(std::numeric_limits<std::size_t>::max)()};
    };

    struct ConnDatagramFixture final
    {
        std::shared_ptr<ConnScriptedTransmission> Raw;
        SS2022::SharedConn Connection;
    };

    struct ConnDatagramWireRecipe final
    {
        std::vector<std::uint8_t> SessionKey;
        std::array<std::uint8_t, SS2022::SessionIdLen> SessionId;
        std::uint64_t PacketId;
        std::uint64_t Timestamp;
        SS2022::Address Target;
        std::array<std::uint8_t, 3> Payload;
    };

    [[nodiscard]] auto DecodeConnDatagramLength(
        std::span<const std::uint8_t> Prefix) -> std::uint32_t
    {
        if (Prefix.size() < ConnDatagramLengthPrefixBytes)
        {
            return 0U;
        }
        return static_cast<std::uint32_t>(Prefix[0]) << 24U |
            static_cast<std::uint32_t>(Prefix[1]) << 16U |
            static_cast<std::uint32_t>(Prefix[2]) << 8U |
            static_cast<std::uint32_t>(Prefix[3]);
    }

    auto AppendConnDatagramLength(
        std::vector<std::uint8_t> &Wire,
        const std::uint32_t PacketLength) -> void
    {
        Wire.push_back(static_cast<std::uint8_t>(PacketLength >> 24U));
        Wire.push_back(static_cast<std::uint8_t>(PacketLength >> 16U));
        Wire.push_back(static_cast<std::uint8_t>(PacketLength >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(PacketLength));
    }

    [[nodiscard]] auto HasConnDatagramLengthPrefix(
        std::span<const std::uint8_t> Wire) -> bool
    {
        return Wire.size() > ConnDatagramLengthPrefixBytes &&
            DecodeConnDatagramLength(Wire.first(ConnDatagramLengthPrefixBytes)) ==
                Wire.size() - ConnDatagramLengthPrefixBytes;
    }

    /** @brief 逐字段核对 SS2022 地址。 */
    auto ExpectAddressEquals(
        const SS2022::Address &Actual,
        const SS2022::Address &Expected) -> void
    {
        EXPECT_EQ(Actual.Type, Expected.Type);
        EXPECT_EQ(Actual.Host, Expected.Host);
        EXPECT_EQ(Actual.Port, Expected.Port);
    }

    [[nodiscard]] auto BuildConnDatagramWire(const ConnDatagramWireRecipe &Recipe)
        -> std::vector<std::uint8_t>
    {
        const auto Packet = SS2022::BuildUdpPacket(SS2022::UdpBuildInput{
            Recipe.SessionKey,
            Recipe.PacketId,
            &Recipe.Target,
            Recipe.Payload,
            Recipe.SessionId,
            Recipe.Timestamp});
        if (Packet.empty())
        {
            return {};
        }
        std::vector<std::uint8_t> Wire;
        Wire.reserve(ConnDatagramLengthPrefixBytes + Packet.size());
        AppendConnDatagramLength(Wire, static_cast<std::uint32_t>(Packet.size()));
        Wire.insert(Wire.end(), Packet.begin(), Packet.end());
        return Wire;
    }

    [[nodiscard]] auto MakeConnDatagramWireRecipe()
        -> std::optional<ConnDatagramWireRecipe>
    {
        const auto Psk = TestKey();
        const auto Salt = TestSalt();
        const auto SessionKey = SS2022::SessionKey(
            Psk, Salt, SS2022::AeadKeyLen);
        const std::array<std::uint8_t, SS2022::SessionIdLen> SessionId{
            0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U};
        const auto Target = SS2022::Address{
            SS2022::AddressType::Ipv4, "1.2.3.4", 443};
        const std::array<std::uint8_t, 3> Payload{0xA1U, 0xB2U, 0xC3U};
        const auto Timestamp = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        constexpr std::uint64_t PacketId = 0U;
        const auto Packet = SS2022::BuildUdpPacket(SS2022::UdpBuildInput{
            SessionKey, PacketId, &Target, Payload, SessionId, Timestamp});
        if (Packet.empty())
        {
            return std::nullopt;
        }
        return ConnDatagramWireRecipe{
            SessionKey, SessionId, PacketId, Timestamp, Target, Payload};
    }

    auto OpenConnDatagramFixture(
        Net::any_io_executor Executor,
        const ConnDatagramHandshake &Handshake) -> Net::awaitable<ConnDatagramFixture>
    {
        std::vector<std::uint8_t> Input;
        Input.reserve(Handshake.Request.size());
        for (const auto Byte : Handshake.Request)
        {
            Input.push_back(std::to_integer<std::uint8_t>(Byte));
        }
        auto Raw = std::make_shared<ConnScriptedTransmission>(
            std::move(Executor), std::move(Input));
        SS2022::ServerConfig Config;
        Config.Psk = Handshake.Psk;
        auto Accepted = co_await SS2022::Accept(Raw, Config);
        EXPECT_TRUE(Accepted);
        if (!Accepted)
        {
            const auto Closed = Raw->Close();
            if (!Closed)
            {
                (void)Raw->Cancel();
            }
            const auto Activity = Raw->Activity();
            if (Activity)
            {
                const auto Drained = co_await Activity->Drain();
                EXPECT_TRUE(Drained.has_value());
                EXPECT_TRUE(Activity->IsRetired());
            }
            EXPECT_TRUE(Closed);
            co_return ConnDatagramFixture{std::move(Raw), {}};
        }
        co_return ConnDatagramFixture{std::move(Raw), std::move(Accepted->Connection)};
    }

    auto CloseConnDatagramFixture(ConnDatagramFixture &Fixture)
        -> Net::awaitable<bool>
    {
        if (!Fixture.Connection || !Fixture.Raw)
        {
            co_return false;
        }
        const auto Closed = Fixture.Connection->Close();
        const auto ConnectionActivity = Fixture.Connection->Activity();
        const auto RawActivity = Fixture.Raw->Activity();
        if (!Closed)
        {
            (void)Fixture.Connection->Cancel();
            if (!Fixture.Raw->Close())
            {
                (void)Fixture.Raw->Cancel();
            }
        }
        if (!ConnectionActivity || !RawActivity)
        {
            if (ConnectionActivity)
            {
                (void)co_await ConnectionActivity->Drain();
            }
            if (RawActivity)
            {
                (void)co_await RawActivity->Drain();
            }
            co_return false;
        }
        const auto ConnectionDrained = co_await ConnectionActivity->Drain();
        const auto RawDrained = co_await RawActivity->Drain();
        co_return Closed && ConnectionDrained.has_value() && ConnectionActivity->IsRetired() &&
            RawDrained.has_value() && RawActivity->IsRetired();
    }

    struct ConnDatagramTerminalScenario final
    {
        std::size_t BytesBeforeTerminal;
        Fault::Failure Terminal;
        Prism::Error FirstError;
        Prism::Error StickyError;
        bool ExpectPacket;
    };

    struct ConnDatagramTerminalInput final
    {
        ConnDatagramWireRecipe WireRecipe;
        SS2022::Address ExpectedTarget;
        std::vector<std::uint8_t> ExpectedPayload;
        ConnDatagramTerminalScenario Scenario;
    };

    auto RunConnDatagramTerminalScenario(
        ConnDatagramTerminalInput Input) -> Net::awaitable<void>
    {
        const auto Wire = BuildConnDatagramWire(Input.WireRecipe);
        if (!HasConnDatagramLengthPrefix(Wire))
        {
            ADD_FAILURE() << "当前 SS2022 packet 未能构成 4 字节长度帧";
            co_return;
        }
        const auto Handshake = MakeConnDatagramHandshake();
        auto Fixture = co_await OpenConnDatagramFixture(
            co_await Net::this_coro::executor, Handshake);
        if (!Fixture.Connection)
        {
            ADD_FAILURE() << "有效 SS2022 握手没有建立公开 Conn";
            co_return;
        }
        Fixture.Raw->ClearReadObservations();
        Fixture.Raw->InjectTerminalBytes(
            std::vector<std::uint8_t>(
                Wire.begin(), Wire.begin() + static_cast<std::ptrdiff_t>(
                    Input.Scenario.BytesBeforeTerminal)),
            Input.Scenario.Terminal);
        const SS2022::Address SentinelTarget{
            SS2022::AddressType::Domain, "preserved.invalid", 43123};
        const std::vector<std::uint8_t> SentinelPayload{
            0xD1U, 0xE2U, 0xF3U, 0xA4U};
        auto Target = SentinelTarget;
        auto Payload = SentinelPayload;
        const auto First = co_await Fixture.Connection->AsyncReceiveDatagram(Target, Payload);
        EXPECT_EQ(First, Input.Scenario.FirstError);
        EXPECT_EQ(Fixture.Raw->ReadsDone(), 1U);
        if (Input.Scenario.ExpectPacket)
        {
            ExpectAddressEquals(Target, Input.ExpectedTarget);
            EXPECT_EQ(Payload, Input.ExpectedPayload);
        }
        else
        {
            ExpectAddressEquals(Target, SentinelTarget);
            EXPECT_EQ(Payload, SentinelPayload);
        }
        const auto ExpectedTarget = Input.Scenario.ExpectPacket
            ? Input.ExpectedTarget : SentinelTarget;
        const auto ExpectedPayload = Input.Scenario.ExpectPacket
            ? Input.ExpectedPayload : SentinelPayload;
        const auto Reads = Fixture.Raw->ReadsDone();
        for (int Attempt = 0; Attempt < 2; ++Attempt)
        {
            EXPECT_EQ(
                co_await Fixture.Connection->AsyncReceiveDatagram(Target, Payload),
                Input.Scenario.StickyError);
            ExpectAddressEquals(Target, ExpectedTarget);
            EXPECT_EQ(Payload, ExpectedPayload);
            EXPECT_EQ(Fixture.Raw->ReadsDone(), Reads);
        }
        if (!Input.Scenario.ExpectPacket)
        {
            SS2022::Address EmptyTarget{};
            std::vector<std::uint8_t> EmptyPayload;
            EXPECT_EQ(
                co_await Fixture.Connection->AsyncReceiveDatagram(
                    EmptyTarget, EmptyPayload),
                Input.Scenario.StickyError);
            EXPECT_EQ(EmptyTarget.Type, SS2022::AddressType::Domain);
            EXPECT_TRUE(EmptyTarget.Host.empty());
            EXPECT_EQ(EmptyTarget.Port, 0U);
            EXPECT_TRUE(EmptyPayload.empty());
            EXPECT_EQ(Fixture.Raw->ReadsDone(), Reads);
        }
        EXPECT_TRUE(co_await CloseConnDatagramFixture(Fixture));
    }

    auto RunConnDatagramTerminalMatrix() -> Net::awaitable<void>
    {
        const auto WireRecipe = MakeConnDatagramWireRecipe();
        if (!WireRecipe)
        {
            ADD_FAILURE() << "未能构造符合 Conn 数据报 stream framing 的固定 wire";
            co_return;
        }
        const auto PreviewWire = BuildConnDatagramWire(*WireRecipe);
        if (!HasConnDatagramLengthPrefix(PreviewWire))
        {
            ADD_FAILURE() << "SS2022 packet 长度前缀与完整 wire 长度不匹配";
            co_return;
        }
        const auto PacketOffset = ConnDatagramLengthPrefixBytes;
        const auto SeparateEnd = PacketOffset + SS2022::SeparateHdrLen;
        const auto NativeReset = Fault::Failure{
            Fault::Code::ConnectionReset,
            std::make_error_code(std::errc::connection_reset)};
        const auto NativeEof = Fault::Failure{Fault::Code::Eof};
        const auto NativeTimeout = Fault::Failure{
            Fault::Code::Timeout, std::make_error_code(std::errc::timed_out)};
        /** @brief 偏移始终从长度前缀起算；packet body 在 Separate Header 后均为密文。 */
        const std::array<ConnDatagramTerminalScenario, 9> Scenarios{{
            {2U, NativeEof,
             Prism::Error::UnexpectedEof, Prism::Error::UnexpectedEof, false},
            {3U, NativeReset,
             Prism::Error::IoError, Prism::Error::IoError, false},
            {PacketOffset, NativeReset,
             Prism::Error::IoError, Prism::Error::IoError, false},
            {PacketOffset + SS2022::SeparateHdrLen / 2U, NativeReset,
             Prism::Error::IoError, Prism::Error::IoError, false},
            {SeparateEnd, NativeTimeout,
             Prism::Error::Timeout, Prism::Error::Timeout, false},
            {PreviewWire.size() - 1U, NativeReset,
             Prism::Error::IoError, Prism::Error::IoError, false},
            /** @brief 长度前缀仍合法，但 packet body 尾部缺一字节后遇到 EOF。 */
            {PreviewWire.size() - 1U, NativeEof,
             Prism::Error::UnexpectedEof, Prism::Error::UnexpectedEof, false},
            {PreviewWire.size(), NativeReset,
             Prism::Error::None, Prism::Error::IoError, true},
            {PreviewWire.size(), NativeEof,
             Prism::Error::None, Prism::Error::UnexpectedEof, true},
        }};
        for (const auto &Scenario : Scenarios)
        {
            co_await RunConnDatagramTerminalScenario(ConnDatagramTerminalInput{
                *WireRecipe,
                WireRecipe->Target,
                std::vector<std::uint8_t>(
                    WireRecipe->Payload.begin(), WireRecipe->Payload.end()),
                Scenario});
        }
    }

    auto RunPublicSendFrameContract() -> Net::awaitable<void>
    {
        const auto Handshake = MakeConnDatagramHandshake();
        auto Fixture = co_await OpenConnDatagramFixture(
            co_await Net::this_coro::executor, Handshake);
        if (!Fixture.Connection)
        {
            ADD_FAILURE() << "有效 SS2022 握手没有建立公开 Conn";
            co_return;
        }
        if (Fixture.Raw->Written().size() < TestSalt().size())
        {
            ADD_FAILURE() << "SS2022 服务端握手没有完成";
            EXPECT_TRUE(co_await CloseConnDatagramFixture(Fixture));
            co_return;
        }
        Fixture.Raw->ClearWritten();
        const auto Target = SS2022::Address{
            SS2022::AddressType::Ipv4, "203.0.113.9", 5353};
        const std::array<std::uint8_t, 4> Payload{0x71U, 0x82U, 0x93U, 0xA4U};
        EXPECT_EQ(
            co_await Fixture.Connection->AsyncSendDatagram(Target, Payload),
            Prism::Error::None);

        const auto Wire = Fixture.Raw->Written();
        if (!HasConnDatagramLengthPrefix(Wire))
        {
            ADD_FAILURE() << "公开发送没有写出正确的 4 字节大端长度帧";
            EXPECT_TRUE(co_await CloseConnDatagramFixture(Fixture));
            co_return;
        }
        const auto PacketLength = DecodeConnDatagramLength(
            std::span<const std::uint8_t>(Wire).first(ConnDatagramLengthPrefixBytes));
        if (PacketLength != Wire.size() - ConnDatagramLengthPrefixBytes)
        {
            ADD_FAILURE() << "公开发送的外层长度与完整 wire 不匹配";
            EXPECT_TRUE(co_await CloseConnDatagramFixture(Fixture));
            co_return;
        }
        SS2022::Address ParsedTarget{};
        std::vector<std::uint8_t> ParsedPayload;
        std::uint64_t PacketId = 0;
        std::uint64_t Timestamp = 0;
        std::uint8_t HeaderType = 0;
        const auto SessionKey = SS2022::SessionKey(
            Handshake.Psk, TestSalt(), SS2022::AeadKeyLen);
        const auto ParseError = SS2022::ParseUdpPacket(SS2022::UdpParseInput{
            SessionKey,
            std::span<const std::uint8_t>(Wire).subspan(ConnDatagramLengthPrefixBytes),
            &ParsedTarget,
            &ParsedPayload,
            nullptr,
            &PacketId,
            &Timestamp,
            &HeaderType});
        EXPECT_EQ(ParseError, Prism::Error::None);
        ExpectAddressEquals(ParsedTarget, Target);
        EXPECT_EQ(ParsedPayload, std::vector<std::uint8_t>(Payload.begin(), Payload.end()));
        EXPECT_EQ(PacketId, 1U);
        EXPECT_EQ(HeaderType, SS2022::HeaderTypeClient);
        EXPECT_NE(Timestamp, 0U);

        auto Receiver = co_await OpenConnDatagramFixture(
            co_await Net::this_coro::executor, Handshake);
        if (!Receiver.Connection)
        {
            ADD_FAILURE() << "第二条有效握手没有建立公开 Conn";
            EXPECT_TRUE(co_await CloseConnDatagramFixture(Fixture));
            co_return;
        }
        Receiver.Raw->InjectBytes(Wire);
        SS2022::Address ReceivedTarget{};
        std::vector<std::uint8_t> ReceivedPayload;
        EXPECT_EQ(
            co_await Receiver.Connection->AsyncReceiveDatagram(
                ReceivedTarget, ReceivedPayload),
            Prism::Error::None);
        ExpectAddressEquals(ReceivedTarget, Target);
        EXPECT_EQ(ReceivedPayload, std::vector<std::uint8_t>(Payload.begin(), Payload.end()));
        EXPECT_TRUE(co_await CloseConnDatagramFixture(Receiver));
        EXPECT_TRUE(co_await CloseConnDatagramFixture(Fixture));
    }

    auto RunPublicReceiveFrame(
        std::vector<std::uint8_t> Wire,
        const ConnDatagramWireRecipe &Recipe,
        const std::size_t MaxReadChunk) -> Net::awaitable<void>
    {
        const auto Handshake = MakeConnDatagramHandshake();
        auto Fixture = co_await OpenConnDatagramFixture(
            co_await Net::this_coro::executor, Handshake);
        if (!Fixture.Connection)
        {
            ADD_FAILURE() << "有效 SS2022 握手没有建立公开 Conn";
            co_return;
        }
        Fixture.Raw->ClearReadObservations();
        Fixture.Raw->SetMaxReadChunk(MaxReadChunk);
        Fixture.Raw->InjectBytes(std::move(Wire));
        SS2022::Address Target{};
        std::vector<std::uint8_t> Payload;
        EXPECT_EQ(
            co_await Fixture.Connection->AsyncReceiveDatagram(Target, Payload),
            Prism::Error::None);
        ExpectAddressEquals(Target, Recipe.Target);
        EXPECT_EQ(Payload, std::vector<std::uint8_t>(
            Recipe.Payload.begin(), Recipe.Payload.end()));
        EXPECT_GT(Fixture.Raw->ReadsDone(), 1U);
        for (const auto ReadSize : Fixture.Raw->ReadSizes())
        {
            EXPECT_LE(ReadSize, MaxReadChunk);
        }
        EXPECT_EQ(Fixture.Raw->BytesRemaining(), 0U);
        EXPECT_TRUE(co_await CloseConnDatagramFixture(Fixture));
    }

    auto RunCoalescedReceiveFrames() -> Net::awaitable<void>
    {
        const auto FirstRecipe = MakeConnDatagramWireRecipe();
        if (!FirstRecipe)
        {
            ADD_FAILURE() << "未能构造固定 SIP022 packet";
            co_return;
        }
        auto SecondRecipe = *FirstRecipe;
        SecondRecipe.PacketId = 1U;
        SecondRecipe.Payload = {0xD4U, 0xE5U, 0xF6U};
        const auto FirstWire = BuildConnDatagramWire(*FirstRecipe);
        const auto SecondWire = BuildConnDatagramWire(SecondRecipe);
        std::vector<std::uint8_t> Combined = FirstWire;
        Combined.insert(Combined.end(), SecondWire.begin(), SecondWire.end());
        if (Combined.size() > ConnDatagramReadBufferBytes)
        {
            ADD_FAILURE() << "两条固定数据报帧超过单次底层读取缓冲";
            co_return;
        }
        const auto Handshake = MakeConnDatagramHandshake();
        auto Fixture = co_await OpenConnDatagramFixture(
            co_await Net::this_coro::executor, Handshake);
        if (!Fixture.Connection)
        {
            ADD_FAILURE() << "有效 SS2022 握手没有建立公开 Conn";
            co_return;
        }
        Fixture.Raw->ClearReadObservations();
        Fixture.Raw->SetMaxReadChunk(Combined.size());
        Fixture.Raw->InjectBytes(std::move(Combined));
        SS2022::Address Target{};
        std::vector<std::uint8_t> Payload;
        EXPECT_EQ(
            co_await Fixture.Connection->AsyncReceiveDatagram(Target, Payload),
            Prism::Error::None);
        ExpectAddressEquals(Target, FirstRecipe->Target);
        EXPECT_EQ(Payload, std::vector<std::uint8_t>(
            FirstRecipe->Payload.begin(), FirstRecipe->Payload.end()));
        EXPECT_EQ(Fixture.Raw->ReadsDone(), 1U);
        if (Fixture.Raw->ReadSizes().size() != 1U)
        {
            ADD_FAILURE() << "两条合帧输入未由一次底层读取交付";
            EXPECT_TRUE(co_await CloseConnDatagramFixture(Fixture));
            co_return;
        }
        EXPECT_EQ(Fixture.Raw->ReadSizes().front(), FirstWire.size() + SecondWire.size());
        EXPECT_EQ(Fixture.Raw->BytesRemaining(), 0U);

        EXPECT_EQ(
            co_await Fixture.Connection->AsyncReceiveDatagram(Target, Payload),
            Prism::Error::None);
        ExpectAddressEquals(Target, SecondRecipe.Target);
        EXPECT_EQ(Payload, std::vector<std::uint8_t>(
            SecondRecipe.Payload.begin(), SecondRecipe.Payload.end()));
        EXPECT_EQ(Fixture.Raw->ReadsDone(), 1U);
        EXPECT_TRUE(co_await CloseConnDatagramFixture(Fixture));
    }

    auto RunRejectLengthBeforeBodyRead(const std::uint32_t PacketLength)
        -> Net::awaitable<void>
    {
        const auto Handshake = MakeConnDatagramHandshake();
        auto Fixture = co_await OpenConnDatagramFixture(
            co_await Net::this_coro::executor, Handshake);
        if (!Fixture.Connection)
        {
            ADD_FAILURE() << "有效 SS2022 握手没有建立公开 Conn";
            co_return;
        }
        std::vector<std::uint8_t> Prefix;
        AppendConnDatagramLength(Prefix, PacketLength);
        Fixture.Raw->ClearReadObservations();
        Fixture.Raw->InjectBytes(std::move(Prefix));
        SS2022::Address Target{};
        std::vector<std::uint8_t> Payload;
        EXPECT_EQ(
            co_await Fixture.Connection->AsyncReceiveDatagram(Target, Payload),
            Prism::Error::BadLength);
        EXPECT_EQ(Fixture.Raw->ReadsDone(), 1U);
        if (Fixture.Raw->ReadSizes().size() != 1U)
        {
            ADD_FAILURE() << "非法数据报长度检查前发生了额外底层读取";
            EXPECT_TRUE(co_await CloseConnDatagramFixture(Fixture));
            co_return;
        }
        EXPECT_EQ(Fixture.Raw->ReadSizes().front(), ConnDatagramLengthPrefixBytes);
        EXPECT_EQ(Fixture.Raw->BytesRemaining(), 0U);
        EXPECT_TRUE(Payload.empty());
        EXPECT_TRUE(co_await CloseConnDatagramFixture(Fixture));
    }

    auto RunCoroutine(Net::awaitable<void> Operation) -> void
    {
        Net::io_context Io;
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Operation),
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    TEST(Ss2022ConnDatagramTerminal, PublicReceivePreservesFieldsAndCiphertext)
    {
        RunCoroutine(RunConnDatagramTerminalMatrix());
    }

    TEST(Ss2022ConnDatagram, PublicSendUsesLengthPrefixedSip022Packet)
    {
        RunCoroutine(RunPublicSendFrameContract());
    }

    TEST(Ss2022ConnDatagram, PublicReceiveAssemblesFragmentedFrame)
    {
        const auto Recipe = MakeConnDatagramWireRecipe();
        ASSERT_TRUE(Recipe);
        RunCoroutine(RunPublicReceiveFrame(
            BuildConnDatagramWire(*Recipe), *Recipe, 3U));
    }

    TEST(Ss2022ConnDatagram, PublicReceiveKeepsSecondCoalescedFrame)
    {
        RunCoroutine(RunCoalescedReceiveFrames());
    }

    TEST(Ss2022ConnDatagram, PublicReceiveRejectsZeroLengthBeforeBodyRead)
    {
        RunCoroutine(RunRejectLengthBeforeBodyRead(0U));
    }

    TEST(Ss2022ConnDatagram, PublicReceiveRejectsOversizedLengthBeforeBodyRead)
    {
        RunCoroutine(RunRejectLengthBeforeBodyRead(
            static_cast<std::uint32_t>(SS2022::MaxUdpPacketSize + 1U)));
    }
} // namespace
