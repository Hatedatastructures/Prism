/**
 * @file TerminalTest.cpp
 * @brief VMess 数据报完整帧与同次终态的 public wire 回归。
 */
#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
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
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Protocols/Common/Datagram/Relay/Pump.hpp>
#include <Prism/Protocols/Vmess/AuthCrypto.hpp>
#include <Prism/Protocols/Vmess/AuthHeader.hpp>
#include <Prism/Protocols/Vmess/AuthId.hpp>
#include <Prism/Protocols/Vmess/ChunkCodec.hpp>
#include <Prism/Protocols/Vmess/Connection/Connection.hpp>
#include <Prism/Protocols/Vmess/Datagram/Session.hpp>
#include <Prism/Protocols/Vmess/RequestCodec.hpp>
#include <Prism/Protocols/Vmess/Types.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Vmess = Prism::Vmess;
    using Key = std::array<std::uint8_t, 16>;
    using Nonce = std::array<std::uint8_t, 16>;

    static_assert(!std::is_default_constructible_v<Vmess::DatagramWire>);
    static_assert(!std::is_constructible_v<
        Vmess::DatagramWire, std::shared_ptr<Vmess::Dgram<>>, Prism::Network::Target>);

    class ScriptedDatagramTransmission final : public Prism::Transmission
    {
    public:
        explicit ScriptedDatagramTransmission(Net::any_io_executor Executor)
            : Prism::Transmission(std::move(Executor))
        {
        }

        auto QueueBytes(std::span<const std::byte> Bytes) -> void
        {
            if (Offset_ == Bytes_.size())
            {
                Bytes_.clear();
                Offset_ = 0;
            }
            Bytes_.insert(Bytes_.end(), Bytes.begin(), Bytes.end());
        }

        auto QueueTerminal(Fault::Failure Failure) -> void
        {
            Terminal_ = std::move(Failure);
        }

        [[nodiscard]] auto ReadsDone() const noexcept -> std::size_t
        {
            return ReadsDone_;
        }

        [[nodiscard]] auto WasClosed() const noexcept -> bool
        {
            return WasClosed_;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadsDone_;
            const auto Count = (std::min)(Buffer.size(), Bytes_.size() - Offset_);
            if (Count != 0U)
            {
                std::memcpy(Buffer.data(), Bytes_.data() + Offset_, Count);
                Offset_ += Count;
            }
            Prism::IoResult Result{Count, {}};
            if (Terminal_ && Offset_ == Bytes_.size())
            {
                Result.Failure = std::move(*Terminal_);
                Terminal_.reset();
            }
            else if (Count == 0U)
            {
                Result.Failure = {Fault::Code::WouldBlock};
            }
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), std::move(Result));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            WasClosed_ = true;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        std::vector<std::byte> Bytes_;
        std::size_t Offset_{0};
        std::size_t ReadsDone_{0};
        std::optional<Fault::Failure> Terminal_;
        bool WasClosed_{false};
    };

    struct ClientHandshake final
    {
        std::array<std::uint8_t, 16> Uuid{};
        Key KeyValue{};
        Nonce NonceValue{};
        std::uint8_t Options{};
        std::vector<std::byte> Wire;
    };

    [[nodiscard]] auto TestKey() -> Key
    {
        return {0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
                0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60};
    }

    [[nodiscard]] auto TestNonce() -> Nonce
    {
        return {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40};
    }

    [[nodiscard]] auto ResetFailure() -> Fault::Failure
    {
        return {Fault::Code::ConnectionReset,
                std::make_error_code(std::errc::connection_reset)};
    }

    [[nodiscard]] auto EofFailure() -> Fault::Failure
    {
        return {Fault::Code::Eof};
    }

    [[nodiscard]] auto Plaintext() -> std::array<std::uint8_t, 5>
    {
        return {0x21, 0x22, 0x23, 0x24, 0x25};
    }

    [[nodiscard]] auto MakeValidTarget() -> Prism::Network::Target
    {
        return {
            .Host = Prism::Network::Host{Prism::Network::Ipv4Bytes{{127, 0, 0, 1}}},
            .Port = 53U,
            .Route = Prism::Network::RouteKind::Forward};
    }

    /** @brief 构造供 public Conn 服务端入口解析的有效 VMess 客户端握手。 */
    [[nodiscard]] auto BuildClientHandshake() -> ClientHandshake
    {
        ClientHandshake Handshake;
        Handshake.Uuid = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                          0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F};
        Handshake.KeyValue = TestKey();
        Handshake.NonceValue = TestNonce();
        Handshake.Options = static_cast<std::uint8_t>(Vmess::Option::ChunkStream) |
                            static_cast<std::uint8_t>(Vmess::Option::ChunkMasking) |
                            static_cast<std::uint8_t>(Vmess::Option::AuthenticatedLength);
        Vmess::RequestHeader Header;
        Header.Version = Vmess::ProtocolVersion;
        Header.Cmd = static_cast<std::uint8_t>(Vmess::Command::Udp);
        Header.opt = Handshake.Options;
        Header.sec = Vmess::Security::Aes128Gcm;
        Header.Target.Type = Vmess::AddressType::Domain;
        Header.Target.Host = "example.com";
        Header.Target.Port = 443;
        const auto Plain = Vmess::BuildRequestHeader(
            Header,
            Vmess::RequestMeta{Handshake.NonceValue, Handshake.KeyValue, 0x71, 0});
        const auto CommandKey = Vmess::CmdKeyFromUuid(Handshake.Uuid);
        const std::array<std::uint8_t, 4> AuthRandom{0xA1, 0xA2, 0xA3, 0xA4};
        const auto TimeSeconds = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const auto AuthHeader = Vmess::SealAuthHeader(
            CommandKey,
            Vmess::AuthHeaderInput{Plain, TimeSeconds, AuthRandom});
        const auto WireBytes = std::as_bytes(std::span(AuthHeader));
        Handshake.Wire.assign(WireBytes.begin(), WireBytes.end());
        return Handshake;
    }

    struct DatagramFixture final
    {
        ClientHandshake Handshake;
        std::shared_ptr<ScriptedDatagramTransmission> Raw;
        std::shared_ptr<Vmess::Conn<>> Connection;
        std::shared_ptr<Vmess::Dgram<>> Datagram;
    };

    auto MakeDatagramFixture(Net::any_io_executor Executor)
        -> Net::awaitable<DatagramFixture>
    {
        DatagramFixture Fixture;
        Fixture.Handshake = BuildClientHandshake();
        Fixture.Raw = std::make_shared<ScriptedDatagramTransmission>(Executor);
        Fixture.Raw->QueueBytes(Fixture.Handshake.Wire);
        Fixture.Connection = std::make_shared<Vmess::Conn<>>(Vmess::ConnOptions{
            .Executor = Executor,
            .Uuid = Fixture.Handshake.Uuid});
        const auto Accepted = co_await Fixture.Connection->ReadHandshake(Fixture.Raw);
        EXPECT_TRUE(Accepted.has_value());
        if (Accepted)
        {
            Fixture.Datagram = std::make_shared<Vmess::Dgram<>>(Fixture.Connection);
        }
        co_return Fixture;
    }

    [[nodiscard]] auto EncodeDatagram(const ClientHandshake &Handshake)
        -> std::vector<std::uint8_t>
    {
        const auto Plain = Plaintext();
        Vmess::ChunkEncryptor Encoder(
            std::span<const std::uint8_t, 16>(Handshake.KeyValue),
            std::span<const std::uint8_t, 16>(Handshake.NonceValue),
            Handshake.Options);
        std::vector<std::uint8_t> Wire(
            Plain.size() + Vmess::ChunkEncryptor::Overhead);
        const auto WireSize = Encoder.Seal(Plain, Wire);
        Wire.resize(WireSize);
        return Wire;
    }

    [[nodiscard]] auto EncodeAuthenticatedOverlengthFrame(const ClientHandshake &Handshake)
        -> std::vector<std::uint8_t>
    {
        constexpr std::size_t Length = Vmess::MaxChunkLen + 1U;
        const auto Nonce = std::span<const std::uint8_t>(Handshake.NonceValue).first(12U);
        const std::array<std::uint8_t, 2> LengthPlain{
            static_cast<std::uint8_t>(Length >> 8U), static_cast<std::uint8_t>(Length)};
        auto Wire = Vmess::detail::AesGcmSeal({Handshake.KeyValue, Nonce, LengthPlain, {}});
        EXPECT_EQ(Wire.size(), 18U);
        auto BodyNonce = std::array<std::uint8_t, 12>{};
        std::copy(Nonce.begin(), Nonce.end(), BodyNonce.begin());
        ++BodyNonce.back();
        const std::vector<std::uint8_t> BodyPlain(Length);
        const auto Body = Vmess::detail::AesGcmSeal({Handshake.KeyValue, BodyNonce, BodyPlain, {}});
        EXPECT_EQ(Body.size(), Length + 16U);
        Wire.insert(Wire.end(), Body.begin(), Body.end());
        return Wire;
    }

    auto DrainCarrierActivity(
        const std::shared_ptr<Prism::Contract::CarrierActivity> &Activity)
        -> Net::awaitable<bool>
    {
        if (!Activity) co_return false;
        const auto Drained = co_await Activity->Drain();
        co_return Drained.has_value() && Activity->IsRetired();
    }

    auto CloseDatagramAndDrain(DatagramFixture &Fixture) -> Net::awaitable<bool>
    {
        const auto Closed = Fixture.Datagram
            ? Fixture.Datagram->Close()
            : Fixture.Connection->Close();
        const auto DatagramActivity = Fixture.Datagram
            ? Fixture.Datagram->Activity()
            : std::shared_ptr<Prism::Contract::CarrierActivity>{};
        const auto ConnectionActivity = Fixture.Connection
            ? Fixture.Connection->Activity()
            : std::shared_ptr<Prism::Contract::CarrierActivity>{};
        const auto RawActivity = Fixture.Raw
            ? Fixture.Raw->Activity()
            : std::shared_ptr<Prism::Contract::CarrierActivity>{};
        bool Succeeded = static_cast<bool>(Closed);
        if (DatagramActivity)
            Succeeded = (co_await DrainCarrierActivity(DatagramActivity)) && Succeeded;
        else if (Fixture.Datagram)
            Succeeded = false;
        if (ConnectionActivity)
            Succeeded = (co_await DrainCarrierActivity(ConnectionActivity)) && Succeeded;
        else
            Succeeded = false;
        if (RawActivity)
            Succeeded = (co_await DrainCarrierActivity(RawActivity)) && Succeeded;
        else
            Succeeded = false;
        co_return Succeeded;
    }

    auto ContinueDatagramFixture(DatagramFixture &Fixture) -> Net::awaitable<bool>
    {
        if (Fixture.Datagram) co_return true;
        EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
        co_return false;
    }

    auto RunCompleteDatagramPrecedesTerminal(Fault::Failure Terminal)
        -> Net::awaitable<void>
    {
        auto Fixture = co_await MakeDatagramFixture(
            co_await Net::this_coro::executor);
        if (!(co_await ContinueDatagramFixture(Fixture))) co_return;

        const auto Plain = Plaintext();
        const auto WireBytes = EncodeDatagram(Fixture.Handshake);
        EXPECT_EQ(WireBytes.size(), Plain.size() + Vmess::ChunkEncryptor::Overhead);
        const auto ReadsBeforeData = Fixture.Raw->ReadsDone();
        Fixture.Raw->QueueBytes(std::as_bytes(std::span(WireBytes)));
        Fixture.Raw->QueueTerminal(Terminal);

        const auto FixedTarget = MakeValidTarget();
        const auto ExpectedTarget = MakeValidTarget();
        auto WireResult = Vmess::DatagramWire::Create(Fixture.Datagram, FixedTarget);
        EXPECT_TRUE(WireResult);
        if (!WireResult)
        {
            EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
            co_return;
        }
        auto &Wire = *WireResult;
        EXPECT_EQ(Wire.Validate(), Fault::Code::Success);
        Prism::Protocols::DatagramPacket Packet;
        const auto Received = co_await Wire.Receive(Packet);
        EXPECT_TRUE(Received.has_value());
        EXPECT_EQ(Packet.Payload.size(), Plain.size());
        EXPECT_TRUE(std::equal(
            Packet.Payload.begin(), Packet.Payload.end(), Plain.begin(), Plain.end()));
        EXPECT_EQ(Packet.Target, ExpectedTarget);
        EXPECT_EQ(Fixture.Raw->ReadsDone(), ReadsBeforeData + 2U);

        Prism::Protocols::DatagramPacket RetryPacket;
        const auto Retry = co_await Wire.Receive(RetryPacket);
        EXPECT_FALSE(Retry.has_value());
        if (!Retry)
        {
            EXPECT_EQ(Retry.error().Code, Terminal.Code);
            EXPECT_EQ(Retry.error().Native, Terminal.Native);
        }
        EXPECT_TRUE(RetryPacket.Payload.empty());
        EXPECT_EQ(Fixture.Raw->ReadsDone(), ReadsBeforeData + 2U);
        EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
        EXPECT_TRUE(Fixture.Raw->WasClosed());
    }

    auto RunCompleteHeaderTerminal(Fault::Failure Terminal) -> Net::awaitable<void>
    {
        auto Fixture = co_await MakeDatagramFixture(
            co_await Net::this_coro::executor);
        if (!(co_await ContinueDatagramFixture(Fixture))) co_return;

        const auto FullFrame = EncodeDatagram(Fixture.Handshake);
        const auto Header = std::span<const std::uint8_t>(FullFrame).first(18);
        const auto ReadsBeforeHeader = Fixture.Raw->ReadsDone();
        Fixture.Raw->QueueBytes(std::as_bytes(Header));
        Fixture.Raw->QueueTerminal(Terminal);

        auto WireResult = Vmess::DatagramWire::Create(Fixture.Datagram, {});
        EXPECT_TRUE(WireResult);
        if (!WireResult)
        {
            EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
            co_return;
        }
        auto &Wire = *WireResult;
        Prism::Protocols::DatagramPacket Packet;
        const auto Read = co_await Wire.Receive(Packet);
        const auto ExpectedCode = Terminal.Code == Fault::Code::Eof
                                      ? Fault::Code::BadMessage
                                      : Terminal.Code;
        auto FirstFailure = Fault::Failure{ExpectedCode, Terminal.Native};
        EXPECT_FALSE(Read.has_value());
        if (!Read)
        {
            FirstFailure = Read.error();
            EXPECT_EQ(Read.error().Code, ExpectedCode);
            EXPECT_EQ(Read.error().Native, Terminal.Native);
        }
        EXPECT_TRUE(Packet.Payload.empty());
        EXPECT_EQ(Fixture.Raw->ReadsDone(), ReadsBeforeHeader + 1U);

        Prism::Protocols::DatagramPacket RetryPacket;
        const auto Retry = co_await Wire.Receive(RetryPacket);
        EXPECT_FALSE(Retry.has_value());
        if (!Retry)
        {
            EXPECT_EQ(Retry.error().Code, FirstFailure.Code);
            EXPECT_EQ(Retry.error().Native, FirstFailure.Native);
        }
        EXPECT_TRUE(RetryPacket.Payload.empty());
        EXPECT_EQ(Fixture.Raw->ReadsDone(), ReadsBeforeHeader + 1U);
        EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
        EXPECT_TRUE(Fixture.Raw->WasClosed());
    }

    /** @brief partial ciphertext 在底层终态后不产包，且重试保持粘滞。 */
    auto RunPartialPayloadTerminalIsSticky(Fault::Failure Terminal)
        -> Net::awaitable<void>
    {
        auto Fixture = co_await MakeDatagramFixture(
            co_await Net::this_coro::executor);
        if (!(co_await ContinueDatagramFixture(Fixture))) co_return;

        constexpr std::size_t HeaderSize = 18U;
        const auto FullWire = EncodeDatagram(Fixture.Handshake);
        EXPECT_GT(FullWire.size(), HeaderSize + 1U);
        if (FullWire.size() <= HeaderSize + 1U)
        {
            EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
            co_return;
        }

        const auto PartialWire = std::span<const std::uint8_t>(FullWire).first(
            FullWire.size() - 1U);
        Fixture.Raw->QueueBytes(std::as_bytes(PartialWire));
        Fixture.Raw->QueueTerminal(Terminal);

        const auto ReadsBefore = Fixture.Raw->ReadsDone();
        std::vector<std::uint8_t> Payload;
        const auto First = co_await Fixture.Datagram->AsyncReceiveDatagram(Payload);
        const auto FirstCode = Terminal.Code == Fault::Code::Eof
            ? Fault::Code::BadMessage
            : Terminal.Code;
        EXPECT_EQ(First.PayloadBytes, 0U);
        EXPECT_EQ(First.WireBytes, PartialWire.size());
        EXPECT_EQ(First.Failure.Code, FirstCode);
        EXPECT_EQ(First.Failure.Native, Terminal.Native);
        EXPECT_TRUE(Payload.empty());
        EXPECT_EQ(Fixture.Raw->ReadsDone(), ReadsBefore + 2U);

        const auto Retry = co_await Fixture.Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_EQ(Retry.PayloadBytes, 0U);
        EXPECT_EQ(Retry.WireBytes, 0U);
        EXPECT_EQ(Retry.Failure.Code, First.Failure.Code);
        EXPECT_EQ(Retry.Failure.Native, First.Failure.Native);
        EXPECT_TRUE(Payload.empty());
        EXPECT_EQ(Fixture.Raw->ReadsDone(), ReadsBefore + 2U);
        EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
        EXPECT_TRUE(Fixture.Raw->WasClosed());
    }

    auto RunZeroByteEofBeforeFirstFrameIsSticky() -> Net::awaitable<void>
    {
        auto Fixture = co_await MakeDatagramFixture(
            co_await Net::this_coro::executor);
        if (!(co_await ContinueDatagramFixture(Fixture))) co_return;

        Fixture.Raw->QueueTerminal(EofFailure());
        const auto ReadsBefore = Fixture.Raw->ReadsDone();
        std::vector<std::uint8_t> Payload;
        const auto First = co_await Fixture.Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_EQ(First.PayloadBytes, 0U);
        EXPECT_EQ(First.WireBytes, 0U);
        EXPECT_EQ(First.Failure.Code, Fault::Code::Eof);
        EXPECT_FALSE(First.Failure.Native);
        EXPECT_TRUE(Payload.empty());
        EXPECT_EQ(Fixture.Raw->ReadsDone(), ReadsBefore + 1U);

        const auto Retry = co_await Fixture.Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_EQ(Retry.PayloadBytes, 0U);
        EXPECT_EQ(Retry.WireBytes, 0U);
        EXPECT_EQ(Retry.Failure.Code, Fault::Code::Eof);
        EXPECT_FALSE(Retry.Failure.Native);
        EXPECT_TRUE(Payload.empty());
        EXPECT_EQ(Fixture.Raw->ReadsDone(), ReadsBefore + 1U);
        EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
        EXPECT_TRUE(Fixture.Raw->WasClosed());
    }

    auto RunZeroLengthEofMarker(Fault::Failure Terminal) -> Net::awaitable<void>
    {
        auto Fixture = co_await MakeDatagramFixture(
            co_await Net::this_coro::executor);
        if (!(co_await ContinueDatagramFixture(Fixture))) co_return;
        Vmess::ChunkEncryptor Encoder(
            std::span<const std::uint8_t, 16>(Fixture.Handshake.KeyValue),
            std::span<const std::uint8_t, 16>(Fixture.Handshake.NonceValue),
            Fixture.Handshake.Options);
        std::array<std::uint8_t, Vmess::ChunkEncryptor::Overhead> EndMarker{};
        const auto EndMarkerSize = Encoder.Finish(EndMarker);
        EXPECT_EQ(EndMarkerSize, 18U);
        if (EndMarkerSize != 18U)
        {
            EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
            EXPECT_TRUE(Fixture.Raw->WasClosed());
            co_return;
        }
        const auto ReadsBeforeData = Fixture.Raw->ReadsDone();
        Fixture.Raw->QueueBytes(std::as_bytes(
            std::span<const std::uint8_t>(EndMarker).first(EndMarkerSize)));
        Fixture.Raw->QueueTerminal(Terminal);
        auto WireResult = Vmess::DatagramWire::Create(Fixture.Datagram, {});
        EXPECT_TRUE(WireResult);
        if (!WireResult)
        {
            EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
            co_return;
        }
        auto &Wire = *WireResult;
        Prism::Protocols::DatagramPacket Packet;
        const auto End = co_await Wire.Receive(Packet);
        EXPECT_FALSE(End.has_value());
        if (!End)
        {
            EXPECT_EQ(End.error().Code, Terminal.Code);
            EXPECT_EQ(End.error().Native, Terminal.Native);
        }
        EXPECT_TRUE(Packet.Payload.empty());
        EXPECT_EQ(Fixture.Raw->ReadsDone(), ReadsBeforeData + 1U);
        Prism::Protocols::DatagramPacket RetryPacket;
        const auto Retry = co_await Wire.Receive(RetryPacket);
        EXPECT_FALSE(Retry.has_value());
        if (!Retry)
        {
            EXPECT_EQ(Retry.error().Code, Terminal.Code);
            EXPECT_EQ(Retry.error().Native, Terminal.Native);
        }
        EXPECT_EQ(Fixture.Raw->ReadsDone(), ReadsBeforeData + 1U);
        EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
        EXPECT_TRUE(Fixture.Raw->WasClosed());
    }

    auto RunAuthenticatedLengthRead(const bool Overlength) -> Net::awaitable<void>
    {
        auto Fixture = co_await MakeDatagramFixture(
            co_await Net::this_coro::executor);
        if (!(co_await ContinueDatagramFixture(Fixture))) co_return;

        if (Overlength)
        {
            const auto WireBytes = EncodeAuthenticatedOverlengthFrame(Fixture.Handshake);
            Fixture.Raw->QueueBytes(std::as_bytes(std::span(WireBytes)));

            const auto ReadsBefore = Fixture.Raw->ReadsDone();
            std::vector<std::uint8_t> Payload;
            const auto First = co_await Fixture.Datagram->AsyncReceiveDatagram(Payload);
            EXPECT_EQ(First.Failure.Code, Fault::Code::BadMessage);
            EXPECT_FALSE(First.Failure.Native);
            EXPECT_EQ(First.PayloadBytes, 0U);
            EXPECT_EQ(First.WireBytes, 18U);
            EXPECT_TRUE(Payload.empty());
            EXPECT_EQ(Fixture.Raw->ReadsDone(), ReadsBefore + 1U);
            const auto Retry = co_await Fixture.Datagram->AsyncReceiveDatagram(Payload);
            EXPECT_EQ(Retry.Failure.Code, First.Failure.Code);
            EXPECT_EQ(Retry.Failure.Native, First.Failure.Native);
            EXPECT_EQ(Retry.PayloadBytes, 0U);
            EXPECT_EQ(Retry.WireBytes, 0U);
            EXPECT_TRUE(Payload.empty());
            EXPECT_EQ(Fixture.Raw->ReadsDone(), ReadsBefore + 1U);
            EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
            EXPECT_TRUE(Fixture.Raw->WasClosed());
            co_return;
        }

        Vmess::ChunkEncryptor Encoder(
            std::span<const std::uint8_t, 16>(Fixture.Handshake.KeyValue),
            std::span<const std::uint8_t, 16>(Fixture.Handshake.NonceValue),
            Fixture.Handshake.Options);
        std::array<std::uint8_t, Vmess::ChunkEncryptor::Overhead> EmptyFrame{};
        const auto Written = Encoder.Seal({}, EmptyFrame);
        EXPECT_EQ(Written, Vmess::ChunkEncryptor::Overhead);
        if (Written != Vmess::ChunkEncryptor::Overhead)
        {
            EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
            co_return;
        }
        Fixture.Raw->QueueBytes(std::as_bytes(
            std::span<const std::uint8_t>(EmptyFrame).first(Written)));
        Fixture.Raw->QueueTerminal({Fault::Code::Eof});

        const auto ReadsBefore = Fixture.Raw->ReadsDone();
        std::vector<std::uint8_t> Payload;
        const auto Empty = co_await Fixture.Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_FALSE(Empty.Failure.Failed());
        EXPECT_EQ(Empty.PayloadBytes, 0U);
        EXPECT_EQ(Empty.WireBytes, Vmess::ChunkEncryptor::Overhead);
        EXPECT_TRUE(Payload.empty());
        EXPECT_EQ(Fixture.Raw->ReadsDone(), ReadsBefore + 2U);

        const auto End = co_await Fixture.Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_EQ(End.PayloadBytes, 0U);
        EXPECT_EQ(End.WireBytes, 0U);
        EXPECT_EQ(End.Failure.Code, Fault::Code::Eof);
        EXPECT_TRUE(Payload.empty());
        EXPECT_EQ(Fixture.Raw->ReadsDone(), ReadsBefore + 2U);

        const auto Retry = co_await Fixture.Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_EQ(Retry.Failure.Code, Fault::Code::Eof);
        EXPECT_EQ(Fixture.Raw->ReadsDone(), ReadsBefore + 2U);
        EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
        EXPECT_TRUE(Fixture.Raw->WasClosed());
    }

    auto RunReleasedDatagramCarrier(const bool CreateWireFirst) -> Net::awaitable<void>
    {
        auto Fixture = co_await MakeDatagramFixture(
            co_await Net::this_coro::executor);
        if (!(co_await ContinueDatagramFixture(Fixture))) co_return;

        std::optional<Vmess::DatagramWire> CreatedWire;
        std::shared_ptr<Prism::Contract::CarrierActivity> DatagramActivity;
        if (CreateWireFirst)
        {
            auto WireResult = Vmess::DatagramWire::Create(
                Fixture.Datagram, MakeValidTarget());
            EXPECT_TRUE(WireResult);
            if (!WireResult)
            {
                EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
                co_return;
            }
            CreatedWire.emplace(std::move(*WireResult));
            DatagramActivity = Fixture.Datagram->Activity();
        }

        const auto Released = Fixture.Datagram->Release();
        EXPECT_TRUE(Released);
        EXPECT_EQ(Fixture.Datagram->NextLayer(), nullptr);
        EXPECT_EQ(Released.get(), Fixture.Connection.get());

        bool WireClosed = !CreateWireFirst;
        if (CreateWireFirst)
        {
            WireClosed = static_cast<bool>(CreatedWire->Close());
            EXPECT_TRUE(WireClosed);
        }
        const auto CarrierClosed = Released
            ? Released->Close()
            : Fixture.Connection->Close();
        EXPECT_TRUE(CarrierClosed);
        const auto ConnectionActivity = Released
            ? Released->Activity()
            : Fixture.Connection->Activity();
        EXPECT_TRUE(co_await DrainCarrierActivity(ConnectionActivity));

        if (CreateWireFirst)
        {
            const auto Activities = CreatedWire->CarrierActivities();
            EXPECT_EQ(Activities.size(), 1U);
            EXPECT_NE(std::find(Activities.begin(), Activities.end(), DatagramActivity),
                Activities.end());
            if (WireClosed)
            {
                for (const auto &Activity : Activities)
                    EXPECT_TRUE(co_await DrainCarrierActivity(Activity));
            }
            EXPECT_TRUE(DatagramActivity->IsRetired());
        }
        else
        {
            const auto Wire = Vmess::DatagramWire::Create(
                Fixture.Datagram, MakeValidTarget());
            EXPECT_FALSE(Wire);
            if (!Wire) EXPECT_EQ(Wire.error().Code, Fault::Code::InvalidArgument);
        }
        EXPECT_TRUE(co_await CloseDatagramAndDrain(Fixture));
        EXPECT_TRUE(Fixture.Raw->WasClosed());
    }

    template <typename Awaitable>
    auto RunCoroutine(Net::io_context &Context, Awaitable Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(
            Context,
            std::move(Operation),
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        Context.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }
} // namespace

TEST(VmessDatagramTerminalRead, PublicWireDeliversCompletePacketBeforeReset)
{
    Net::io_context Context;
    RunCoroutine(Context, RunCompleteDatagramPrecedesTerminal(ResetFailure()));
}

TEST(VmessDatagramTerminalRead, PublicWireDeliversCompletePacketBeforeEof)
{
    Net::io_context Context;
    RunCoroutine(Context, RunCompleteDatagramPrecedesTerminal(EofFailure()));
}

TEST(VmessDatagramTerminalRead, PublicWireDeliversCompletePacketBeforeCancellation)
{
    Net::io_context Context;
    RunCoroutine(Context, RunCompleteDatagramPrecedesTerminal({
        Fault::Code::Canceled,
        std::make_error_code(std::errc::operation_canceled)}));
}

TEST(VmessDatagramTerminalRead, CompleteHeaderResetDoesNotProducePacket)
{
    Net::io_context Context;
    RunCoroutine(Context, RunCompleteHeaderTerminal(ResetFailure()));
}

TEST(VmessDatagramTerminalRead, CompleteHeaderEofDoesNotProducePacket)
{
    Net::io_context Context;
    RunCoroutine(Context, RunCompleteHeaderTerminal(EofFailure()));
}

TEST(VmessDatagramTerminalRead, PartialPayloadNativeResetIsSticky)
{
    Net::io_context Context;
    RunCoroutine(Context, RunPartialPayloadTerminalIsSticky(ResetFailure()));
}

TEST(VmessDatagramTerminalRead, PartialPayloadEofIsSticky)
{
    Net::io_context Context;
    RunCoroutine(Context, RunPartialPayloadTerminalIsSticky(EofFailure()));
}

TEST(VmessDatagramTerminalRead, ZeroByteEofBeforeFirstFrameIsStickyWithoutReread)
{
    Net::io_context Context;
    RunCoroutine(Context, RunZeroByteEofBeforeFirstFrameIsSticky());
}

TEST(VmessDatagramTerminalRead, CompleteZeroLengthEofMarkerIsCleanBoundary)
{
    Net::io_context Context;
    RunCoroutine(Context, RunZeroLengthEofMarker(EofFailure()));
}

TEST(VmessDatagramTerminalRead, AuthenticatedEndMarkerPreservesResetTerminal)
{
    Net::io_context Context;
    RunCoroutine(Context, RunZeroLengthEofMarker(ResetFailure()));
}

TEST(VmessDatagramTerminalRead, EmptyAuthenticatedChunkConsumesTagBeforeBoundaryEof)
{
    Net::io_context Context;
    RunCoroutine(Context, RunAuthenticatedLengthRead(false));
}

TEST(VmessDatagramTerminalRead, AuthenticatedOverlengthHeaderFailureIsSticky)
{
    Net::io_context Context;
    RunCoroutine(Context, RunAuthenticatedLengthRead(true));
}

TEST(VmessDatagramWireValidation, RejectsNullCarrierWithValidTarget)
{
    const auto FixedTarget = MakeValidTarget();
    ASSERT_FALSE(FixedTarget.Host.Empty());
    ASSERT_EQ(FixedTarget.Port, 53U);

    const auto Wire = Vmess::DatagramWire::Create({}, FixedTarget);
    ASSERT_FALSE(Wire);
    EXPECT_EQ(Wire.error().Code, Fault::Code::InvalidArgument);
}

TEST(VmessDatagramWireValidation, RejectsReleasedNonNullCarrier)
{
    Net::io_context Context;
    RunCoroutine(Context, RunReleasedDatagramCarrier(false));
}

TEST(VmessDatagramWireValidation, WireCloseDrainsReleasedDatagramCarrier)
{
    Net::io_context Context;
    RunCoroutine(Context, RunReleasedDatagramCarrier(true));
}
