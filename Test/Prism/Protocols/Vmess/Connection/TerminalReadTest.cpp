/**
 * @file TerminalReadTest.cpp
 * @brief VMess 完整 chunk 与同次读取终态的交付顺序回归。
 */
#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/associated_cancellation_slot.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/cancellation_type.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

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
#include <utility>
#include <vector>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Vmess/AuthHeader.hpp>
#include <Prism/Protocols/Vmess/AuthId.hpp>
#include <Prism/Protocols/Vmess/ChunkCodec.hpp>
#include <Prism/Protocols/Vmess/Connection/Connection.hpp>
#include <Prism/Protocols/Vmess/Connection/Chunk.hpp>
#include <Prism/Protocols/Vmess/Connection/Io.hpp>
#include <Prism/Protocols/Vmess/Connection/Session.hpp>
#include <Prism/Protocols/Vmess/RequestCodec.hpp>
#include <Prism/Protocols/Vmess/Types.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Vmess = Prism::Vmess;
    using Memory = Prism::Memory::SessionResource<>;
    using Session = Vmess::detail::ConnSession<Memory>;
    using ConnIo = Vmess::detail::ConnIo<Memory>;
    using ConnChunk = Vmess::detail::ConnChunk<Memory>;
    using Key = std::array<std::uint8_t, 16>;
    using Nonce = std::array<std::uint8_t, 16>;

    /** @brief 缓存测试 wire，并在末尾一次交付指定终态的传输 owner。 */
    class BufferedTerminalTransmission final : public Prism::Transmission
    {
    public:
        explicit BufferedTerminalTransmission(Net::any_io_executor Executor)
            : Prism::Transmission(std::move(Executor))
        {
        }

        auto QueueBytes(std::span<const std::byte> Bytes) -> void
        {
            if (ReadOffset_ == ReadBytes_.size())
            {
                ReadBytes_.clear();
                ReadOffset_ = 0;
            }
            ReadBytes_.insert(ReadBytes_.end(), Bytes.begin(), Bytes.end());
        }

        auto QueueTerminal(
            Fault::Failure Failure,
            Net::cancellation_signal *Signal) -> void
        {
            Terminal_ = std::move(Failure);
            Signal_ = Signal;
        }

        [[nodiscard]] auto ReadsDone() const noexcept -> std::size_t
        {
            return ReadsDone_;
        }

        [[nodiscard]] auto SawCancellationSlot() const noexcept -> bool
        {
            return SawCancellationSlot_;
        }

        [[nodiscard]] auto WasClosed() const noexcept -> bool
        {
            return WasClosed_;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadsDone_;
            const auto Remaining = ReadBytes_.size() - ReadOffset_;
            const auto Count = (std::min)(Buffer.size(), Remaining);
            if (Count != 0U)
            {
                std::memcpy(Buffer.data(), ReadBytes_.data() + ReadOffset_, Count);
                ReadOffset_ += Count;
            }

            Prism::IoResult Result{Count, {}};
            auto *Signal = static_cast<Net::cancellation_signal *>(nullptr);
            if (Terminal_ && ReadOffset_ == ReadBytes_.size())
            {
                Result.Failure = std::move(*Terminal_);
                Terminal_.reset();
                Signal = std::exchange(Signal_, nullptr);
            }
            else if (Count == 0U)
            {
                Result.Failure = {Fault::Code::WouldBlock};
            }

            Net::post(
                Executor(),
                [this, Handler = std::move(Handler), Result = std::move(Result), Signal]() mutable
                {
                    CompleteRead(std::move(Handler), std::move(Result), Signal);
                });
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
        auto CompleteRead(
            Completion Handler,
            Prism::IoResult Result,
            Net::cancellation_signal *Signal) -> void
        {
            if (Signal != nullptr)
            {
                SawCancellationSlot_ =
                    Net::get_associated_cancellation_slot(Handler).is_connected();
                Signal->emit(Net::cancellation_type::total);
            }
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), std::move(Result));
        }

        std::vector<std::byte> ReadBytes_;
        std::size_t ReadOffset_{0};
        std::size_t ReadsDone_{0};
        std::optional<Fault::Failure> Terminal_;
        Net::cancellation_signal *Signal_{nullptr};
        bool SawCancellationSlot_{false};
        bool WasClosed_{false};
    };

    class ScriptedTransmission final : public Prism::Transmission
    {
    public:
        struct ReadStep final
        {
            std::vector<std::byte> Bytes;
            Fault::Failure Failure;
        };

        explicit ScriptedTransmission(Net::any_io_executor Executor)
            : Prism::Transmission(std::move(Executor))
        {
        }

        auto QueueRead(ReadStep Step) -> void
        {
            Steps_.push_back(std::move(Step));
        }

        [[nodiscard]] auto ReadsDone() const noexcept -> std::size_t
        {
            return ReadsDone_;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadsDone_;
            if (Steps_.empty())
            {
                Prism::Transmission::PostResult(
                    Executor(), std::move(Handler), {0, {Fault::Code::Eof}});
                return;
            }
            auto Step = std::move(Steps_.front());
            Steps_.erase(Steps_.begin());
            const auto Count = (std::min)(Buffer.size(), Step.Bytes.size());
            if (Count != 0U)
            {
                std::memcpy(Buffer.data(), Step.Bytes.data(), Count);
            }
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Count, std::move(Step.Failure)});
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
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        std::vector<ReadStep> Steps_;
        std::size_t ReadsDone_{0};
    };

    [[nodiscard]] auto ResetFailure() -> Fault::Failure
    {
        return {Fault::Code::ConnectionReset,
                std::make_error_code(std::errc::connection_reset)};
    }

    [[nodiscard]] auto EofFailure() -> Fault::Failure
    {
        return {Fault::Code::Eof};
    }

    [[nodiscard]] auto CancellationFailure() -> Fault::Failure
    {
        return {Fault::Code::Canceled,
                std::make_error_code(std::errc::operation_canceled)};
    }

    [[nodiscard]] auto TruncatedFailure() -> Fault::Failure
    {
        return {Fault::Code::Eof};
    }

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

    struct PublicConnHandshake final
    {
        std::array<std::uint8_t, 16> Uuid{};
        Key KeyValue{};
        Nonce NonceValue{};
        std::uint8_t Options{};
        std::vector<std::byte> Wire;
    };

    /** @brief 构造供 public Conn 服务端入口解析的有效 VMess 客户端握手。 */
    [[nodiscard]] auto BuildPublicConnHandshake() -> PublicConnHandshake
    {
        PublicConnHandshake Handshake;
        Handshake.Uuid = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                          0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F};
        Handshake.KeyValue = TestKey();
        Handshake.NonceValue = TestNonce();
        Handshake.Options = static_cast<std::uint8_t>(Vmess::Option::ChunkStream) |
                            static_cast<std::uint8_t>(Vmess::Option::ChunkMasking) |
                            static_cast<std::uint8_t>(Vmess::Option::AuthenticatedLength);

        Vmess::RequestHeader Header;
        Header.Version = Vmess::ProtocolVersion;
        Header.Cmd = static_cast<std::uint8_t>(Vmess::Command::Tcp);
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

    [[nodiscard]] auto Plaintext() -> std::array<std::uint8_t, 5>
    {
        return {0x21, 0x22, 0x23, 0x24, 0x25};
    }

    struct ChunkParts final
    {
        std::vector<std::byte> Header;
        std::vector<std::byte> Payload;
    };

    [[nodiscard]] auto EncodeChunk(const Key &KeyValue, const Nonce &NonceValue)
        -> ChunkParts
    {
        constexpr auto Options = static_cast<std::uint8_t>(
            Vmess::Option::AuthenticatedLength);
        Vmess::ChunkEncryptor Encoder(
            std::span<const std::uint8_t, 16>(KeyValue),
            std::span<const std::uint8_t, 16>(NonceValue), Options);
        const auto Plain = Plaintext();
        std::vector<std::uint8_t> Wire(
            Plain.size() + Vmess::ChunkEncryptor::Overhead);
        const auto Size = Encoder.Seal(Plain, Wire);
        Wire.resize(Size);
        const auto Bytes = std::as_bytes(std::span(Wire));
        return {
            std::vector<std::byte>(Bytes.begin(), Bytes.begin() + 18),
            std::vector<std::byte>(Bytes.begin() + 18, Bytes.end())};
    }

    struct ReadFixture final
    {
        explicit ReadFixture(Net::any_io_executor Executor)
            : Raw(std::make_shared<ScriptedTransmission>(Executor)),
              SessionValue({}, {}, {}),
              Io(SessionValue, std::move(Executor)),
              Chunk(SessionValue, Io)
        {
            SessionValue.Reset(Raw, true);
            SessionValue.Handshaken_ = true;
            Chunk.Configure(Vmess::detail::ChunkKeys{
                .EncryptKey = TestKey(),
                .EncryptNonce = TestNonce(),
                .DecryptKey = TestKey(),
                .DecryptNonce = TestNonce(),
                .Options = static_cast<std::uint8_t>(Vmess::Option::AuthenticatedLength)});
        }

        std::shared_ptr<ScriptedTransmission> Raw;
        Session SessionValue;
        ConnIo Io;
        ConnChunk Chunk;
    };

    auto VerifyStickyFailure(ReadFixture &Fixture,
                             const Fault::Failure &Expected,
                             const std::size_t ExpectedReads) -> Net::awaitable<void>
    {
        std::array<std::byte, 16> Buffer{};
        for (int Attempt = 0; Attempt != 2; ++Attempt)
        {
            const auto Retry = co_await Fixture.Chunk.ReadSome(Buffer);
            EXPECT_EQ(Retry.Bytes, 0U);
            EXPECT_EQ(Retry.Failure.Code, Expected.Code);
            EXPECT_EQ(Retry.Failure.Native, Expected.Native);
            EXPECT_EQ(Fixture.Raw->ReadsDone(), ExpectedReads);
        }
    }

    auto CloseSessionAndDrain(ReadFixture &Fixture) -> Net::awaitable<bool>
    {
        const auto Closed = Fixture.SessionValue.Close();
        const auto Activity = Fixture.Raw->Activity();
        if (!Closed || !Activity)
        {
            co_return false;
        }
        const auto Drained = co_await Activity->Drain();
        co_return Drained.has_value();
    }

    auto RunCompleteChunkTerminal(Fault::Failure Terminal) -> Net::awaitable<void>
    {
        ReadFixture Fixture(co_await Net::this_coro::executor);
        const auto Parts = EncodeChunk(TestKey(), TestNonce());
        Fixture.Raw->QueueRead({Parts.Header, {}});
        Fixture.Raw->QueueRead({Parts.Payload, Terminal});
        std::array<std::byte, 2> Buffer{};
        const auto Read = co_await Fixture.Chunk.ReadSome(Buffer);
        const auto Plain = Plaintext();
        const auto PlainBytes = std::as_bytes(std::span(Plain));
        EXPECT_EQ(Read.Bytes, Buffer.size());
        EXPECT_FALSE(Read.Failure.Failed());
        EXPECT_TRUE(std::equal(Buffer.begin(), Buffer.end(), PlainBytes.begin()));
        EXPECT_EQ(Fixture.Raw->ReadsDone(), 2U);
        std::array<std::byte, 8> Tail{};
        const auto TailRead = co_await Fixture.Chunk.ReadSome(Tail);
        EXPECT_EQ(TailRead.Bytes, Plain.size() - Buffer.size());
        EXPECT_FALSE(TailRead.Failure.Failed());
        EXPECT_TRUE(std::equal(
            Tail.begin(), Tail.begin() + static_cast<std::ptrdiff_t>(TailRead.Bytes),
            PlainBytes.begin() + static_cast<std::ptrdiff_t>(Buffer.size())));
        EXPECT_EQ(Fixture.Raw->ReadsDone(), 2U);
        co_await VerifyStickyFailure(Fixture, Terminal, 2U);
        EXPECT_TRUE(co_await CloseSessionAndDrain(Fixture));
    }

    auto RunHeaderTerminal(Fault::Failure Terminal, const bool CompleteField)
        -> Net::awaitable<void>
    {
        ReadFixture Fixture(co_await Net::this_coro::executor);
        const auto Parts = EncodeChunk(TestKey(), TestNonce());
        if (CompleteField)
        {
            Fixture.Raw->QueueRead({Parts.Header, Terminal});
        }
        else
        {
            Fixture.Raw->QueueRead({{Parts.Header.front()}, Terminal});
        }
        std::array<std::byte, 16> Buffer{};
        const auto Read = co_await Fixture.Chunk.ReadSome(Buffer);
        const auto Expected = Terminal.Code == Fault::Code::Eof
                                 ? TruncatedFailure()
                                 : Terminal;
        EXPECT_EQ(Read.Bytes, 0U);
        EXPECT_EQ(Read.Failure.Code, Expected.Code);
        EXPECT_EQ(Read.Failure.Native, Expected.Native);
        EXPECT_EQ(Fixture.Raw->ReadsDone(), 1U);
        co_await VerifyStickyFailure(Fixture, Expected, 1U);
        EXPECT_TRUE(co_await CloseSessionAndDrain(Fixture));
    }

    auto RunPayloadTerminal(Fault::Failure Terminal) -> Net::awaitable<void>
    {
        ReadFixture Fixture(co_await Net::this_coro::executor);
        const auto Parts = EncodeChunk(TestKey(), TestNonce());
        Fixture.Raw->QueueRead({Parts.Header, {}});
        Fixture.Raw->QueueRead({{Parts.Payload.front()}, Terminal});
        std::array<std::byte, 16> Buffer{};
        const auto Read = co_await Fixture.Chunk.ReadSome(Buffer);
        const auto Expected = Terminal.Code == Fault::Code::Eof
                                 ? TruncatedFailure()
                                 : Terminal;
        EXPECT_EQ(Read.Bytes, 0U);
        EXPECT_EQ(Read.Failure.Code, Expected.Code);
        EXPECT_EQ(Read.Failure.Native, Expected.Native);
        EXPECT_EQ(Fixture.Raw->ReadsDone(), 2U);
        co_await VerifyStickyFailure(Fixture, Expected, 2U);
        EXPECT_TRUE(co_await CloseSessionAndDrain(Fixture));
    }

    auto RunCleanBoundaryEof() -> Net::awaitable<void>
    {
        ReadFixture Fixture(co_await Net::this_coro::executor);
        Fixture.Raw->QueueRead({{}, EofFailure()});
        std::array<std::byte, 16> Buffer{};
        const auto Read = co_await Fixture.Chunk.ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0U);
        EXPECT_EQ(Read.Failure.Code, Fault::Code::Eof);
        co_await VerifyStickyFailure(Fixture, EofFailure(), 1U);
        EXPECT_TRUE(co_await CloseSessionAndDrain(Fixture));
    }

    auto RunZeroLengthHeaderEof() -> Net::awaitable<void>
    {
        ReadFixture Fixture(co_await Net::this_coro::executor);
        const auto KeyValue = TestKey();
        const auto NonceValue = TestNonce();
        Vmess::ChunkEncryptor Encoder(
            std::span<const std::uint8_t, 16>(KeyValue),
            std::span<const std::uint8_t, 16>(NonceValue),
            static_cast<std::uint8_t>(Vmess::Option::AuthenticatedLength));
        std::array<std::uint8_t, 18> Header{};
        const auto HeaderSize = Encoder.Finish(Header);
        EXPECT_EQ(HeaderSize, Header.size());
        if (HeaderSize != Header.size())
        {
            EXPECT_TRUE(co_await CloseSessionAndDrain(Fixture));
            co_return;
        }

        const auto HeaderBytes = std::as_bytes(std::span(Header));
        Fixture.Raw->QueueRead({
            std::vector<std::byte>(HeaderBytes.begin(), HeaderBytes.end()),
            EofFailure()});
        std::array<std::byte, 16> Buffer{};
        const auto Read = co_await Fixture.Chunk.ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0U);
        EXPECT_EQ(Read.Failure.Code, Fault::Code::Eof);
        EXPECT_EQ(Fixture.Raw->ReadsDone(), 1U);

        const auto Retry = co_await Fixture.Chunk.ReadSome(Buffer);
        EXPECT_EQ(Retry.Bytes, 0U);
        EXPECT_EQ(Retry.Failure.Code, Fault::Code::Eof);
        EXPECT_EQ(Fixture.Raw->ReadsDone(), 1U);
        EXPECT_TRUE(co_await CloseSessionAndDrain(Fixture));
    }

    auto RunDatagramPrecedesTerminal(Fault::Failure Terminal) -> Net::awaitable<void>
    {
        ReadFixture Fixture(co_await Net::this_coro::executor);
        const auto Parts = EncodeChunk(TestKey(), TestNonce());
        Fixture.Raw->QueueRead({Parts.Header, {}});
        Fixture.Raw->QueueRead({Parts.Payload, Terminal});
        std::vector<std::uint8_t> Payload;
        const auto Read = co_await Fixture.Chunk.AsyncReceiveDatagram(Payload);
        const auto Plain = Plaintext();
        EXPECT_EQ(Read.PayloadBytes, Plain.size());
        EXPECT_EQ(Read.WireBytes, Parts.Header.size() + Parts.Payload.size());
        EXPECT_FALSE(Read.Failure.Failed());
        EXPECT_TRUE(std::equal(Payload.begin(), Payload.end(), Plain.begin()));
        EXPECT_EQ(Fixture.Raw->ReadsDone(), 2U);

        const auto DeferredTerminal = co_await Fixture.Chunk.AsyncReceiveDatagram(Payload);
        EXPECT_EQ(DeferredTerminal.PayloadBytes, 0U);
        EXPECT_EQ(DeferredTerminal.Failure.Code, Terminal.Code);
        EXPECT_EQ(DeferredTerminal.Failure.Native, Terminal.Native);
        EXPECT_EQ(Fixture.Raw->ReadsDone(), 2U);
        EXPECT_TRUE(co_await CloseSessionAndDrain(Fixture));
    }

    [[nodiscard]] auto ClosePublicConnectionAndDrain(
        const std::shared_ptr<Vmess::Conn<>> &Connection,
        const std::shared_ptr<BufferedTerminalTransmission> &Raw)
        -> Net::awaitable<bool>
    {
        const auto Closed = Connection->Close();
        const auto ConnectionActivity = Connection->Activity();
        const auto RawActivity = Raw->Activity();
        if (!Closed || !ConnectionActivity || !RawActivity)
        {
            co_return false;
        }
        const auto ConnectionDrained = co_await ConnectionActivity->Drain();
        const auto RawDrained = co_await RawActivity->Drain();
        co_return ConnectionDrained.has_value() && RawDrained.has_value();
    }

    auto RunPublicConnCancellationSlot() -> Net::awaitable<void>
    {
        const auto Executor = co_await Net::this_coro::executor;
        const auto Handshake = BuildPublicConnHandshake();
        auto Raw = std::make_shared<BufferedTerminalTransmission>(Executor);
        Raw->QueueBytes(Handshake.Wire);
        auto Connection = std::make_shared<Vmess::Conn<>>(Vmess::ConnOptions{
            .Executor = Executor,
            .Uuid = Handshake.Uuid});

        const auto Accepted = co_await Connection->ReadHandshake(Raw);
        EXPECT_TRUE(Accepted.has_value());
        if (!Accepted)
        {
            EXPECT_TRUE(co_await ClosePublicConnectionAndDrain(Connection, Raw));
            co_return;
        }

        const auto Plain = Plaintext();
        Vmess::ChunkEncryptor Encoder(
            std::span<const std::uint8_t, 16>(Handshake.KeyValue),
            std::span<const std::uint8_t, 16>(Handshake.NonceValue),
            Handshake.Options);
        std::vector<std::uint8_t> Encrypted(
            Plain.size() + Vmess::ChunkEncryptor::Overhead);
        const auto EncryptedSize = Encoder.Seal(Plain, Encrypted);
        EXPECT_NE(EncryptedSize, 0U);
        if (EncryptedSize == 0U)
        {
            EXPECT_TRUE(co_await ClosePublicConnectionAndDrain(Connection, Raw));
            co_return;
        }
        Encrypted.resize(EncryptedSize);
        Raw->QueueBytes(std::as_bytes(std::span(Encrypted)));

        Net::cancellation_signal Signal;
        Raw->QueueTerminal(CancellationFailure(), &Signal);
        const auto ReadsBeforeData = Raw->ReadsDone();
        std::array<std::byte, 5> Buffer{};
        const auto Read = co_await Connection->ReadSome(
            Buffer,
            Net::bind_cancellation_slot(Signal.slot(), Net::use_awaitable));
        const auto PlainBytes = std::as_bytes(std::span(Plain));
        EXPECT_EQ(Read.Bytes, Plain.size());
        EXPECT_FALSE(Read.Failure.Failed());
        EXPECT_TRUE(std::equal(Buffer.begin(), Buffer.end(), PlainBytes.begin()));
        EXPECT_TRUE(Raw->SawCancellationSlot());
        const auto ReadsAfterData = Raw->ReadsDone();
        EXPECT_EQ(ReadsAfterData, ReadsBeforeData + 2U);

        for (int Attempt = 0; Attempt != 2; ++Attempt)
        {
            const auto Retry = co_await Connection->ReadSome(Buffer);
            EXPECT_EQ(Retry.Bytes, 0U);
            EXPECT_EQ(Retry.Failure.Code, Fault::Code::Canceled);
            EXPECT_EQ(Retry.Failure.Native, CancellationFailure().Native);
            EXPECT_EQ(Raw->ReadsDone(), ReadsAfterData);
        }
        EXPECT_TRUE(co_await ClosePublicConnectionAndDrain(Connection, Raw));
        EXPECT_TRUE(Raw->WasClosed());
    }

    auto RunPartialDatagramEof(const bool CompleteHeader) -> Net::awaitable<void>
    {
        ReadFixture Fixture(co_await Net::this_coro::executor);
        const auto Parts = EncodeChunk(TestKey(), TestNonce());
        std::size_t ExpectedWireBytes = 1U;
        std::size_t ExpectedReads = 1U;
        if (CompleteHeader)
        {
            Fixture.Raw->QueueRead({Parts.Header, {}});
            Fixture.Raw->QueueRead({{Parts.Payload.front()}, EofFailure()});
            ExpectedWireBytes += Parts.Header.size();
            ++ExpectedReads;
        }
        else
        {
            Fixture.Raw->QueueRead({{Parts.Header.front()}, EofFailure()});
        }

        std::vector<std::uint8_t> Payload;
        const auto Truncated = co_await Fixture.Chunk.AsyncReceiveDatagram(Payload);
        EXPECT_EQ(Truncated.PayloadBytes, 0U);
        EXPECT_EQ(Truncated.WireBytes, ExpectedWireBytes);
        EXPECT_EQ(Truncated.Failure.Code, Fault::Code::BadMessage);
        EXPECT_TRUE(Payload.empty());
        EXPECT_EQ(Fixture.Raw->ReadsDone(), ExpectedReads);

        for (int Attempt = 0; Attempt != 2; ++Attempt)
        {
            const auto Retry = co_await Fixture.Chunk.AsyncReceiveDatagram(Payload);
            EXPECT_EQ(Retry.PayloadBytes, 0U);
            EXPECT_EQ(Retry.Failure.Code, Truncated.Failure.Code);
            EXPECT_EQ(Retry.Failure.Native, Truncated.Failure.Native);
            EXPECT_EQ(Fixture.Raw->ReadsDone(), ExpectedReads);
        }
        EXPECT_TRUE(co_await CloseSessionAndDrain(Fixture));
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

    TEST(VmessConnTerminalRead, CompleteChunkPrecedesReset)
    {
        RunCoroutine(RunCompleteChunkTerminal(ResetFailure()));
    }

    TEST(VmessConnTerminalRead, CompleteChunkPrecedesEof)
    {
        RunCoroutine(RunCompleteChunkTerminal(EofFailure()));
    }

    TEST(VmessConnTerminalRead, CompleteChunkPrecedesCancellation)
    {
        RunCoroutine(RunCompleteChunkTerminal(CancellationFailure()));
    }

    TEST(VmessConnTerminalRead, PublicConnCancellationSlotDefersCompleteChunkTerminal)
    {
        RunCoroutine(RunPublicConnCancellationSlot());
    }

    TEST(VmessConnTerminalRead, CompleteLengthResetCannotCompleteChunk)
    {
        RunCoroutine(RunHeaderTerminal(ResetFailure(), true));
    }

    TEST(VmessConnTerminalRead, CompleteLengthEofCannotCompleteChunk)
    {
        RunCoroutine(RunHeaderTerminal(EofFailure(), true));
    }

    TEST(VmessConnTerminalRead, PartialLengthResetIsSticky)
    {
        RunCoroutine(RunHeaderTerminal(ResetFailure(), false));
    }

    TEST(VmessConnTerminalRead, PartialLengthEofIsSticky)
    {
        RunCoroutine(RunHeaderTerminal(EofFailure(), false));
    }

    TEST(VmessConnTerminalRead, PartialPayloadResetIsSticky)
    {
        RunCoroutine(RunPayloadTerminal(ResetFailure()));
    }

    TEST(VmessConnTerminalRead, PartialPayloadEofIsSticky)
    {
        RunCoroutine(RunPayloadTerminal(EofFailure()));
    }

    TEST(VmessConnTerminalRead, PartialPayloadCancellationIsSticky)
    {
        RunCoroutine(RunPayloadTerminal(CancellationFailure()));
    }

    TEST(VmessConnTerminalRead, CleanBoundaryEofIsStable)
    {
        RunCoroutine(RunCleanBoundaryEof());
    }

    TEST(VmessConnTerminalRead, ZeroLengthHeaderEofIsCleanBoundary)
    {
        RunCoroutine(RunZeroLengthHeaderEof());
    }

    TEST(VmessConnTerminalRead, CompleteDatagramPrecedesReset)
    {
        RunCoroutine(RunDatagramPrecedesTerminal(ResetFailure()));
    }

    TEST(VmessConnTerminalRead, CompleteDatagramPrecedesEof)
    {
        RunCoroutine(RunDatagramPrecedesTerminal(EofFailure()));
    }

    TEST(VmessConnTerminalRead, CompleteDatagramPrecedesCancellation)
    {
        RunCoroutine(RunDatagramPrecedesTerminal(CancellationFailure()));
    }

    TEST(VmessConnTerminalRead, PartialDatagramHeaderEofIsSticky)
    {
        RunCoroutine(RunPartialDatagramEof(false));
    }

    TEST(VmessConnTerminalRead, PartialDatagramPayloadEofIsSticky)
    {
        RunCoroutine(RunPartialDatagramEof(true));
    }
} // namespace
