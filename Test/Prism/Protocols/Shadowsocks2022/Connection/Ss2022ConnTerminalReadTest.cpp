/**
 * @file Ss2022ConnTerminalReadTest.cpp
 * @brief SS2022 完整 chunk 与同次读取终态的交付顺序回归。
 */
#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/this_coro.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Shadowsocks2022/ChunkCodec.hpp>
#include <Prism/Protocols/Shadowsocks2022/ConnRecord.hpp>
#include <Prism/Protocols/Shadowsocks2022/ConnSession.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace SS2022 = Prism::Shadowsocks2022;
    namespace Fault = Prism::Fault;
    using Memory = Prism::Memory::SessionResource<>;
    using Session = SS2022::detail::ConnSession<Memory>;
    using Record = SS2022::detail::ConnRecord<Memory>;
    using Key = std::array<std::uint8_t, 16>;

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

    struct RecordParts final
    {
        std::vector<std::byte> Header;
        std::vector<std::byte> Payload;
    };

    [[nodiscard]] auto Plaintext() -> std::array<std::uint8_t, 5>
    {
        return {0x21, 0x22, 0x23, 0x24, 0x25};
    }

    [[nodiscard]] auto EncodeRecord(const Key &KeyValue) -> RecordParts
    {
        SS2022::ChunkCodec Encoder{std::span<const std::uint8_t>(KeyValue)};
        const auto Plain = Plaintext();
        const auto Wire = Encoder.Seal(std::span<const std::uint8_t>(Plain));
        const auto Bytes = std::as_bytes(std::span(Wire));
        return {
            std::vector<std::byte>(Bytes.begin(), Bytes.begin() + SS2022::LenBlockSize),
            std::vector<std::byte>(Bytes.begin() + SS2022::LenBlockSize, Bytes.end())};
    }

    struct ReadFixture final
    {
        explicit ReadFixture(Net::any_io_executor Executor, const Key &KeyValue)
            : Raw(std::make_shared<ScriptedTransmission>(Executor)),
              SessionValue(SS2022::ConnOptions{.Executor = std::move(Executor),
                                               .Psk = KeyValue}),
              RecordValue(SessionValue)
        {
            SessionValue.Handshaken_ = true;
            SessionValue.SetUpstream(Raw);
            RecordValue.ConfigureDecoder(
                SS2022::ChunkCodec{std::span<const std::uint8_t>(KeyValue)});
        }

        std::shared_ptr<ScriptedTransmission> Raw;
        Session SessionValue;
        Record RecordValue;
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

    [[nodiscard]] auto TruncatedFailure() -> Fault::Failure
    {
        return {Fault::Detail::MapProtocolCategoryValue(
            static_cast<int>(Prism::Error::UnexpectedEof))};
    }

    [[nodiscard]] auto TestKey() -> Key
    {
        return {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
                0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50};
    }

    auto VerifyStickyFailure(ReadFixture &Fixture,
                             const Fault::Failure &Expected,
                             const std::size_t ExpectedReads) -> Net::awaitable<void>
    {
        std::array<std::byte, 16> Buffer{};
        for (int Attempt = 0; Attempt != 2; ++Attempt)
        {
            const auto Retry = co_await Fixture.RecordValue.ReadSome(Buffer);
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
        auto Fixture = ReadFixture(co_await Net::this_coro::executor, TestKey());
        const auto Parts = EncodeRecord(TestKey());
        Fixture.Raw->QueueRead({Parts.Header, {}});
        Fixture.Raw->QueueRead({Parts.Payload, Terminal});
        std::array<std::byte, 2> Buffer{};
        const auto Read = co_await Fixture.RecordValue.ReadSome(Buffer);
        const auto Plain = Plaintext();
        const auto PlainBytes = std::as_bytes(std::span(Plain));
        EXPECT_EQ(Read.Bytes, Buffer.size());
        EXPECT_FALSE(Read.Failure.Failed());
        EXPECT_TRUE(std::equal(Buffer.begin(), Buffer.end(), PlainBytes.begin()));
        EXPECT_EQ(Fixture.Raw->ReadsDone(), 2U);
        std::array<std::byte, 8> Tail{};
        const auto TailRead = co_await Fixture.RecordValue.ReadSome(Tail);
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
        auto Fixture = ReadFixture(co_await Net::this_coro::executor, TestKey());
        const auto Parts = EncodeRecord(TestKey());
        if (CompleteField)
        {
            Fixture.Raw->QueueRead({Parts.Header, Terminal});
        }
        else
        {
            Fixture.Raw->QueueRead({{Parts.Header.front()}, Terminal});
        }
        std::array<std::byte, 16> Buffer{};
        const auto Read = co_await Fixture.RecordValue.ReadSome(Buffer);
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
        auto Fixture = ReadFixture(co_await Net::this_coro::executor, TestKey());
        const auto Parts = EncodeRecord(TestKey());
        Fixture.Raw->QueueRead({Parts.Header, {}});
        Fixture.Raw->QueueRead({{Parts.Payload.front()}, Terminal});
        std::array<std::byte, 16> Buffer{};
        const auto Read = co_await Fixture.RecordValue.ReadSome(Buffer);
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
        auto Fixture = ReadFixture(co_await Net::this_coro::executor, TestKey());
        Fixture.Raw->QueueRead({{}, EofFailure()});
        std::array<std::byte, 16> Buffer{};
        const auto Read = co_await Fixture.RecordValue.ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0U);
        EXPECT_EQ(Read.Failure.Code, Fault::Code::Eof);
        co_await VerifyStickyFailure(Fixture, EofFailure(), 1U);
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

    TEST(Ss2022ConnTerminalRead, CompleteChunkPrecedesReset)
    {
        RunCoroutine(RunCompleteChunkTerminal(ResetFailure()));
    }

    TEST(Ss2022ConnTerminalRead, CompleteChunkPrecedesEof)
    {
        RunCoroutine(RunCompleteChunkTerminal(EofFailure()));
    }

    TEST(Ss2022ConnTerminalRead, CompleteLengthResetCannotCompleteChunk)
    {
        RunCoroutine(RunHeaderTerminal(ResetFailure(), true));
    }

    TEST(Ss2022ConnTerminalRead, CompleteLengthEofCannotCompleteChunk)
    {
        RunCoroutine(RunHeaderTerminal(EofFailure(), true));
    }

    TEST(Ss2022ConnTerminalRead, PartialLengthResetIsSticky)
    {
        RunCoroutine(RunHeaderTerminal(ResetFailure(), false));
    }

    TEST(Ss2022ConnTerminalRead, PartialLengthEofIsSticky)
    {
        RunCoroutine(RunHeaderTerminal(EofFailure(), false));
    }

    TEST(Ss2022ConnTerminalRead, PartialPayloadResetIsSticky)
    {
        RunCoroutine(RunPayloadTerminal(ResetFailure()));
    }

    TEST(Ss2022ConnTerminalRead, PartialPayloadEofIsSticky)
    {
        RunCoroutine(RunPayloadTerminal(EofFailure()));
    }

    TEST(Ss2022ConnTerminalRead, CleanBoundaryEofIsStable)
    {
        RunCoroutine(RunCleanBoundaryEof());
    }

} // namespace
