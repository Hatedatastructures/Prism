/**
 * @file RecordEndTest.cpp
 * @brief Shadowtls 完整记录先交付且同读终态保持粘性的回归测试。
 */

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Shadowtls/Types.hpp>
#include <Prism/Protocols/Shadowtls/Detail/CarrierWire.hpp>
#include <Prism/Protocols/Shadowtls/Detail/ClientHello.hpp>
#include <Prism/Protocols/Shadowtls/Detail/Conn.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Shadowtls = Prism::Shadowtls;
    namespace Detail = Prism::Shadowtls::Detail;

    class ScriptedReadTransmission final : public Prism::Transmission
    {
    public:
        ScriptedReadTransmission(
            ExecutorType Executor,
            std::vector<std::byte> Wire,
            Prism::Fault::Failure Terminal)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)),
              Wire_(std::move(Wire)), Terminal_(Terminal)
        {
        }

        [[nodiscard]] auto ReadCount() const noexcept -> std::size_t
        {
            return ReadCount_;
        }

        [[nodiscard]] auto CloseCount() const noexcept -> std::size_t
        {
            return CloseCount_;
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCount_;
            if (Offset_ == Wire_.size())
            {
                Prism::Transmission::PostResult(
                    Executor_, std::move(Handler), {0, {Prism::Fault::Code::WouldBlock}});
                return;
            }
            const auto Count = (std::min)(Buffer.size(), Wire_.size() - Offset_);
            std::copy_n(
                Wire_.begin() + static_cast<std::ptrdiff_t>(Offset_), Count, Buffer.begin());
            Offset_ += Count;
            const auto Failure = Offset_ == Wire_.size()
                                     ? Terminal_
                                     : Prism::Fault::Failure{};
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {Count, Failure});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor_, std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            ++CloseCount_;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        ExecutorType Executor_;
        std::vector<std::byte> Wire_;
        Prism::Fault::Failure Terminal_;
        std::size_t Offset_{0};
        std::size_t ReadCount_{0};
        std::size_t CloseCount_{0};
    };

    struct ReadObservation final
    {
        std::size_t Bytes{0};
        std::string Data;
        Prism::Fault::Failure Failure{};
    };

    struct ClientHelloOutcome final
    {
        bool HandshakeSucceeded{false};
        std::vector<std::uint8_t> ClientHello;
        Shadowtls::Failure FirstHandshakeFailure{};
        Shadowtls::Failure StickyHandshakeFailure{};
        ReadObservation FirstRead;
        ReadObservation SecondRead;
        bool CloseSucceeded{false};
        bool ConnDrainSucceeded{false};
        bool InnerDrainSucceeded{false};
    };

    struct ClientHelloRequest final
    {
        std::shared_ptr<ScriptedReadTransmission> Inner;
        std::shared_ptr<Detail::Conn<>> Connection;
        ClientHelloOutcome *Outcome;
    };

    struct ClientHelloInput final
    {
        std::vector<std::uint8_t> Wire;
        Prism::Fault::Failure Terminal;
        ClientHelloOutcome *Outcome;
    };

    struct ServerRecordOutcome final
    {
        bool RecordSucceeded{false};
        bool ServerHelloParsed{false};
        std::vector<std::uint8_t> Record;
        std::vector<std::uint8_t> ServerRandom;
        Shadowtls::Failure FirstFailure{};
        Shadowtls::Failure StickyFailure{};
        bool CloseSucceeded{false};
        bool InnerDrainSucceeded{false};
    };

    struct ServerRecordRequest final
    {
        std::shared_ptr<ScriptedReadTransmission> Inner;
        ServerRecordOutcome *Outcome;
    };

    [[nodiscard]] auto ToBytes(std::span<const std::uint8_t> Input)
        -> std::vector<std::byte>
    {
        const auto View = std::as_bytes(Input);
        return std::vector<std::byte>(View.begin(), View.end());
    }

    [[nodiscard]] auto MakeClientHelloRecord() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Hello(75, 0);
        Hello[0] = 0x03;
        Hello[1] = 0x03;
        for (std::size_t Index = 0; Index < Shadowtls::TlsRndSize; ++Index)
        {
            Hello[2 + Index] = static_cast<std::uint8_t>(0x60 + Index);
        }
        Hello[34] = Shadowtls::TlsSessionIdSz;
        Hello[67] = 0;
        Hello[68] = 2;
        Hello[69] = 0x13;
        Hello[70] = 0x01;
        Hello[71] = 1;
        Hello[72] = 0;
        Hello[73] = 0;
        Hello[74] = 0;

        std::vector<std::uint8_t> Record(Shadowtls::TlsHdrsize + 4 + Hello.size(), 0);
        Record[0] = 0x16;
        Record[1] = 0x03;
        Record[2] = 0x03;
        const auto BodyLength = static_cast<std::uint16_t>(4 + Hello.size());
        Record[3] = static_cast<std::uint8_t>(BodyLength >> 8);
        Record[4] = static_cast<std::uint8_t>(BodyLength);
        Record[5] = Shadowtls::HsTypeClienthello;
        Record[7] = static_cast<std::uint8_t>(Hello.size() >> 8);
        Record[8] = static_cast<std::uint8_t>(Hello.size());
        std::copy(Hello.begin(), Hello.end(), Record.begin() + 9);
        std::span<std::uint8_t, Shadowtls::TlsSessionIdSz> SessionId(
            Record.data() + Shadowtls::TlsHdrsize + Shadowtls::SessionIdStart,
            Shadowtls::TlsSessionIdSz);
        EXPECT_EQ(Detail::GenerateSessionId(
                      Detail::SessionIdInput{
                          "pw", std::span<const std::uint8_t>(Record).subspan(5), SessionId}),
                  Prism::Error::None);
        return Record;
    }

    [[nodiscard]] auto MakeServerHelloRecord() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Hello(78, 0);
        Hello[0] = 0x03;
        Hello[1] = 0x03;
        for (std::size_t Index = 0; Index < Shadowtls::TlsRndSize; ++Index)
        {
            Hello[2 + Index] = static_cast<std::uint8_t>(0x80 + Index);
        }
        Hello[34] = Shadowtls::TlsSessionIdSz;
        Hello[67] = 0x13;
        Hello[68] = 0x01;
        Hello[69] = 0;
        Hello[70] = 0;
        Hello[71] = 6;
        Hello[72] = 0;
        Hello[73] = 43;
        Hello[74] = 0;
        Hello[75] = 2;
        Hello[76] = 3;
        Hello[77] = 4;

        std::vector<std::uint8_t> Record(Shadowtls::TlsHdrsize + 4 + Hello.size(), 0);
        Record[0] = 0x16;
        Record[1] = 0x03;
        Record[2] = 0x03;
        const auto BodyLength = static_cast<std::uint16_t>(4 + Hello.size());
        Record[3] = static_cast<std::uint8_t>(BodyLength >> 8);
        Record[4] = static_cast<std::uint8_t>(BodyLength);
        Record[5] = 2;
        Record[7] = static_cast<std::uint8_t>(Hello.size() >> 8);
        Record[8] = static_cast<std::uint8_t>(Hello.size());
        std::copy(Hello.begin(), Hello.end(), Record.begin() + 9);
        return Record;
    }

    auto CaptureRead(
        ReadObservation &Observation,
        const Prism::IoResult &Result,
        std::span<const std::byte> Buffer) -> void
    {
        Observation.Bytes = Result.Bytes;
        Observation.Failure = Result.Failure;
        if (Result.Bytes <= Buffer.size())
        {
            Observation.Data.assign(
                reinterpret_cast<const char *>(Buffer.data()), Result.Bytes);
        }
    }

    [[nodiscard]] auto MakeClientHelloRequest(
        Net::io_context &Context,
        ClientHelloInput Input) -> ClientHelloRequest
    {
        auto Inner = std::make_shared<ScriptedReadTransmission>(
            Context.get_executor(), ToBytes(Input.Wire), Input.Terminal);
        auto Connection = std::make_shared<Detail::Conn<>>(Inner, "pw");
        return {std::move(Inner), std::move(Connection), Input.Outcome};
    }

    auto RunClientHello(ClientHelloRequest Request) -> Net::awaitable<void>
    {
        auto Handshake = co_await Request.Connection->ReadStandardHandshake();
        Request.Outcome->HandshakeSucceeded = static_cast<bool>(Handshake);
        if (Handshake)
        {
            Request.Outcome->ClientHello = Request.Connection->TakeClientHelloWire();
            std::array<std::byte, 32> Buffer{};
            auto Read = co_await Request.Connection->ReadSome(Buffer);
            CaptureRead(Request.Outcome->FirstRead, Read, Buffer);
            Read = co_await Request.Connection->ReadSome(Buffer);
            CaptureRead(Request.Outcome->SecondRead, Read, Buffer);
        }
        else
        {
            Request.Outcome->FirstHandshakeFailure = Handshake.error();
            auto Sticky = co_await Request.Connection->ReadStandardHandshake();
            if (!Sticky) Request.Outcome->StickyHandshakeFailure = Sticky.error();
        }

        const auto Closed = Request.Connection->Close();
        Request.Outcome->CloseSucceeded = static_cast<bool>(Closed);
        const auto ConnDrain = co_await Request.Connection->Activity()->Drain();
        Request.Outcome->ConnDrainSucceeded = static_cast<bool>(ConnDrain);
        const auto InnerDrain = co_await Request.Inner->Activity()->Drain();
        Request.Outcome->InnerDrainSucceeded = static_cast<bool>(InnerDrain);
    }

    auto RunServerRecord(ServerRecordRequest Request) -> Net::awaitable<void>
    {
        std::optional<Shadowtls::Failure> PendingTerminal;
        auto First = co_await Detail::Io::ReadRecord(Request.Inner, PendingTerminal);
        Request.Outcome->RecordSucceeded = static_cast<bool>(First);
        if (First)
        {
            Request.Outcome->Record = std::move(*First);
            Shadowtls::Detail::ServerHelloRecord Parsed;
            Request.Outcome->ServerHelloParsed =
                Detail::ParseServerHelloRecord(Request.Outcome->Record, Parsed) == Prism::Error::None;
            if (Request.Outcome->ServerHelloParsed)
            {
                Request.Outcome->ServerRandom.assign(Parsed.Random.begin(), Parsed.Random.end());
            }
        }
        else
        {
            Request.Outcome->FirstFailure = First.error();
        }

        auto Sticky = co_await Detail::Io::ReadRecord(Request.Inner, PendingTerminal);
        if (!Sticky) Request.Outcome->StickyFailure = Sticky.error();
        const auto Closed = Request.Inner->Close();
        Request.Outcome->CloseSucceeded = static_cast<bool>(Closed);
        const auto InnerDrain = co_await Request.Inner->Activity()->Drain();
        Request.Outcome->InnerDrainSucceeded = static_cast<bool>(InnerDrain);
    }

    auto RunTerminalScenario(Net::io_context &Context, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(
            Context, std::move(Operation),
            [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
        Context.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto ExpectFault(
        const Prism::Fault::Failure &Actual,
        const Prism::Fault::Failure &Expected) -> void
    {
        EXPECT_EQ(Actual.Code, Expected.Code);
        EXPECT_EQ(Actual.Native, Expected.Native);
    }

    auto ExpectFailure(
        const Shadowtls::Failure &Actual,
        const Shadowtls::Failure &Expected) -> void
    {
        EXPECT_EQ(Actual.Code, Expected.Code);
        EXPECT_EQ(Actual.Native, Expected.Native);
        EXPECT_EQ(Actual.Bytes, Expected.Bytes);
    }
}

TEST(ShadowtlsRecordTerminal, ClientHelloRecordPrecedesSameReadEof)
{
    Net::io_context Context;
    const auto Wire = MakeClientHelloRecord();
    ClientHelloOutcome Outcome;
    const Prism::Fault::Failure Eof{Prism::Fault::Code::Eof};
    const auto Request = MakeClientHelloRequest(Context, ClientHelloInput{Wire, Eof, &Outcome});
    const auto Inner = Request.Inner;

    RunTerminalScenario(Context, RunClientHello(Request));

    EXPECT_TRUE(Outcome.HandshakeSucceeded);
    EXPECT_EQ(Outcome.ClientHello, Wire);
    ExpectFault(Outcome.FirstRead.Failure, Eof);
    ExpectFault(Outcome.SecondRead.Failure, Eof);
    EXPECT_EQ(Inner->ReadCount(), 2U);
    EXPECT_EQ(Inner->CloseCount(), 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.ConnDrainSucceeded);
    EXPECT_TRUE(Outcome.InnerDrainSucceeded);
}

TEST(ShadowtlsRecordTerminal, ClientHelloRecordPrecedesSameReadNativeReset)
{
    Net::io_context Context;
    const auto Wire = MakeClientHelloRecord();
    ClientHelloOutcome Outcome;
    const Prism::Fault::Failure Reset{
        Prism::Fault::Code::IoError,
        std::make_error_code(std::errc::connection_reset)};
    const auto Request = MakeClientHelloRequest(Context, ClientHelloInput{Wire, Reset, &Outcome});
    const auto Inner = Request.Inner;

    RunTerminalScenario(Context, RunClientHello(Request));

    EXPECT_TRUE(Outcome.HandshakeSucceeded);
    EXPECT_EQ(Outcome.ClientHello, Wire);
    ExpectFault(Outcome.FirstRead.Failure, Reset);
    ExpectFault(Outcome.SecondRead.Failure, Reset);
    EXPECT_EQ(Inner->ReadCount(), 2U);
    EXPECT_EQ(Inner->CloseCount(), 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.ConnDrainSucceeded);
    EXPECT_TRUE(Outcome.InnerDrainSucceeded);
}

TEST(ShadowtlsRecordTerminal, PartialClientHelloKeepsNativeFailureSticky)
{
    Net::io_context Context;
    auto Wire = MakeClientHelloRecord();
    ASSERT_GT(Wire.size(), 3U);
    Wire.resize(Wire.size() - 3U);
    ClientHelloOutcome Outcome;
    const Prism::Fault::Failure Reset{
        Prism::Fault::Code::IoError,
        std::make_error_code(std::errc::connection_reset)};
    const auto Request = MakeClientHelloRequest(Context, ClientHelloInput{Wire, Reset, &Outcome});
    const auto Inner = Request.Inner;

    RunTerminalScenario(Context, RunClientHello(Request));

    EXPECT_FALSE(Outcome.HandshakeSucceeded);
    ExpectFailure(Outcome.FirstHandshakeFailure, Shadowtls::FailureFromFault(Reset, Wire.size()));
    ExpectFailure(Outcome.StickyHandshakeFailure, Shadowtls::FailureFromFault(Reset, Wire.size()));
    EXPECT_EQ(Inner->ReadCount(), 2U);
    EXPECT_EQ(Inner->CloseCount(), 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.ConnDrainSucceeded);
    EXPECT_TRUE(Outcome.InnerDrainSucceeded);
}

TEST(ShadowtlsRecordTerminal, ServerHelloRecordPrecedesSameReadNativeReset)
{
    Net::io_context Context;
    const auto Wire = MakeServerHelloRecord();
    ServerRecordOutcome Outcome;
    const Prism::Fault::Failure Reset{
        Prism::Fault::Code::IoError,
        std::make_error_code(std::errc::connection_reset)};
    auto Inner = std::make_shared<ScriptedReadTransmission>(
        Context.get_executor(), ToBytes(Wire), Reset);

    RunTerminalScenario(Context, RunServerRecord({Inner, &Outcome}));

    EXPECT_TRUE(Outcome.RecordSucceeded);
    EXPECT_TRUE(Outcome.ServerHelloParsed);
    EXPECT_EQ(Outcome.Record, Wire);
    ASSERT_EQ(Outcome.ServerRandom.size(), Shadowtls::TlsRndSize);
    EXPECT_EQ(Outcome.ServerRandom.front(), 0x80U);
    ExpectFailure(Outcome.StickyFailure, Shadowtls::FailureFromFault(Reset, Wire.size()));
    EXPECT_EQ(Inner->ReadCount(), 2U);
    EXPECT_EQ(Inner->CloseCount(), 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.InnerDrainSucceeded);
}

TEST(ShadowtlsRecordTerminal, ServerHelloRecordPrecedesSameReadEof)
{
    Net::io_context Context;
    const auto Wire = MakeServerHelloRecord();
    ServerRecordOutcome Outcome;
    const Prism::Fault::Failure Eof{Prism::Fault::Code::Eof};
    auto Inner = std::make_shared<ScriptedReadTransmission>(
        Context.get_executor(), ToBytes(Wire), Eof);

    RunTerminalScenario(Context, RunServerRecord({Inner, &Outcome}));

    EXPECT_TRUE(Outcome.RecordSucceeded);
    EXPECT_TRUE(Outcome.ServerHelloParsed);
    EXPECT_EQ(Outcome.Record, Wire);
    ASSERT_EQ(Outcome.ServerRandom.size(), Shadowtls::TlsRndSize);
    EXPECT_EQ(Outcome.ServerRandom.front(), 0x80U);
    ExpectFailure(Outcome.StickyFailure, Shadowtls::FailureFromFault(Eof, Wire.size()));
    EXPECT_EQ(Inner->ReadCount(), 2U);
    EXPECT_EQ(Inner->CloseCount(), 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.InnerDrainSucceeded);
}

TEST(ShadowtlsRecordTerminal, PartialServerHelloKeepsNativeFailureSticky)
{
    Net::io_context Context;
    auto Wire = MakeServerHelloRecord();
    ASSERT_GT(Wire.size(), 3U);
    Wire.resize(Wire.size() - 3U);
    ServerRecordOutcome Outcome;
    const Prism::Fault::Failure Reset{
        Prism::Fault::Code::IoError,
        std::make_error_code(std::errc::connection_reset)};
    auto Inner = std::make_shared<ScriptedReadTransmission>(
        Context.get_executor(), ToBytes(Wire), Reset);

    RunTerminalScenario(Context, RunServerRecord({Inner, &Outcome}));

    EXPECT_FALSE(Outcome.RecordSucceeded);
    ExpectFailure(Outcome.FirstFailure, Shadowtls::FailureFromFault(Reset, Wire.size()));
    ExpectFailure(Outcome.StickyFailure, Shadowtls::FailureFromFault(Reset, Wire.size()));
    EXPECT_EQ(Inner->ReadCount(), 2U);
    EXPECT_EQ(Inner->CloseCount(), 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.InnerDrainSucceeded);
}
