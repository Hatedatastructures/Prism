/**
 * @file RestlsRecordTerminalTest.cpp
 * @brief Restls 完整 TLS record 先解码、同读终态随后 sticky 交付的回归测试。
 */

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Restls/Detail/Codec.hpp>
#include <Prism/Protocols/Restls/Detail/Conn.hpp>
#include <Prism/Protocols/Restls/Types.hpp>
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
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Restls = Prism::Restls;
    namespace Detail = Prism::Restls::Detail;

    class ScriptedRecordTransmission final : public Prism::Transmission
    {
    public:
        ScriptedRecordTransmission(
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

    struct ReadOutcome final
    {
        bool HandshakeSucceeded{false};
        ReadObservation First;
        ReadObservation Second;
        ReadObservation Third;
        bool CloseSucceeded{false};
        bool ConnDrainSucceeded{false};
        bool InnerDrainSucceeded{false};
    };

    struct ReadRequest final
    {
        std::shared_ptr<ScriptedRecordTransmission> Inner;
        std::shared_ptr<Detail::Conn<>> Connection;
        ReadOutcome *Outcome;
        std::array<std::uint8_t, 32> ServerRandom{};
        std::vector<std::uint8_t> ClientFinished;
    };

    struct ReadRequestInput final
    {
        std::vector<std::byte> Wire;
        Prism::Fault::Failure Terminal;
        std::array<std::uint8_t, 32> ServerRandom{};
        std::vector<std::uint8_t> ClientFinished;
        ReadOutcome *Outcome;
    };

    struct ReadScenario final
    {
        std::array<std::uint8_t, 32> ServerRandom{};
        std::vector<std::uint8_t> ClientFinished;
        std::vector<std::uint8_t> Record;
    };

    [[nodiscard]] auto ToBytes(std::span<const std::uint8_t> Input)
        -> std::vector<std::byte>
    {
        const auto View = std::as_bytes(Input);
        return std::vector<std::byte>(View.begin(), View.end());
    }

    [[nodiscard]] auto MakeFrame(
        std::span<const std::uint8_t, 32> ServerRandom,
        std::span<const std::uint8_t> ClientFinished,
        std::span<const std::uint8_t> Data) -> std::vector<std::uint8_t>
    {
        const auto Secret = Detail::DeriveSecret("pw");
        auto [Error, Wire] = Detail::BuildFrame(Detail::FrameOptions{
            .Secret = Secret,
            .ServerRandom = ServerRandom,
            .Direction = Restls::FlowDirection::ToServer,
            .Counter = 0,
            .ClientFinished = ClientFinished,
            .Data = Data,
            .PaddingLength = 0,
            .Command = Restls::CmdTypeNoop,
            .CommandArgument = 0});
        if (Error != Prism::Error::None)
        {
            return {};
        }
        return Wire;
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

    auto CloseAndDrain(ReadRequest &Request) -> Net::awaitable<void>
    {
        const auto Closed = Request.Connection->Close();
        Request.Outcome->CloseSucceeded = static_cast<bool>(Closed);
        const auto ConnDrain = co_await Request.Connection->Activity()->Drain();
        Request.Outcome->ConnDrainSucceeded = static_cast<bool>(ConnDrain);
        const auto InnerDrain = co_await Request.Inner->Activity()->Drain();
        Request.Outcome->InnerDrainSucceeded = static_cast<bool>(InnerDrain);
    }

    auto RunRead(ReadRequest Request) -> Net::awaitable<void>
    {
        const auto Handshake = co_await Request.Connection->ReadHandshake(
            Request.ServerRandom, Request.ClientFinished);
        Request.Outcome->HandshakeSucceeded = static_cast<bool>(Handshake);
        if (!Handshake)
        {
            co_await CloseAndDrain(Request);
            co_return;
        }

        std::array<std::byte, 128> Buffer{};
        auto Result = co_await Request.Connection->ReadSome(Buffer);
        CaptureRead(Request.Outcome->First, Result, Buffer);
        Result = co_await Request.Connection->ReadSome(Buffer);
        CaptureRead(Request.Outcome->Second, Result, Buffer);
        Result = co_await Request.Connection->ReadSome(Buffer);
        CaptureRead(Request.Outcome->Third, Result, Buffer);

        co_await CloseAndDrain(Request);
    }

    auto RunRecordTerminalScenario(Net::io_context &Context, ReadRequest Request) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(
            Context, RunRead(std::move(Request)),
            [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
        Context.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    [[nodiscard]] auto MakeRequest(
        Net::io_context &Context,
        ReadRequestInput Input) -> ReadRequest
    {
        auto Inner = std::make_shared<ScriptedRecordTransmission>(
            Context.get_executor(), std::move(Input.Wire), Input.Terminal);
        auto Connection = std::make_shared<Detail::Conn<>>(Inner, "pw");
        return {std::move(Inner), std::move(Connection), Input.Outcome,
                Input.ServerRandom, std::move(Input.ClientFinished)};
    }

    auto ExpectTerminal(
        const ReadObservation &Observation,
        const Prism::Fault::Failure &Expected) -> void
    {
        EXPECT_EQ(Observation.Bytes, 0U);
        EXPECT_EQ(Observation.Failure.Code, Expected.Code);
        EXPECT_EQ(Observation.Failure.Native, Expected.Native);
    }

    [[nodiscard]] auto BuildScenario() -> ReadScenario
    {
        ReadScenario Scenario;
        for (std::size_t Index = 0; Index < Scenario.ServerRandom.size(); ++Index)
        {
            Scenario.ServerRandom[Index] = static_cast<std::uint8_t>(Index + 1U);
        }
        Scenario.ClientFinished = {0x16, 0x03, 0x03, 0x00, 0x01, 0x01};
        constexpr std::array<std::uint8_t, 5> Payload{'h', 'e', 'l', 'l', 'o'};
        Scenario.Record = MakeFrame(
            Scenario.ServerRandom, Scenario.ClientFinished, Payload);
        return Scenario;
    }
}

TEST(RestlsRecordTerminal, CompleteRecordPrecedesEof)
{
    Net::io_context Context;
    auto Scenario = BuildScenario();
    ASSERT_FALSE(Scenario.Record.empty());
    ReadOutcome Outcome;
    const Prism::Fault::Failure Eof{Prism::Fault::Code::Eof};
    const auto Request = MakeRequest(Context, ReadRequestInput{
        ToBytes(Scenario.Record), Eof, Scenario.ServerRandom,
        Scenario.ClientFinished, &Outcome});
    const auto Inner = Request.Inner;

    RunRecordTerminalScenario(Context, Request);

    EXPECT_TRUE(Outcome.HandshakeSucceeded);
    EXPECT_EQ(Outcome.First.Data, "hello");
    EXPECT_TRUE(Outcome.First.Failure.Succeeded());
    ExpectTerminal(Outcome.Second, Eof);
    ExpectTerminal(Outcome.Third, Eof);
    EXPECT_FALSE(Outcome.Second.Failure.Native);
    EXPECT_FALSE(Outcome.Third.Failure.Native);
    EXPECT_EQ(Inner->ReadCount(), 2U);
    EXPECT_EQ(Inner->CloseCount(), 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.ConnDrainSucceeded);
    EXPECT_TRUE(Outcome.InnerDrainSucceeded);
}

TEST(RestlsRecordTerminal, CompleteRecordPrecedesNativeReset)
{
    Net::io_context Context;
    auto Scenario = BuildScenario();
    ASSERT_FALSE(Scenario.Record.empty());
    ReadOutcome Outcome;
    const Prism::Fault::Failure Reset{
        Prism::Fault::Code::IoError,
        std::make_error_code(std::errc::connection_reset)};
    const auto Request = MakeRequest(Context, ReadRequestInput{
        ToBytes(Scenario.Record), Reset, Scenario.ServerRandom,
        Scenario.ClientFinished, &Outcome});
    const auto Inner = Request.Inner;

    RunRecordTerminalScenario(Context, Request);

    EXPECT_TRUE(Outcome.HandshakeSucceeded);
    EXPECT_EQ(Outcome.First.Data, "hello");
    EXPECT_TRUE(Outcome.First.Failure.Succeeded());
    ExpectTerminal(Outcome.Second, Reset);
    ExpectTerminal(Outcome.Third, Reset);
    EXPECT_EQ(Inner->ReadCount(), 2U);
    EXPECT_EQ(Inner->CloseCount(), 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.ConnDrainSucceeded);
    EXPECT_TRUE(Outcome.InnerDrainSucceeded);
}

TEST(RestlsRecordTerminal, PartialRecordPreservesNativeFailureWithoutReread)
{
    Net::io_context Context;
    auto Scenario = BuildScenario();
    ASSERT_FALSE(Scenario.Record.empty());
    ASSERT_GT(Scenario.Record.size(), 3U);
    Scenario.Record.resize(Scenario.Record.size() - 3U);
    ReadOutcome Outcome;
    const Prism::Fault::Failure Reset{
        Prism::Fault::Code::IoError,
        std::make_error_code(std::errc::connection_reset)};
    const auto Request = MakeRequest(Context, ReadRequestInput{
        ToBytes(Scenario.Record), Reset, Scenario.ServerRandom,
        Scenario.ClientFinished, &Outcome});
    const auto Inner = Request.Inner;

    RunRecordTerminalScenario(Context, Request);

    EXPECT_TRUE(Outcome.HandshakeSucceeded);
    ExpectTerminal(Outcome.First, Reset);
    ExpectTerminal(Outcome.Second, Reset);
    ExpectTerminal(Outcome.Third, Reset);
    EXPECT_EQ(Inner->ReadCount(), 2U);
    EXPECT_EQ(Inner->CloseCount(), 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.ConnDrainSucceeded);
    EXPECT_TRUE(Outcome.InnerDrainSucceeded);
}
