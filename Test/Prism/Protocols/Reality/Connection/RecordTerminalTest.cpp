/**
 * @file RecordTerminalTest.cpp
 * @brief Reality TLS record 完成字节先于同读终态的回归测试。
 */

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Reality/Detail/CarrierStream.hpp>
#include <Prism/Protocols/Reality/Detail/Tls13.hpp>
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
    namespace Reality = Prism::Reality;
    namespace Detail = Prism::Reality::Detail;

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
        ReadObservation First;
        ReadObservation Second;
        ReadObservation Third;
        bool CloseSucceeded{false};
        bool StreamDrainSucceeded{false};
        bool InnerDrainSucceeded{false};
    };

    struct ReadRequest final
    {
        std::shared_ptr<ScriptedRecordTransmission> Inner;
        std::shared_ptr<Detail::TlsRecordStream> Stream;
        ReadOutcome *Outcome;
    };

    struct ReadRequestInput final
    {
        std::span<const std::uint8_t> Wire;
        Prism::Fault::Failure Terminal;
        ReadOutcome *Outcome;
    };

    [[nodiscard]] auto MakeKeys() -> Detail::Tls13Keys
    {
        Detail::Tls13Keys Keys;
        for (std::size_t Index = 0; Index < Keys.ClientApplicationKey.size(); ++Index)
        {
            Keys.ClientApplicationKey[Index] = static_cast<std::uint8_t>(Index + 1U);
        }
        for (std::size_t Index = 0; Index < Keys.ClientApplicationIv.size(); ++Index)
        {
            Keys.ClientApplicationIv[Index] = static_cast<std::uint8_t>(0x20U + Index);
        }
        return Keys;
    }

    [[nodiscard]] auto ToBytes(std::span<const std::uint8_t> Input)
        -> std::vector<std::byte>
    {
        const auto View = std::as_bytes(Input);
        return std::vector<std::byte>(View.begin(), View.end());
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

    auto RunRead(ReadRequest Request) -> Net::awaitable<void>
    {
        std::array<std::byte, 128> Buffer{};
        auto Result = co_await Request.Stream->ReadSome(Buffer);
        CaptureRead(Request.Outcome->First, Result, Buffer);
        Result = co_await Request.Stream->ReadSome(Buffer);
        CaptureRead(Request.Outcome->Second, Result, Buffer);
        Result = co_await Request.Stream->ReadSome(Buffer);
        CaptureRead(Request.Outcome->Third, Result, Buffer);

        const auto Closed = Request.Stream->Close();
        Request.Outcome->CloseSucceeded = static_cast<bool>(Closed);
        const auto StreamDrain = co_await Request.Stream->Activity()->Drain();
        Request.Outcome->StreamDrainSucceeded = static_cast<bool>(StreamDrain);
        const auto InnerDrain = co_await Request.Inner->Activity()->Drain();
        Request.Outcome->InnerDrainSucceeded = static_cast<bool>(InnerDrain);
    }

    auto RunReadScenario(Net::io_context &Context, ReadRequest Request) -> void
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

    [[nodiscard]] auto MakeRecord(Detail::Tls13Keys &Keys) -> std::vector<std::uint8_t>
    {
        constexpr std::array<std::uint8_t, 5> Payload{'h', 'e', 'l', 'l', 'o'};
        auto [Error, Record] = Detail::EncryptTlsRecord(
            Detail::Tls13RecordSealInput{
                Keys.ClientApplicationKey,
                std::span<const std::uint8_t, 12>(Keys.ClientApplicationIv),
                0, 0x17, Payload});
        if (Error != Prism::Error::None)
        {
            return {};
        }
        return Record;
    }

    [[nodiscard]] auto MakeRequest(
        Net::io_context &Context,
        ReadRequestInput Input) -> ReadRequest
    {
        auto Inner = std::make_shared<ScriptedRecordTransmission>(
            Context.get_executor(), ToBytes(Input.Wire), Input.Terminal);
        auto Stream = std::make_shared<Detail::TlsRecordStream>(Inner, MakeKeys());
        return {std::move(Inner), std::move(Stream), Input.Outcome};
    }

    auto ExpectTerminal(
        const ReadObservation &Observation,
        const Prism::Fault::Failure &Expected) -> void
    {
        EXPECT_EQ(Observation.Bytes, 0U);
        EXPECT_EQ(Observation.Failure.Code, Expected.Code);
        EXPECT_EQ(Observation.Failure.Native, Expected.Native);
    }
}

TEST(RealityRecordTerminal, CompleteRecordPrecedesEof)
{
    Net::io_context Context;
    auto Keys = MakeKeys();
    const auto Record = MakeRecord(Keys);
    ASSERT_FALSE(Record.empty());
    ReadOutcome Outcome;
    const Prism::Fault::Failure Eof{Prism::Fault::Code::Eof};
    const auto Request = MakeRequest(Context, ReadRequestInput{Record, Eof, &Outcome});
    const auto Inner = Request.Inner;

    RunReadScenario(Context, Request);

    EXPECT_EQ(Outcome.First.Data, "hello");
    EXPECT_TRUE(Outcome.First.Failure.Succeeded());
    ExpectTerminal(Outcome.Second, Eof);
    ExpectTerminal(Outcome.Third, Eof);
    EXPECT_EQ(Inner->ReadCount(), 2U);
    EXPECT_EQ(Inner->CloseCount(), 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.StreamDrainSucceeded);
    EXPECT_TRUE(Outcome.InnerDrainSucceeded);
}

TEST(RealityRecordTerminal, CompleteRecordPrecedesNativeReset)
{
    Net::io_context Context;
    auto Keys = MakeKeys();
    const auto Record = MakeRecord(Keys);
    ASSERT_FALSE(Record.empty());
    ReadOutcome Outcome;
    const Prism::Fault::Failure Reset{
        Prism::Fault::Code::IoError,
        std::make_error_code(std::errc::connection_reset)};
    const auto Request = MakeRequest(Context, ReadRequestInput{Record, Reset, &Outcome});
    const auto Inner = Request.Inner;

    RunReadScenario(Context, Request);

    EXPECT_EQ(Outcome.First.Data, "hello");
    EXPECT_TRUE(Outcome.First.Failure.Succeeded());
    ExpectTerminal(Outcome.Second, Reset);
    ExpectTerminal(Outcome.Third, Reset);
    EXPECT_EQ(Inner->ReadCount(), 2U);
    EXPECT_EQ(Inner->CloseCount(), 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.StreamDrainSucceeded);
    EXPECT_TRUE(Outcome.InnerDrainSucceeded);
}

TEST(RealityRecordTerminal, PartialRecordPreservesNativeFailureWithoutReread)
{
    Net::io_context Context;
    auto Keys = MakeKeys();
    auto Record = MakeRecord(Keys);
    ASSERT_GT(Record.size(), 6U);
    Record.resize(Record.size() - 3U);
    ReadOutcome Outcome;
    const Prism::Fault::Failure Reset{
        Prism::Fault::Code::IoError,
        std::make_error_code(std::errc::connection_reset)};
    const auto Request = MakeRequest(Context, ReadRequestInput{Record, Reset, &Outcome});
    const auto Inner = Request.Inner;

    RunReadScenario(Context, Request);

    ExpectTerminal(Outcome.First, Reset);
    ExpectTerminal(Outcome.Second, Reset);
    ExpectTerminal(Outcome.Third, Reset);
    EXPECT_EQ(Inner->ReadCount(), 2U);
    EXPECT_EQ(Inner->CloseCount(), 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.StreamDrainSucceeded);
    EXPECT_TRUE(Outcome.InnerDrainSucceeded);
}
