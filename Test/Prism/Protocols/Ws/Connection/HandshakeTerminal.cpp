/**
 * @file HandshakeTerminal.cpp
 * @brief WebSocket Upgrade 头与同次读取终态的顺序回归。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Ws/Detail/Codec.hpp>
#include <Prism/Protocols/Ws/Detail/Connection/Handshake.hpp>
#include <Prism/Protocols/Ws/Detail/Connection/Session.hpp>
#include <Prism/Protocols/Ws/Detail/Connection/Transport.hpp>
#include <Prism/Protocols/Ws/Ws.hpp>
#include <Prism/Transport/Transmission.hpp>

#include "../Admission/FactorySupport.hpp"
#include "SessionSupport.hpp"

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Ws = Prism::Ws;
    namespace TestSupport = Prism::Tests::WsFactorySupport;
    using Prism::Tests::WsConnSessionSupport::TestKey;

    class ScriptedUpgradeTransmission final : public Prism::Transmission
    {
    public:
        ScriptedUpgradeTransmission(
            Net::any_io_executor Executor,
            std::vector<std::byte> Input,
            Fault::Failure Terminal)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)),
              Input_(std::move(Input)), Terminal_(std::move(Terminal))
        {
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

        [[nodiscard]] auto CloseCalls() const noexcept -> std::size_t
        {
            return CloseCalls_;
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCalls_;
            const auto Count = (std::min)(Buffer.size(), Input_.size() - Offset_);
            if (Count != 0U)
            {
                std::memcpy(Buffer.data(), Input_.data() + Offset_, Count);
                Offset_ += Count;
            }
            const auto Failure = Offset_ == Input_.size() ? Terminal_ : Fault::Failure{};
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
            ++CloseCalls_;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        ExecutorType Executor_;
        std::vector<std::byte> Input_;
        Fault::Failure Terminal_;
        std::size_t Offset_{0};
        std::size_t ReadCalls_{0};
        std::size_t CloseCalls_{0};
    };

    struct ReadObservation final
    {
        std::size_t Bytes{0};
        std::string Data;
        Fault::Failure Failure{};
    };

    struct UpgradeOutcome final
    {
        bool HandshakeSucceeded{false};
        Fault::Failure HandshakeFailure{};
        std::array<ReadObservation, 3> Reads{};
        std::size_t RawReadCalls{0};
        std::size_t RawCloseCalls{0};
        bool CloseSucceeded{false};
        bool DrainSucceeded{false};
    };

    struct PartialOutcome final
    {
        bool HandshakeSucceeded{false};
        Fault::Failure HandshakeFailure{};
        std::array<Prism::IoResult, 2> Retries{};
        std::size_t RawReadCalls{0};
        std::size_t RawCloseCalls{0};
        bool CloseSucceeded{false};
        bool DrainSucceeded{false};
    };

    auto AppendText(std::vector<std::byte> &Output, const std::string_view Text) -> void
    {
        for (const auto Character : Text)
        {
            Output.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(Character)));
        }
    }

    [[nodiscard]] auto MakeUnmaskedFrame(const std::string_view Payload)
        -> std::vector<std::byte>
    {
        std::vector<std::byte> Frame{
            std::byte{0x82}, static_cast<std::byte>(Payload.size())};
        AppendText(Frame, Payload);
        return Frame;
    }

    [[nodiscard]] auto MakeMaskedFrame(const std::string_view Payload)
        -> std::vector<std::byte>
    {
        constexpr std::array<std::uint8_t, 4> Mask{0xA1U, 0xB2U, 0xC3U, 0xD4U};
        std::vector<std::byte> Frame{
            std::byte{0x82}, static_cast<std::byte>(0x80U | Payload.size())};
        for (const auto Byte : Mask)
        {
            Frame.push_back(static_cast<std::byte>(Byte));
        }
        for (std::size_t Index = 0; Index < Payload.size(); ++Index)
        {
            const auto Byte = static_cast<std::uint8_t>(Payload[Index]);
            Frame.push_back(static_cast<std::byte>(Byte ^ Mask[Index % Mask.size()]));
        }
        return Frame;
    }

    [[nodiscard]] auto MakeClientInput(const bool WithTail) -> std::vector<std::byte>
    {
        const auto Accept = Ws::Detail::ComputeAccept(TestKey);
        const std::string Header =
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Accept: " + Accept + "\r\n\r\n";
        std::vector<std::byte> Input;
        AppendText(Input, Header);
        if (WithTail)
        {
            const auto Frame = MakeUnmaskedFrame("server-tail");
            Input.insert(Input.end(), Frame.begin(), Frame.end());
        }
        return Input;
    }

    [[nodiscard]] auto MakeServerInput(const bool WithTail) -> std::vector<std::byte>
    {
        const std::string Header =
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: " + std::string(TestKey) +
            "\r\nSec-WebSocket-Version: 13\r\n\r\n";
        std::vector<std::byte> Input;
        AppendText(Input, Header);
        if (WithTail)
        {
            const auto Frame = MakeMaskedFrame("client-tail");
            Input.insert(Input.end(), Frame.begin(), Frame.end());
        }
        return Input;
    }

    [[nodiscard]] auto MakeClientPartialInput() -> std::vector<std::byte>
    {
        std::vector<std::byte> Input;
        AppendText(Input,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n");
        return Input;
    }

    [[nodiscard]] auto MakeServerPartialInput() -> std::vector<std::byte>
    {
        std::vector<std::byte> Input;
        AppendText(Input,
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket");
        return Input;
    }

    auto CaptureRead(
        ReadObservation &Observation,
        const Prism::IoResult &Result,
        const std::span<const std::byte> Buffer) -> void
    {
        Observation.Bytes = Result.Bytes;
        Observation.Failure = Result.Failure;
        if (Result.Bytes <= Buffer.size())
        {
            Observation.Data.assign(
                reinterpret_cast<const char *>(Buffer.data()), Result.Bytes);
        }
    }

    auto RunClientSuccess(
        std::shared_ptr<ScriptedUpgradeTransmission> Raw,
        UpgradeOutcome *Outcome) -> Net::awaitable<void>
    {
        auto Connected = co_await Ws::Connect(TestSupport::MakeConnectOptionsForTest(
            Raw, Ws::ClientOptions{"example.com", TestKey}));
        Outcome->HandshakeSucceeded = static_cast<bool>(Connected);
        if (!Connected)
        {
            Outcome->HandshakeFailure = Connected.error();
            co_return;
        }

        auto Connection = std::move(Connected->Connection);
        std::array<std::byte, 32> Buffer{};
        for (auto &Read : Outcome->Reads)
        {
            const auto Result = co_await Connection->ReadSome(Buffer);
            CaptureRead(Read, Result, Buffer);
        }
        const auto Closed = Connection->Close();
        Outcome->CloseSucceeded = static_cast<bool>(Closed);
        const auto Drained = co_await Connection->Activity()->Drain();
        Outcome->DrainSucceeded = static_cast<bool>(Drained);
    }

    auto RunServerSuccess(
        std::shared_ptr<ScriptedUpgradeTransmission> Raw,
        UpgradeOutcome *Outcome) -> Net::awaitable<void>
    {
        auto Accepted = co_await Ws::Accept(TestSupport::MakeAcceptOptionsForTest(
            Raw, Ws::ServerOptions{}));
        Outcome->HandshakeSucceeded = static_cast<bool>(Accepted);
        if (!Accepted)
        {
            Outcome->HandshakeFailure = Accepted.error();
            co_return;
        }

        auto Connection = std::move(Accepted->Connection);
        std::array<std::byte, 32> Buffer{};
        for (auto &Read : Outcome->Reads)
        {
            const auto Result = co_await Connection->ReadSome(Buffer);
            CaptureRead(Read, Result, Buffer);
        }
        const auto Closed = Connection->Close();
        Outcome->CloseSucceeded = static_cast<bool>(Closed);
        const auto Drained = co_await Connection->Activity()->Drain();
        Outcome->DrainSucceeded = static_cast<bool>(Drained);
    }

    auto RunPartialClientHandshake(
        std::shared_ptr<ScriptedUpgradeTransmission> Raw,
        PartialOutcome *Outcome) -> Net::awaitable<void>
    {
        using Memory = Prism::Memory::SessionResource<>;
        Ws::Detail::ConnSession<Memory> Session(
            Raw, TestSupport::WebSocketTestBytes(), true);
        Ws::Detail::ConnTransport<Memory> Transport(Session);
        Ws::Detail::ConnHandshake<Memory> Handshake(Session, Transport);
        const auto Result = co_await Handshake.WriteHandshake(TestKey, "example.com");
        Outcome->HandshakeSucceeded = static_cast<bool>(Result);
        if (!Result)
        {
            Outcome->HandshakeFailure = Result.error();
        }
        std::array<std::uint8_t, 16> Buffer{};
        for (auto &Retry : Outcome->Retries)
        {
            Retry = co_await Transport.ReadHandshakeChunk(Buffer);
        }
        const auto Closed = Raw->Close();
        Outcome->CloseSucceeded = static_cast<bool>(Closed);
        const auto Drained = co_await Raw->Activity()->Drain();
        Outcome->DrainSucceeded = static_cast<bool>(Drained);
    }

    auto RunPartialServerHandshake(
        std::shared_ptr<ScriptedUpgradeTransmission> Raw,
        PartialOutcome *Outcome) -> Net::awaitable<void>
    {
        using Memory = Prism::Memory::SessionResource<>;
        Ws::Detail::ConnSession<Memory> Session(
            Raw, TestSupport::WebSocketTestBytes(), false);
        Ws::Detail::ConnTransport<Memory> Transport(Session);
        Ws::Detail::ConnHandshake<Memory> Handshake(Session, Transport);
        std::string Key;
        const auto Result = co_await Handshake.ReadHandshake(Key);
        Outcome->HandshakeSucceeded = static_cast<bool>(Result);
        if (!Result)
        {
            Outcome->HandshakeFailure = Result.error();
        }
        std::array<std::uint8_t, 16> Buffer{};
        for (auto &Retry : Outcome->Retries)
        {
            Retry = co_await Transport.ReadHandshakeChunk(Buffer);
        }
        const auto Closed = Raw->Close();
        Outcome->CloseSucceeded = static_cast<bool>(Closed);
        const auto Drained = co_await Raw->Activity()->Drain();
        Outcome->DrainSucceeded = static_cast<bool>(Drained);
    }

    auto RunCoroutine(Net::io_context &Io, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(
            Io, std::move(Operation),
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    [[nodiscard]] auto ResetFailure() -> Fault::Failure
    {
        return Fault::FromNative(std::make_error_code(std::errc::connection_reset));
    }

    [[nodiscard]] auto EofFailure() -> Fault::Failure
    {
        return {Fault::Code::Eof};
    }

    [[nodiscard]] auto RunClient(
        std::vector<std::byte> Input,
        Fault::Failure Terminal) -> UpgradeOutcome
    {
        Net::io_context Io;
        UpgradeOutcome Outcome;
        auto Raw = std::make_shared<ScriptedUpgradeTransmission>(
            Io.get_executor(), std::move(Input), std::move(Terminal));
        RunCoroutine(Io, RunClientSuccess(Raw, &Outcome));
        Outcome.RawReadCalls = Raw->ReadCalls();
        Outcome.RawCloseCalls = Raw->CloseCalls();
        return Outcome;
    }

    [[nodiscard]] auto RunServer(
        std::vector<std::byte> Input,
        Fault::Failure Terminal) -> UpgradeOutcome
    {
        Net::io_context Io;
        UpgradeOutcome Outcome;
        auto Raw = std::make_shared<ScriptedUpgradeTransmission>(
            Io.get_executor(), std::move(Input), std::move(Terminal));
        RunCoroutine(Io, RunServerSuccess(Raw, &Outcome));
        Outcome.RawReadCalls = Raw->ReadCalls();
        Outcome.RawCloseCalls = Raw->CloseCalls();
        return Outcome;
    }

    [[nodiscard]] auto RunPartialClient(Fault::Failure Terminal) -> PartialOutcome
    {
        Net::io_context Io;
        PartialOutcome Outcome;
        auto Raw = std::make_shared<ScriptedUpgradeTransmission>(
            Io.get_executor(), MakeClientPartialInput(), std::move(Terminal));
        RunCoroutine(Io, RunPartialClientHandshake(Raw, &Outcome));
        Outcome.RawReadCalls = Raw->ReadCalls();
        Outcome.RawCloseCalls = Raw->CloseCalls();
        return Outcome;
    }

    [[nodiscard]] auto RunPartialServer(Fault::Failure Terminal) -> PartialOutcome
    {
        Net::io_context Io;
        PartialOutcome Outcome;
        auto Raw = std::make_shared<ScriptedUpgradeTransmission>(
            Io.get_executor(), MakeServerPartialInput(), std::move(Terminal));
        RunCoroutine(Io, RunPartialServerHandshake(Raw, &Outcome));
        Outcome.RawReadCalls = Raw->ReadCalls();
        Outcome.RawCloseCalls = Raw->CloseCalls();
        return Outcome;
    }

    auto ExpectFailure(
        const Fault::Failure &Actual,
        const Fault::Failure &Expected) -> void
    {
        EXPECT_EQ(Actual.Code, Expected.Code);
        EXPECT_EQ(Actual.Native, Expected.Native);
    }

    auto ExpectSuccessfulFrameThenTerminal(
        const UpgradeOutcome &Outcome,
        const std::string_view Payload,
        const Fault::Failure &Terminal) -> void
    {
        ASSERT_TRUE(Outcome.HandshakeSucceeded);
        EXPECT_EQ(Outcome.Reads[0].Data, Payload);
        EXPECT_EQ(Outcome.Reads[0].Bytes, Payload.size());
        EXPECT_TRUE(Outcome.Reads[0].Failure.Succeeded());
        for (std::size_t Index = 1; Index < Outcome.Reads.size(); ++Index)
        {
            EXPECT_EQ(Outcome.Reads[Index].Bytes, 0U);
            ExpectFailure(Outcome.Reads[Index].Failure, Terminal);
        }
        EXPECT_EQ(Outcome.RawReadCalls, 1U);
        EXPECT_EQ(Outcome.RawCloseCalls, 1U);
        EXPECT_TRUE(Outcome.CloseSucceeded);
        EXPECT_TRUE(Outcome.DrainSucceeded);
    }

    auto ExpectHandshakeTerminal(
        const UpgradeOutcome &Outcome,
        const Fault::Failure &Terminal) -> void
    {
        ASSERT_TRUE(Outcome.HandshakeSucceeded);
        for (const auto &Read : Outcome.Reads)
        {
            EXPECT_EQ(Read.Bytes, 0U);
            ExpectFailure(Read.Failure, Terminal);
        }
        EXPECT_EQ(Outcome.RawReadCalls, 1U);
        EXPECT_EQ(Outcome.RawCloseCalls, 1U);
        EXPECT_TRUE(Outcome.CloseSucceeded);
        EXPECT_TRUE(Outcome.DrainSucceeded);
    }

    auto ExpectPartialSticky(
        const PartialOutcome &Outcome,
        const Fault::Failure &Terminal) -> void
    {
        EXPECT_FALSE(Outcome.HandshakeSucceeded);
        ExpectFailure(Outcome.HandshakeFailure, Terminal);
        for (const auto &Retry : Outcome.Retries)
        {
            EXPECT_EQ(Retry.Bytes, 0U);
            ExpectFailure(Retry.Failure, Terminal);
        }
        EXPECT_EQ(Outcome.RawReadCalls, 1U);
        EXPECT_EQ(Outcome.RawCloseCalls, 1U);
        EXPECT_TRUE(Outcome.CloseSucceeded);
        EXPECT_TRUE(Outcome.DrainSucceeded);
    }

    TEST(WsConnHandshakeTerminal, ClientCompleteHeaderTailFramePrecedesEof)
    {
        ExpectSuccessfulFrameThenTerminal(
            RunClient(MakeClientInput(true), EofFailure()), "server-tail", EofFailure());
    }

    TEST(WsConnHandshakeTerminal, ClientCompleteHeaderTailFramePrecedesNativeReset)
    {
        const auto Reset = ResetFailure();
        ExpectSuccessfulFrameThenTerminal(
            RunClient(MakeClientInput(true), Reset), "server-tail", Reset);
    }

    TEST(WsConnHandshakeTerminal, ServerCompleteHeaderTailFramePrecedesEof)
    {
        ExpectSuccessfulFrameThenTerminal(
            RunServer(MakeServerInput(true), EofFailure()), "client-tail", EofFailure());
    }

    TEST(WsConnHandshakeTerminal, ServerCompleteHeaderTailFramePrecedesNativeReset)
    {
        const auto Reset = ResetFailure();
        ExpectSuccessfulFrameThenTerminal(
            RunServer(MakeServerInput(true), Reset), "client-tail", Reset);
    }

    TEST(WsConnHandshakeTerminal, ClientCompleteHeaderWithoutTailKeepsEofSticky)
    {
        ExpectHandshakeTerminal(RunClient(MakeClientInput(false), EofFailure()), EofFailure());
    }

    TEST(WsConnHandshakeTerminal, ServerCompleteHeaderWithoutTailKeepsEofSticky)
    {
        ExpectHandshakeTerminal(RunServer(MakeServerInput(false), EofFailure()), EofFailure());
    }

    TEST(WsConnHandshakeTerminal, ClientPartialHeaderEofIsSticky)
    {
        ExpectPartialSticky(RunPartialClient(EofFailure()), EofFailure());
    }

    TEST(WsConnHandshakeTerminal, ClientPartialHeaderNativeResetIsSticky)
    {
        const auto Reset = ResetFailure();
        ExpectPartialSticky(RunPartialClient(Reset), Reset);
    }

    TEST(WsConnHandshakeTerminal, ServerPartialHeaderEofIsSticky)
    {
        ExpectPartialSticky(RunPartialServer(EofFailure()), EofFailure());
    }

    TEST(WsConnHandshakeTerminal, ServerPartialHeaderNativeResetIsSticky)
    {
        const auto Reset = ResetFailure();
        ExpectPartialSticky(RunPartialServer(Reset), Reset);
    }
} // namespace
