/**
 * @file ReadCompletionTest.cpp
 * @brief Mux reads consume completed bytes before handling a same-completion terminal.
 */
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Net/Relay/Relay.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Mux/Detail/SingMux/SingMux.hpp>
#include <Prism/Protocols/Mux/H2Mux/Server.hpp>
#include <Prism/Protocols/Mux/Session.hpp>
#include <Prism/Protocols/Mux/SessionOptions.hpp>
#include <Prism/Protocols/Mux/SingMux/Stream.hpp>
#include <Prism/Protocols/Mux/Smux/Wire/Codec.hpp>
#include <Prism/Protocols/Mux/Smux/Smux.hpp>
#include <Prism/Protocols/Mux/Stream.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>

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
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Mux = Prism::Mux;
    namespace Smux = Prism::Mux::Smux;
    namespace SmuxWire = Prism::Mux::Smux::Detail;

    /** @brief 返回指定终止位置处交付数据与终态的脚本传输。 */
    class TerminalReadTransmission final : public Prism::Transmission
    {
    public:
        TerminalReadTransmission(
            Net::any_io_executor Executor,
            std::vector<std::uint8_t> Input,
            Prism::Fault::Failure Terminal)
            : Prism::Transmission(std::move(Executor)), Input_(std::move(Input)),
              Terminal_(Terminal), TerminalOffset_(Input_.size())
        {
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

        [[nodiscard]] auto Writes() const -> const std::vector<std::vector<std::byte>> &
        {
            return Writes_;
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCalls_;
            const auto Remaining = Input_.size() - ReadOffset_;
            const auto Count = (std::min)(Buffer.size(), Remaining);
            if (Count != 0U)
            {
                std::memcpy(Buffer.data(), Input_.data() + ReadOffset_, Count);
                ReadOffset_ += Count;
            }
            auto Failure = Prism::Fault::Failure{};
            if (ReadOffset_ == TerminalOffset_)
            {
                if (!TerminalReported_)
                {
                    Failure = Terminal_;
                    TerminalReported_ = true;
                }
            }
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Count, Failure});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Writes_.emplace_back(Buffer.begin(), Buffer.end());
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {0U, {}});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_ = true;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        std::vector<std::uint8_t> Input_;
        std::vector<std::vector<std::byte>> Writes_;
        Prism::Fault::Failure Terminal_;
        std::size_t TerminalOffset_{0U};
        std::size_t ReadOffset_{0U};
        std::size_t ReadCalls_{0U};
        bool TerminalReported_{false};
        bool Closed_{false};
    };

    struct H2ReadOutcome final
    {
        bool InputReady{false};
        bool RunSucceeded{false};
        bool Retired{false};
        Prism::Fault::Failure RunFailure;
        std::size_t ReadCalls{0U};
        std::vector<std::vector<std::byte>> Writes;
    };

    struct H2ReadScenario final
    {
        Prism::Fault::Failure Terminal{Prism::Fault::Code::Eof};
        bool PartialInput{false};
    };

    auto RunH2SettingsRead(
        Net::any_io_executor Executor,
        H2ReadScenario Scenario)
        -> Net::awaitable<H2ReadOutcome>
    {
        auto Client = std::make_shared<Prism::Http2::Session>(Executor, false);
        Client->SendSettings();
        std::vector<std::byte> Wire;
        H2ReadOutcome Outcome;
        if (!Client->Collect(Wire))
        {
            co_return Outcome;
        }
        Outcome.InputReady = true;
        if (Scenario.PartialInput && !Wire.empty())
        {
            Wire.pop_back();
        }
        std::vector<std::uint8_t> Input;
        Input.reserve(Wire.size());
        for (const auto Byte : Wire)
        {
            Input.push_back(std::to_integer<std::uint8_t>(Byte));
        }
        auto Raw = std::make_shared<TerminalReadTransmission>(
            Executor, std::move(Input), Scenario.Terminal);
        auto Server = std::make_shared<Prism::Mux::H2Mux::Http2Server>(Raw, 4U);
        const auto Run = co_await Server->Run();
        Outcome.RunSucceeded = Run.has_value();
        if (!Run)
        {
            Outcome.RunFailure = Run.error();
        }
        Outcome.Retired = Server->IsRetired();
        Outcome.ReadCalls = Raw->ReadCalls();
        Outcome.Writes = Raw->Writes();
        co_return Outcome;
    }

    struct SessionReadOutcome final
    {
        bool StreamAccepted{false};
        std::size_t PayloadBytes{0U};
        std::string Payload;
        std::size_t EofBytes{999U};
        bool PeerEof{false};
        bool HasPeerFailure{false};
    };

    struct SessionResetOutcome final
    {
        bool FirstStreamAccepted{false};
        bool SecondStreamAccepted{false};
        Prism::IoResult FirstStreamRead;
        Prism::IoResult FirstStreamTerminal;
        Prism::IoResult SecondStreamTerminal;
        std::string Payload;
        std::size_t ReadCalls{0U};
    };

    struct SessionRequestOutcome final
    {
        bool HasRequest{false};
        Prism::Mux::Mode Wire{Prism::Mux::Mode::Auto};
        Prism::Fault::Failure Failure;
        std::optional<Prism::Fault::Failure> Terminal;
        std::size_t ReadCalls{0U};
    };

    struct StreamRequestOutcome final
    {
        bool HasRequest{false};
        Prism::Network::Target Target;
        Prism::Fault::Failure Failure;
        std::optional<Prism::Fault::Failure> Terminal;
        std::size_t ReadCalls{0U};
    };

    struct StreamEmptyReadOutcome final
    {
        bool HasRequest{false};
        Prism::IoResult EmptyRead;
        Prism::IoResult TerminalRead;
        std::size_t ReadCallsAfterEmpty{0U};
        std::size_t ReadCallsAfterTerminal{0U};
    };

    struct StreamRelayOutcome final
    {
        Prism::Network::Relay::Result Relay;
        std::vector<std::byte> UpstreamRequest;
        std::vector<std::vector<std::byte>> ChildWrites;
        std::size_t RequestReadCalls{0U};
    };

    auto RunSessionPayloadRead(Net::any_io_executor Executor)
        -> Net::awaitable<SessionReadOutcome>
    {
        const std::string Payload{"complete-frame"};
        const auto Open = SmuxWire::BuildSyn(1U);
        const auto Data = SmuxWire::BuildPush(1U, Prism::AsU8Span(Payload));
        std::vector<std::uint8_t> Input(Open.begin(), Open.end());
        Input.insert(Input.end(), Data.begin(), Data.end());
        auto Raw = std::make_shared<TerminalReadTransmission>(
            Executor, std::move(Input), Prism::Fault::Failure{Prism::Fault::Code::Eof});
        Prism::Mux::SessionOptions Options;
        Options.Role = Prism::Mux::Role::Server;
        auto Session = Mux::Session<SmuxWire::Codec>::Create(Raw, Options);
        SessionReadOutcome Outcome;
        if (!Session)
        {
            co_return Outcome;
        }
        const auto Stream = co_await Session->AcceptStream();
        if (Stream)
        {
            Outcome.StreamAccepted = true;
            std::array<std::uint8_t, 32> Buffer{};
            Outcome.PayloadBytes = co_await Stream->ReadSome(Buffer);
            Outcome.Payload.assign(
                reinterpret_cast<const char *>(Buffer.data()), Outcome.PayloadBytes);
            Outcome.EofBytes = co_await Stream->ReadSome(Buffer);
            Outcome.PeerEof = Stream->IsPeerEof();
            Outcome.HasPeerFailure = Stream->PeerFailure().has_value();
        }
        co_await Session->Close();
        co_return Outcome;
    }

    auto RunSessionResetRead(
        Net::any_io_executor Executor,
        const bool PartialFrame) -> Net::awaitable<SessionResetOutcome>
    {
        const std::string Payload{"native-reset"};
        const auto Open = SmuxWire::BuildSyn(1U);
        const auto SecondOpen = SmuxWire::BuildSyn(3U);
        const auto Data = SmuxWire::BuildPush(1U, Prism::AsU8Span(Payload));
        std::vector<std::uint8_t> Input(Open.begin(), Open.end());
        Input.insert(Input.end(), SecondOpen.begin(), SecondOpen.end());
        const auto DataEnd = PartialFrame ? Data.end() - 1 : Data.end();
        Input.insert(Input.end(), Data.begin(), DataEnd);
        const auto Native = std::make_error_code(std::errc::connection_reset);
        auto Raw = std::make_shared<TerminalReadTransmission>(
            Executor, std::move(Input), Prism::Fault::FromNative(Native));
        Prism::Mux::SessionOptions Options;
        Options.Role = Prism::Mux::Role::Server;
        auto Session = Mux::Session<SmuxWire::Codec>::Create(Raw, Options);
        SessionResetOutcome Outcome;
        if (!Session)
        {
            co_return Outcome;
        }
        const auto FirstHandle = co_await Session->AcceptStream();
        const auto SecondHandle = co_await Session->AcceptStream();
        if (FirstHandle)
        {
            Outcome.FirstStreamAccepted = true;
        }
        if (SecondHandle)
        {
            Outcome.SecondStreamAccepted = true;
        }
        if (FirstHandle && SecondHandle)
        {
            auto FirstStream = std::make_shared<Prism::Mux::StreamTransmission>(FirstHandle);
            auto SecondStream = std::make_shared<Prism::Mux::StreamTransmission>(SecondHandle);
            std::array<std::byte, 32> Buffer{};
            Outcome.FirstStreamRead = co_await FirstStream->ReadSome(Buffer);
            Outcome.Payload.assign(
                reinterpret_cast<const char *>(Buffer.data()), Outcome.FirstStreamRead.Bytes);
            if (!PartialFrame)
            {
                Outcome.FirstStreamTerminal = co_await FirstStream->ReadSome(Buffer);
            }
            else
            {
                Outcome.FirstStreamTerminal = Outcome.FirstStreamRead;
            }
            Outcome.SecondStreamTerminal = co_await SecondStream->ReadSome(Buffer);
        }
        Outcome.ReadCalls = Raw->ReadCalls();
        co_await Session->Close();
        co_return Outcome;
    }

    auto RunSessionRequestRead(
        Net::any_io_executor Executor,
        std::vector<std::uint8_t> Input,
        Prism::Fault::Failure Terminal)
        -> Net::awaitable<SessionRequestOutcome>
    {
        auto Raw = std::make_shared<TerminalReadTransmission>(
            Executor, std::move(Input), Terminal);
        const auto Result = co_await Prism::Mux::Detail::SingMux::ReadSessionRequest(Raw);
        SessionRequestOutcome Outcome;
        Outcome.ReadCalls = Raw->ReadCalls();
        if (Result)
        {
            Outcome.HasRequest = true;
            Outcome.Wire = Result->Request.Wire;
            Outcome.Terminal = Result->Terminal;
        }
        else
        {
            Outcome.Failure = Result.error();
        }
        co_return Outcome;
    }

    auto RunStreamRequestRead(
        Net::any_io_executor Executor,
        std::vector<std::uint8_t> Input,
        Prism::Fault::Failure Terminal)
        -> Net::awaitable<StreamRequestOutcome>
    {
        auto Raw = std::make_shared<TerminalReadTransmission>(
            Executor, std::move(Input), Terminal);
        const auto Result = co_await Prism::Mux::Detail::SingMux::ReadStreamRequest(Raw);
        StreamRequestOutcome Outcome;
        Outcome.ReadCalls = Raw->ReadCalls();
        if (Result)
        {
            Outcome.HasRequest = true;
            Outcome.Target = Result->Request.Target;
            Outcome.Terminal = Result->Terminal;
        }
        else
        {
            Outcome.Failure = Result.error();
        }
        co_return Outcome;
    }

    auto RunStreamEmptyRead(Net::any_io_executor Executor)
        -> Net::awaitable<StreamEmptyReadOutcome>
    {
        const std::vector<std::uint8_t> RequestWire{
            0x00U, 0x00U, 0x01U, 127U, 0U, 0U, 1U, 0x1FU, 0x90U};
        auto Raw = std::make_shared<TerminalReadTransmission>(
            Executor, RequestWire, Prism::Fault::Failure{Prism::Fault::Code::Eof});
        const auto Request = co_await Prism::Mux::Detail::SingMux::ReadStreamRequest(Raw);
        StreamEmptyReadOutcome Outcome;
        if (!Request) co_return Outcome;
        Outcome.HasRequest = true;
        auto Stream = std::make_shared<Prism::Mux::SingMux::ServerStream>(
            Raw, Request->Request.Target, Request->Terminal);
        Outcome.EmptyRead = co_await Stream->ReadSome(std::span<std::byte>{});
        Outcome.ReadCallsAfterEmpty = Raw->ReadCalls();
        std::array<std::byte, 1> Buffer{};
        Outcome.TerminalRead = co_await Stream->ReadSome(Buffer);
        Outcome.ReadCallsAfterTerminal = Raw->ReadCalls();
        co_return Outcome;
    }

    auto ReadUntilEof(const Prism::SharedTransmission &Carrier)
        -> Net::awaitable<std::vector<std::byte>>
    {
        std::vector<std::byte> Payload;
        std::array<std::byte, 32> Buffer{};
        while (true)
        {
            const auto Part = co_await Carrier->ReadSome(Buffer);
            if (Part.Bytes > Buffer.size())
            {
                throw std::runtime_error("Mux relay peer returned oversized input");
            }
            Payload.insert(Payload.end(), Buffer.begin(),
                Buffer.begin() + static_cast<std::ptrdiff_t>(Part.Bytes));
            if (Part.Failure.Code == Prism::Fault::Code::Eof)
            {
                co_return Payload;
            }
            if (Part.Failure.Failed() || Part.Bytes == 0U)
            {
                throw std::runtime_error("Mux relay peer ended before EOF");
            }
        }
    }

    auto RunStreamRelayPeer(const Prism::SharedTransmission &Upstream)
        -> Net::awaitable<std::vector<std::byte>>
    {
        auto Request = co_await ReadUntilEof(Upstream);
        const std::array<std::byte, 5> Response{
            std::byte{0x72}, std::byte{0x65}, std::byte{0x70},
            std::byte{0x6C}, std::byte{0x79}};
        const auto Write = co_await Upstream->WriteExact(Response);
        if (Write.Failure.Failed() || Write.Bytes != Response.size())
        {
            throw std::runtime_error("Mux relay response write failed");
        }
        const auto Shutdown = co_await Upstream->WriteShutdown();
        if (!Shutdown)
        {
            throw std::runtime_error("Mux relay response half-close failed");
        }
        co_return Request;
    }

    auto RunStreamRelayHalfClose(Net::any_io_executor Executor)
        -> Net::awaitable<StreamRelayOutcome>
    {
        const std::vector<std::uint8_t> RequestWire{
            0x00U, 0x00U, 0x01U, 127U, 0U, 0U, 1U, 0x1FU, 0x90U};
        auto RequestRaw = std::make_shared<TerminalReadTransmission>(
            Executor, RequestWire, Prism::Fault::Failure{Prism::Fault::Code::Eof});
        const auto RequestRead = co_await Prism::Mux::Detail::SingMux::ReadStreamRequest(RequestRaw);
        if (!RequestRead || !RequestRead->Terminal ||
            RequestRead->Terminal->Code != Prism::Fault::Code::Eof)
        {
            co_return StreamRelayOutcome{};
        }

        auto [OutboundValue, UpstreamValue] = Prism::MakeMemoryPair(Executor);
        Prism::SharedTransmission Outbound =
            std::make_shared<Prism::MemoryStream>(std::move(OutboundValue));
        Prism::SharedTransmission Upstream =
            std::make_shared<Prism::MemoryStream>(std::move(UpstreamValue));
        auto Inbound = std::make_shared<Prism::Mux::SingMux::ServerStream>(
            RequestRaw, RequestRead->Request.Target, RequestRead->Terminal);
        auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{4096U, 2U});
        const Prism::Network::Relay::Request RelayRequest{
            .Inbound = Inbound,
            .Outbound = Outbound,
            .BufferSize = 4096U,
            .Bytes = std::move(Bytes)};
        using Net::experimental::awaitable_operators::operator&&;
        auto [Relay, UpstreamRequest] = co_await (
            Prism::Network::Relay::Run(RelayRequest) &&
            RunStreamRelayPeer(Upstream));
        co_return StreamRelayOutcome{
            std::move(Relay), std::move(UpstreamRequest), RequestRaw->Writes(),
            RequestRaw->ReadCalls()};
    }

    auto RunStreamFailureRead(Net::any_io_executor Executor)
        -> Net::awaitable<std::pair<Prism::Fault::Failure, std::size_t>>
    {
        const std::vector<std::uint8_t> RequestWire{
            0x00U, 0x00U, 0x01U, 127U, 0U, 0U, 1U, 0x1FU, 0x90U};
        const auto Native = std::make_error_code(std::errc::connection_reset);
        auto Raw = std::make_shared<TerminalReadTransmission>(
            Executor, RequestWire, Prism::Fault::FromNative(Native));
        const auto Request = co_await Prism::Mux::Detail::SingMux::ReadStreamRequest(Raw);
        if (!Request)
        {
            co_return std::pair{Request.error(), Raw->ReadCalls()};
        }
        auto Stream = std::make_shared<Prism::Mux::SingMux::ServerStream>(
            Raw, Request->Request.Target, Request->Terminal);
        std::array<std::byte, 16> Buffer{};
        const auto Part = co_await Stream->ReadSome(Buffer);
        co_return std::pair{Part.Failure, Raw->ReadCalls()};
    }

    template <class Result>
    auto RunCoro(Net::io_context &Io, Net::awaitable<Result> Operation) -> Result
    {
        std::optional<Result> Value;
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Operation),
            [&Value, &Failure](std::exception_ptr Error, Result Output)
            {
                Failure = std::move(Error);
                if (!Failure)
                {
                    Value.emplace(std::move(Output));
                }
            });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
        if (!Value)
        {
            throw std::runtime_error("Mux read completion scenario did not finish");
        }
        return std::move(*Value);
    }

    template <class Result>
    auto RunCoroWithDeadline(Net::io_context &Io, Net::awaitable<Result> Operation)
        -> Result
    {
        std::optional<Result> Value;
        std::exception_ptr Failure;
        bool TimedOut = false;
        Net::steady_timer Deadline(Io);
        Deadline.expires_after(std::chrono::seconds{2});
        Deadline.async_wait([&](const boost::system::error_code &Error)
        {
            if (!Error)
            {
                TimedOut = true;
                Io.stop();
            }
        });
        Net::co_spawn(Io, std::move(Operation),
            [&Value, &Failure, &Deadline](std::exception_ptr Error, Result Output)
            {
                Failure = std::move(Error);
                if (!Failure) Value.emplace(std::move(Output));
                (void)Deadline.cancel();
            });
        Io.run();
        if (TimedOut) throw std::runtime_error("Mux relay half-close timed out");
        if (Failure) std::rethrow_exception(Failure);
        if (!Value) throw std::runtime_error("Mux relay half-close did not finish");
        return std::move(*Value);
    }

    auto IsSettingsAck(const std::vector<std::byte> &Wire) -> bool
    {
        return Wire.size() == 9U &&
            Wire[0] == std::byte{0U} && Wire[1] == std::byte{0U} &&
            Wire[2] == std::byte{0U} && Wire[3] == std::byte{0x04} &&
            Wire[4] == std::byte{0x01} && Wire[5] == std::byte{0U} &&
            Wire[6] == std::byte{0U} && Wire[7] == std::byte{0U} &&
            Wire[8] == std::byte{0U};
    }

    TEST(MuxReadCompletion, H2ServerFeedsBytesBeforeEof)
    {
        Net::io_context Io;
        const auto Outcome = RunCoro(Io, RunH2SettingsRead(Io.get_executor(), {}));
        ASSERT_TRUE(Outcome.InputReady);
        EXPECT_TRUE(Outcome.RunSucceeded);
        EXPECT_TRUE(Outcome.Retired);
        EXPECT_EQ(Outcome.ReadCalls, 1U);
        ASSERT_EQ(Outcome.Writes.size(), 2U);
        EXPECT_TRUE(IsSettingsAck(Outcome.Writes.back()));
    }

    TEST(MuxReadCompletion, H2ServerFeedsCompleteSettingsBeforeNativeReset)
    {
        Net::io_context Io;
        const auto Native = std::make_error_code(std::errc::connection_reset);
        const auto Outcome = RunCoro(Io, RunH2SettingsRead(Io.get_executor(),
            H2ReadScenario{.Terminal = Prism::Fault::FromNative(Native)}));
        ASSERT_TRUE(Outcome.InputReady);
        EXPECT_FALSE(Outcome.RunSucceeded);
        EXPECT_EQ(Outcome.RunFailure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.RunFailure.Native, Native);
        EXPECT_TRUE(Outcome.Retired);
        EXPECT_EQ(Outcome.ReadCalls, 1U);
        ASSERT_EQ(Outcome.Writes.size(), 2U);
        EXPECT_TRUE(IsSettingsAck(Outcome.Writes.back()));
    }

    TEST(MuxReadCompletion, H2ServerFeedsPartialSettingsBeforeNativeReset)
    {
        Net::io_context Io;
        const auto Native = std::make_error_code(std::errc::connection_reset);
        const auto Outcome = RunCoro(Io, RunH2SettingsRead(Io.get_executor(),
            H2ReadScenario{.Terminal = Prism::Fault::FromNative(Native), .PartialInput = true}));
        ASSERT_TRUE(Outcome.InputReady);
        EXPECT_FALSE(Outcome.RunSucceeded);
        EXPECT_EQ(Outcome.RunFailure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.RunFailure.Native, Native);
        EXPECT_TRUE(Outcome.Retired);
        EXPECT_EQ(Outcome.ReadCalls, 1U);
        ASSERT_EQ(Outcome.Writes.size(), 1U);
        EXPECT_FALSE(IsSettingsAck(Outcome.Writes.back()));
    }

    TEST(MuxReadCompletion, SessionDispatchesPayloadBeforeEof)
    {
        Net::io_context Io;
        const auto Outcome = RunCoro(Io, RunSessionPayloadRead(Io.get_executor()));
        ASSERT_TRUE(Outcome.StreamAccepted);
        EXPECT_EQ(Outcome.PayloadBytes, std::string_view{"complete-frame"}.size());
        EXPECT_EQ(Outcome.Payload, "complete-frame");
        EXPECT_EQ(Outcome.EofBytes, 0U);
        EXPECT_TRUE(Outcome.PeerEof);
        EXPECT_FALSE(Outcome.HasPeerFailure);
    }

    TEST(MuxReadCompletion, SessionDispatchesCompleteFrameBeforeNativeReset)
    {
        Net::io_context Io;
        const auto Outcome = RunCoro(Io, RunSessionResetRead(Io.get_executor(), false));
        ASSERT_TRUE(Outcome.FirstStreamAccepted);
        ASSERT_TRUE(Outcome.SecondStreamAccepted);
        ASSERT_EQ(Outcome.FirstStreamRead.Bytes, std::string_view{"native-reset"}.size());
        EXPECT_FALSE(Outcome.FirstStreamRead.Failure.Failed());
        EXPECT_EQ(Outcome.Payload, "native-reset");
        EXPECT_EQ(Outcome.FirstStreamTerminal.Bytes, 0U);
        EXPECT_EQ(Outcome.FirstStreamTerminal.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.FirstStreamTerminal.Failure.Native,
            std::make_error_code(std::errc::connection_reset));
        EXPECT_EQ(Outcome.SecondStreamTerminal.Bytes, 0U);
        EXPECT_EQ(Outcome.SecondStreamTerminal.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.SecondStreamTerminal.Failure.Native,
            std::make_error_code(std::errc::connection_reset));
        EXPECT_EQ(Outcome.ReadCalls, 4U);
    }

    TEST(MuxReadCompletion, PartialFrameBroadcastsNativeResetWithoutReread)
    {
        Net::io_context Io;
        const auto Outcome = RunCoro(Io, RunSessionResetRead(Io.get_executor(), true));
        ASSERT_TRUE(Outcome.FirstStreamAccepted);
        ASSERT_TRUE(Outcome.SecondStreamAccepted);
        EXPECT_TRUE(Outcome.Payload.empty());
        EXPECT_EQ(Outcome.FirstStreamRead.Bytes, 0U);
        EXPECT_EQ(Outcome.FirstStreamRead.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.FirstStreamRead.Failure.Native,
            std::make_error_code(std::errc::connection_reset));
        EXPECT_EQ(Outcome.SecondStreamTerminal.Bytes, 0U);
        EXPECT_EQ(Outcome.SecondStreamTerminal.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.SecondStreamTerminal.Failure.Native,
            std::make_error_code(std::errc::connection_reset));
        EXPECT_EQ(Outcome.ReadCalls, 4U);
    }

    TEST(MuxReadCompletion, SessionRequestCarriesCompleteBootstrapEof)
    {
        Net::io_context Io;
        const auto Outcome = RunCoro(Io, RunSessionRequestRead(
            Io.get_executor(), {0U, 0U},
            Prism::Fault::Failure{Prism::Fault::Code::Eof}));
        ASSERT_TRUE(Outcome.HasRequest);
        EXPECT_EQ(Outcome.Wire, Prism::Mux::Mode::Smux);
        ASSERT_TRUE(Outcome.Terminal.has_value());
        EXPECT_EQ(Outcome.Terminal->Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(Outcome.ReadCalls, 1U);
    }

    TEST(MuxReadCompletion, SessionRequestCarriesCompleteBootstrapNativeFailure)
    {
        Net::io_context Io;
        const auto Native = std::make_error_code(std::errc::connection_reset);
        const auto Outcome = RunCoro(Io, RunSessionRequestRead(
            Io.get_executor(), {0U, 1U}, Prism::Fault::FromNative(Native)));
        ASSERT_TRUE(Outcome.HasRequest);
        EXPECT_EQ(Outcome.Wire, Prism::Mux::Mode::Yamux);
        ASSERT_TRUE(Outcome.Terminal.has_value());
        EXPECT_EQ(Outcome.Terminal->Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.Terminal->Native, Native);
        EXPECT_EQ(Outcome.ReadCalls, 1U);
    }

    TEST(MuxReadCompletion, PartialSessionFieldReturnsTerminalWithoutReread)
    {
        Net::io_context Io;
        const auto IncompleteRequest = RunCoro(Io, RunSessionRequestRead(
            Io.get_executor(), {1U, 0U}, Prism::Fault::Failure{Prism::Fault::Code::Eof}));
        EXPECT_FALSE(IncompleteRequest.HasRequest);
        EXPECT_EQ(IncompleteRequest.Failure.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(IncompleteRequest.ReadCalls, 1U);

        Io.restart();
        const auto PartialField = RunCoro(Io, RunSessionRequestRead(
            Io.get_executor(), {0U}, Prism::Fault::Failure{Prism::Fault::Code::Eof}));
        EXPECT_FALSE(PartialField.HasRequest);
        EXPECT_EQ(PartialField.Failure.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(PartialField.ReadCalls, 1U);
    }

    TEST(MuxReadCompletion, StreamRequestEofHalfClosesRelayAndKeepsResponse)
    {
        Net::io_context Io;
        const auto Outcome = RunCoroWithDeadline(
            Io, RunStreamRelayHalfClose(Io.get_executor()));
        EXPECT_TRUE(Outcome.Relay.Failure.Succeeded());
        EXPECT_TRUE(Outcome.UpstreamRequest.empty());
        ASSERT_EQ(Outcome.ChildWrites.size(), 2U);
        ASSERT_EQ(Outcome.ChildWrites[0].size(), 1U);
        EXPECT_EQ(Outcome.ChildWrites[0][0], std::byte{0x00});
        const std::array<std::byte, 5> Expected{
            std::byte{0x72}, std::byte{0x65}, std::byte{0x70},
            std::byte{0x6C}, std::byte{0x79}};
        ASSERT_EQ(Outcome.ChildWrites[1].size(), Expected.size());
        EXPECT_TRUE(std::equal(Expected.begin(), Expected.end(), Outcome.ChildWrites[1].begin()));
        EXPECT_EQ(Outcome.RequestReadCalls, 3U);
    }

    TEST(MuxReadCompletion, StreamRequestNativeFailureIsDeliveredOnce)
    {
        Net::io_context Io;
        const auto [Failure, ReadCalls] = RunCoro(
            Io, RunStreamFailureRead(Io.get_executor()));
        EXPECT_EQ(Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Failure.Native, std::make_error_code(std::errc::connection_reset));
        EXPECT_EQ(ReadCalls, 3U);
    }

    TEST(MuxReadCompletion, EmptyServerStreamReadPreservesPendingTerminal)
    {
        Net::io_context Io;
        const auto Outcome = RunCoro(Io, RunStreamEmptyRead(Io.get_executor()));
        ASSERT_TRUE(Outcome.HasRequest);
        EXPECT_EQ(Outcome.EmptyRead.Bytes, 0U);
        EXPECT_FALSE(Outcome.EmptyRead.Failure.Failed());
        EXPECT_EQ(Outcome.ReadCallsAfterEmpty, 3U);
        EXPECT_EQ(Outcome.TerminalRead.Bytes, 0U);
        EXPECT_EQ(Outcome.TerminalRead.Failure.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(Outcome.ReadCallsAfterTerminal, 3U);
    }

    TEST(MuxReadCompletion, PartialStreamRequestReturnsTerminalWithoutReread)
    {
        Net::io_context Io;
        const auto MissingAddress = RunCoro(Io, RunStreamRequestRead(
            Io.get_executor(), {0U, 0U, 1U},
            Prism::Fault::Failure{Prism::Fault::Code::Eof}));
        EXPECT_FALSE(MissingAddress.HasRequest);
        EXPECT_EQ(MissingAddress.Failure.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(MissingAddress.ReadCalls, 1U);

        Io.restart();
        const auto PartialPrefix = RunCoro(Io, RunStreamRequestRead(
            Io.get_executor(), {0U, 0U},
            Prism::Fault::Failure{Prism::Fault::Code::Eof}));
        EXPECT_FALSE(PartialPrefix.HasRequest);
        EXPECT_EQ(PartialPrefix.Failure.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(PartialPrefix.ReadCalls, 1U);
    }
} // namespace
