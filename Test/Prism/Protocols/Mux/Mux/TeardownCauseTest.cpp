/**
 * @file TeardownCauseTest.cpp
 * @brief Mux 会话 teardown 将非 EOF 首因交付给已接收 child。
 */
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Mux/Session.hpp>
#include <Prism/Protocols/Mux/SessionOptions.hpp>
#include <Prism/Protocols/Mux/Smux/Types.hpp>
#include <Prism/Protocols/Mux/Smux/Wire/Codec.hpp>
#include <Prism/Protocols/Mux/Stream.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace SmuxWire = Prism::Mux::Smux::Detail;
    using Session = Prism::Mux::Session<SmuxWire::Codec>;

    struct ScriptedTransmissionPlan final
    {
        std::vector<std::uint8_t> Input;
        std::size_t FailWriteCall{0U};
        std::size_t FailWriteBytes{0U};
        Prism::Fault::Failure WriteFailure;
    };

    class ScriptedMuxTransmission final : public Prism::Transmission
    {
    public:
        ScriptedMuxTransmission(
            Net::any_io_executor Executor,
            ScriptedTransmissionPlan Plan)
            : Prism::Transmission(std::move(Executor)), Input_(std::move(Plan.Input)),
              FailWriteCall_(Plan.FailWriteCall), FailWriteBytes_(Plan.FailWriteBytes),
              WriteFailure_(Plan.WriteFailure)
        {
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

        [[nodiscard]] auto WriteCalls() const noexcept -> std::size_t
        {
            return WriteCalls_;
        }

        [[nodiscard]] auto FailedWriteBytes() const noexcept -> std::size_t
        {
            return FailedWriteBytes_;
        }

        auto Feed(std::span<const std::uint8_t> Bytes) -> void
        {
            Input_.insert(Input_.end(), Bytes.begin(), Bytes.end());
            CompletePendingRead();
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCalls_;
            if (ReadOffset_ < Input_.size())
            {
                const auto Count = (std::min)(Buffer.size(), Input_.size() - ReadOffset_);
                std::memcpy(Buffer.data(), Input_.data() + ReadOffset_, Count);
                ReadOffset_ += Count;
                Prism::Transmission::PostResult(Executor(), std::move(Handler), {Count, {}});
                return;
            }
            PendingBuffer_ = Buffer;
            PendingRead_.emplace(std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            ++WriteCalls_;
            if (WriteCalls_ == FailWriteCall_)
            {
                FailedWriteBytes_ = FailWriteBytes_;
                Prism::Transmission::PostResult(
                    Executor(), std::move(Handler), {FailWriteBytes_, WriteFailure_});
                return;
            }
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
            if (PendingRead_)
            {
                auto Handler = std::move(*PendingRead_);
                PendingRead_.reset();
                PendingBuffer_ = {};
                Prism::Transmission::PostResult(
                    Executor(), std::move(Handler),
                    {0U, Prism::Fault::Failure{Prism::Fault::Code::Canceled}});
            }
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        auto CompletePendingRead() -> void
        {
            if (!PendingRead_ || ReadOffset_ >= Input_.size())
            {
                return;
            }
            const auto Count = (std::min)(PendingBuffer_.size(), Input_.size() - ReadOffset_);
            std::memcpy(PendingBuffer_.data(), Input_.data() + ReadOffset_, Count);
            ReadOffset_ += Count;
            auto Handler = std::move(*PendingRead_);
            PendingRead_.reset();
            PendingBuffer_ = {};
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {Count, {}});
        }

        std::vector<std::uint8_t> Input_;
        std::size_t FailWriteCall_{0U};
        std::size_t FailWriteBytes_{0U};
        Prism::Fault::Failure WriteFailure_;
        std::optional<Completion> PendingRead_;
        std::span<std::byte> PendingBuffer_;
        std::size_t ReadOffset_{0U};
        std::size_t ReadCalls_{0U};
        std::size_t WriteCalls_{0U};
        std::size_t FailedWriteBytes_{0U};
        bool Closed_{false};
    };

    struct TeardownOutcome final
    {
        bool Accepted{false};
        Prism::IoResult FirstRead;
        Prism::IoResult RepeatRead;
        Prism::IoResult StickyRead;
        std::vector<std::byte> Payload;
        Prism::IoResult Write;
        std::optional<Prism::Fault::Failure> PeerFailure;
        bool PeerEof{false};
        bool SessionDrained{false};
        bool StreamRetired{false};
        bool RawClosed{false};
        bool RawRetired{false};
        std::size_t FailedWriteBytes{0U};
        std::size_t ReadCalls{0U};
        std::size_t WriteCalls{0U};
    };

    struct AcceptedSession final
    {
        std::shared_ptr<Session> Owner;
        std::shared_ptr<ScriptedMuxTransmission> Raw;
        std::shared_ptr<Prism::Mux::StreamHandle<>> Handle;
        std::shared_ptr<Prism::Mux::StreamTransmission> Stream;
    };

    [[nodiscard]] auto MakeSession(
        const std::shared_ptr<ScriptedMuxTransmission> &Raw) -> std::shared_ptr<Session>
    {
        Prism::Mux::SessionOptions Options;
        Options.Role = Prism::Mux::Role::Server;
        return Session::Create(Raw, Options);
    }

    auto CaptureAndRetire(
        const AcceptedSession &Scenario,
        TeardownOutcome &Outcome) -> Net::awaitable<void>
    {
        std::array<std::byte, 32> Buffer{};
        Outcome.FirstRead = co_await Scenario.Stream->ReadSome(Buffer);
        Outcome.Payload.assign(
            Buffer.begin(), Buffer.begin() + static_cast<std::ptrdiff_t>(Outcome.FirstRead.Bytes));
        Outcome.RepeatRead = co_await Scenario.Stream->ReadSome(Buffer);
        Outcome.StickyRead = co_await Scenario.Stream->ReadSome(Buffer);
        Outcome.PeerFailure = Scenario.Handle->PeerFailure();
        Outcome.PeerEof = Scenario.Handle->IsPeerEof();
        Outcome.FailedWriteBytes = Scenario.Raw->FailedWriteBytes();
        Outcome.ReadCalls = Scenario.Raw->ReadCalls();
        Outcome.WriteCalls = Scenario.Raw->WriteCalls();
        co_await Scenario.Owner->Close();
        const auto StreamClose = Scenario.Stream->Close();
        if (StreamClose)
        {
            const auto Terminations = co_await Scenario.Stream->DrainTerminations();
            const auto StreamDrain = co_await Scenario.Stream->Activity()->Drain();
            Outcome.StreamRetired = Terminations.has_value() && StreamDrain.has_value() &&
                Scenario.Stream->Activity()->IsRetired();
        }
        Outcome.SessionDrained = (co_await Scenario.Owner->Tasks()->Drain()).has_value();
        const auto RawDrain = co_await Scenario.Raw->Activity()->Drain();
        Outcome.RawClosed = !Scenario.Raw->IsOpen();
        Outcome.RawRetired = RawDrain.has_value() && Scenario.Raw->Activity()->IsRetired();
    }

    auto RunMalformedPeerFrame(Net::any_io_executor Executor) -> Net::awaitable<TeardownOutcome>
    {
        const auto Open = SmuxWire::BuildSyn(1U);
        const std::array<std::uint8_t, 6> BufferedPayload{
            'q', 'u', 'e', 'u', 'e', 'd'};
        const auto Data = SmuxWire::BuildPush(1U, BufferedPayload);
        std::vector<std::uint8_t> Input(Open.begin(), Open.end());
        Input.insert(Input.end(), Data.begin(), Data.end());
        auto Raw = std::make_shared<ScriptedMuxTransmission>(
            Executor, ScriptedTransmissionPlan{
                .Input = std::move(Input)});
        auto Owner = MakeSession(Raw);
        TeardownOutcome Outcome;
        const auto Handle = co_await Owner->AcceptStream();
        Outcome.Accepted = static_cast<bool>(Handle);
        if (!Handle)
        {
            co_await Owner->Close();
            co_return Outcome;
        }
        const AcceptedSession Scenario{
            Owner, Raw, Handle, std::make_shared<Prism::Mux::StreamTransmission>(Handle)};
        const std::array<std::uint8_t, Prism::Mux::Smux::FrameHdrsize> Malformed{
            0x7FU, static_cast<std::uint8_t>(Prism::Mux::Smux::Command::Push),
            0U, 0U, 1U, 0U, 0U, 0U};
        co_await Net::dispatch(Raw->Executor(), Net::use_awaitable);
        Raw->Feed(Malformed);
        co_await CaptureAndRetire(Scenario, Outcome);
        co_return Outcome;
    }

    auto RunWriterReset(
        Net::any_io_executor Executor,
        const std::size_t FailureBytes) -> Net::awaitable<TeardownOutcome>
    {
        const auto Open = SmuxWire::BuildSyn(1U);
        const auto Native = std::make_error_code(std::errc::connection_reset);
        auto Raw = std::make_shared<ScriptedMuxTransmission>(
            Executor, ScriptedTransmissionPlan{
                .Input = std::vector<std::uint8_t>(Open.begin(), Open.end()),
                .FailWriteCall = 1U,
                .FailWriteBytes = FailureBytes,
                .WriteFailure = Prism::Fault::FromNative(Native)});
        auto Owner = MakeSession(Raw);
        TeardownOutcome Outcome;
        const auto Handle = co_await Owner->AcceptStream();
        Outcome.Accepted = static_cast<bool>(Handle);
        if (!Handle)
        {
            co_await Owner->Close();
            co_return Outcome;
        }
        auto Stream = std::make_shared<Prism::Mux::StreamTransmission>(Handle);
        const std::array<std::byte, 1> Payload{std::byte{0x41}};
        Outcome.Write = co_await Stream->WriteSome(Payload);
        const AcceptedSession Scenario{Owner, Raw, Handle, std::move(Stream)};
        co_await CaptureAndRetire(Scenario, Outcome);
        co_return Outcome;
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
            throw std::runtime_error("Mux teardown scenario did not finish");
        }
        return std::move(*Value);
    }

    TEST(MuxTeardownCause, MalformedFrameIsNotPeerEof)
    {
        Net::io_context Io;
        const auto Outcome = RunCoro(Io, RunMalformedPeerFrame(Io.get_executor()));
        ASSERT_TRUE(Outcome.Accepted);
        EXPECT_EQ(Outcome.FirstRead.Bytes, 6U);
        EXPECT_FALSE(Outcome.FirstRead.Failure.Failed());
        const std::array<std::byte, 6> ExpectedPayload{
            std::byte{0x71}, std::byte{0x75}, std::byte{0x65},
            std::byte{0x75}, std::byte{0x65}, std::byte{0x64}};
        ASSERT_EQ(Outcome.Payload.size(), ExpectedPayload.size());
        EXPECT_TRUE(std::equal(
            ExpectedPayload.begin(), ExpectedPayload.end(), Outcome.Payload.begin()));
        EXPECT_EQ(Outcome.RepeatRead.Bytes, 0U);
        EXPECT_EQ(Outcome.RepeatRead.Failure.Code, Prism::Fault::Code::ProtocolError);
        EXPECT_EQ(Outcome.StickyRead.Bytes, 0U);
        EXPECT_EQ(Outcome.StickyRead.Failure.Code, Prism::Fault::Code::ProtocolError);
        EXPECT_FALSE(Outcome.PeerEof);
        ASSERT_TRUE(Outcome.PeerFailure.has_value());
        EXPECT_EQ(Outcome.PeerFailure->Code, Prism::Fault::Code::ProtocolError);
        EXPECT_FALSE(Outcome.PeerFailure->Native);
        EXPECT_EQ(Outcome.ReadCalls, 4U);
        EXPECT_EQ(Outcome.WriteCalls, 0U);
        EXPECT_TRUE(Outcome.SessionDrained);
        EXPECT_TRUE(Outcome.StreamRetired);
        EXPECT_TRUE(Outcome.RawClosed);
        EXPECT_TRUE(Outcome.RawRetired);
    }

    TEST(MuxTeardownCause, WriterResetReachesAcceptedChildWithoutBecomingEof)
    {
        Net::io_context Io;
        const auto Native = std::make_error_code(std::errc::connection_reset);
        const auto Outcome = RunCoro(Io, RunWriterReset(Io.get_executor(), 0U));
        ASSERT_TRUE(Outcome.Accepted);
        EXPECT_EQ(Outcome.Write.Bytes, 0U);
        EXPECT_EQ(Outcome.Write.Failure.Code, Prism::Fault::Code::IoError);
        EXPECT_EQ(Outcome.FirstRead.Bytes, 0U);
        EXPECT_EQ(Outcome.FirstRead.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.FirstRead.Failure.Native, Native);
        EXPECT_EQ(Outcome.RepeatRead.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.RepeatRead.Failure.Native, Native);
        EXPECT_EQ(Outcome.StickyRead.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.StickyRead.Failure.Native, Native);
        EXPECT_FALSE(Outcome.PeerEof);
        ASSERT_TRUE(Outcome.PeerFailure.has_value());
        EXPECT_EQ(Outcome.PeerFailure->Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.PeerFailure->Native, Native);
        EXPECT_EQ(Outcome.ReadCalls, 2U);
        EXPECT_EQ(Outcome.WriteCalls, 1U);
        EXPECT_TRUE(Outcome.SessionDrained);
        EXPECT_TRUE(Outcome.StreamRetired);
        EXPECT_TRUE(Outcome.RawClosed);
        EXPECT_TRUE(Outcome.RawRetired);
    }

    TEST(MuxTeardownCause, PartialFrameBytesAndNativeResetRemainTyped)
    {
        Net::io_context Io;
        const auto Native = std::make_error_code(std::errc::connection_reset);
        const auto Outcome = RunCoro(Io, RunWriterReset(Io.get_executor(), 1U));
        ASSERT_TRUE(Outcome.Accepted);
        EXPECT_EQ(Outcome.FailedWriteBytes, 1U);
        EXPECT_EQ(Outcome.Write.Bytes, 0U);
        EXPECT_EQ(Outcome.Write.Failure.Code, Prism::Fault::Code::IoError);
        EXPECT_EQ(Outcome.FirstRead.Bytes, 0U);
        EXPECT_EQ(Outcome.FirstRead.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.FirstRead.Failure.Native, Native);
        EXPECT_EQ(Outcome.RepeatRead.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.RepeatRead.Failure.Native, Native);
        EXPECT_EQ(Outcome.StickyRead.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.StickyRead.Failure.Native, Native);
        EXPECT_FALSE(Outcome.PeerEof);
        ASSERT_TRUE(Outcome.PeerFailure.has_value());
        EXPECT_EQ(Outcome.PeerFailure->Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.PeerFailure->Native, Native);
        EXPECT_EQ(Outcome.ReadCalls, 2U);
        EXPECT_EQ(Outcome.WriteCalls, 1U);
        EXPECT_TRUE(Outcome.SessionDrained);
        EXPECT_TRUE(Outcome.StreamRetired);
        EXPECT_TRUE(Outcome.RawClosed);
        EXPECT_TRUE(Outcome.RawRetired);
    }
} // namespace
