/** @file WriteProgressTest.cpp @brief 验证 sing-mux 子流写入保留字节与终态。 */
#include <Prism/Protocols/Mux/SingMux/Stream.hpp>
#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

namespace
{
    namespace Net = boost::asio;

    struct WriteStep final
    {
        std::size_t Bytes{0};
        Prism::Fault::Failure Failure{};
    };

    class ScriptedWriteTransmission final : public Prism::Transmission
    {
    public:
        ScriptedWriteTransmission(Net::any_io_executor Executor, std::vector<WriteStep> Steps)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)), Steps_(std::move(Steps))
        {
        }

        auto Executor() const -> ExecutorType override { return Executor_; }

        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), Prism::IoResult{0, {Prism::Fault::Code::Eof}});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            WriteRequests_.emplace_back(Buffer.begin(), Buffer.end());
            Prism::IoResult Result;
            if (StepIndex_ < Steps_.size())
            {
                const auto &Step = Steps_[StepIndex_++];
                Result = {Step.Bytes, Step.Failure};
            }
            else if (StickyFailure_)
            {
                Result = {0, *StickyFailure_};
            }
            else
            {
                Result = {Buffer.size(), {}};
            }

            const auto Written = (std::min)(Result.Bytes, Buffer.size());
            Written_.insert(Written_.end(), Buffer.begin(), Buffer.begin() + static_cast<std::ptrdiff_t>(Written));
            if (Result.Failure.Failed()) StickyFailure_ = Result.Failure;
            Prism::Transmission::PostResult(Executor_, std::move(Handler), Result);
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor_, std::move(Handler), Prism::IoResult{});
        }

        auto OnClose() -> ControlResult override { return {}; }
        auto OnCancel() -> ControlResult override { return {}; }

        [[nodiscard]] auto WriteCalls() const noexcept -> std::size_t { return WriteRequests_.size(); }
        [[nodiscard]] auto WriteRequests() const noexcept -> const std::vector<std::vector<std::byte>> &
        {
            return WriteRequests_;
        }
        [[nodiscard]] auto Written() const noexcept -> const std::vector<std::byte> & { return Written_; }

    private:
        Net::any_io_executor Executor_;
        std::vector<WriteStep> Steps_;
        std::size_t StepIndex_{0};
        std::vector<std::vector<std::byte>> WriteRequests_;
        std::vector<std::byte> Written_;
        std::optional<Prism::Fault::Failure> StickyFailure_;
    };

    struct WriteOutcome final
    {
        Prism::IoResult First{};
        Prism::IoResult Second{};
        Prism::Fault::Failure ExpectedFailure{};
        std::vector<std::vector<std::byte>> WriteRequests;
        std::vector<std::byte> Written;
        std::size_t WriteCalls{0};
        std::size_t FirstWriteCalls{0};
        bool CloseAccepted{false};
        bool Drained{false};
    };

    struct RunCapture final
    {
        std::optional<WriteOutcome> Outcome;
        std::exception_ptr Failure;
    };

    auto ProtocolFailureWithNativeReset() -> Prism::Fault::Failure
    {
        return {
            Prism::Fault::Code::ProtocolError,
            std::make_error_code(std::errc::connection_reset)};
    }

    auto RunPayloadProgress(Net::any_io_executor Executor) -> Net::awaitable<WriteOutcome>
    {
        const auto Failure = ProtocolFailureWithNativeReset();
        auto Raw = std::make_shared<ScriptedWriteTransmission>(
            Executor, std::vector<WriteStep>{{1, {}}, {2, Failure}});
        auto Stream = std::make_shared<Prism::Mux::SingMux::ServerStream>(
            Raw, Prism::Network::Target{}, std::nullopt);
        const std::array<std::byte, 4> Payload{
            std::byte{0x31}, std::byte{0x32}, std::byte{0x33}, std::byte{0x34}};
        const auto First = co_await Stream->WriteSome(Payload);
        const auto FirstWriteCalls = Raw->WriteCalls();
        const auto Closed = Stream->Close();
        const auto Drained = co_await Stream->Activity()->Drain();
        co_return WriteOutcome{
            First, {}, Failure, Raw->WriteRequests(), Raw->Written(), Raw->WriteCalls(),
            FirstWriteCalls, static_cast<bool>(Closed), static_cast<bool>(Drained)};
    }

    auto RunStatusProgress(Net::any_io_executor Executor) -> Net::awaitable<WriteOutcome>
    {
        const auto Failure = ProtocolFailureWithNativeReset();
        auto Raw = std::make_shared<ScriptedWriteTransmission>(
            Executor, std::vector<WriteStep>{{1, Failure}});
        auto Stream = std::make_shared<Prism::Mux::SingMux::ServerStream>(
            Raw, Prism::Network::Target{}, std::nullopt);
        const std::array<std::byte, 2> Payload{std::byte{0x41}, std::byte{0x42}};
        const auto First = co_await Stream->WriteSome(Payload);
        const auto FirstWriteCalls = Raw->WriteCalls();
        const auto Second = co_await Stream->WriteSome(Payload);
        const auto Closed = Stream->Close();
        const auto Drained = co_await Stream->Activity()->Drain();
        co_return WriteOutcome{
            First, Second, Failure, Raw->WriteRequests(), Raw->Written(), Raw->WriteCalls(),
            FirstWriteCalls, static_cast<bool>(Closed), static_cast<bool>(Drained)};
    }

    auto RunZeroProgressStatusRetry(Net::any_io_executor Executor)
        -> Net::awaitable<WriteOutcome>
    {
        const auto Failure = Prism::Fault::FromNative(
            std::make_error_code(std::errc::broken_pipe));
        auto Raw = std::make_shared<ScriptedWriteTransmission>(
            Executor, std::vector<WriteStep>{{0, {}}});
        auto Stream = std::make_shared<Prism::Mux::SingMux::ServerStream>(
            Raw, Prism::Network::Target{}, std::nullopt);
        const std::array<std::byte, 2> Payload{std::byte{0x51}, std::byte{0x52}};
        const auto First = co_await Stream->WriteSome(Payload);
        const auto FirstWriteCalls = Raw->WriteCalls();
        const auto Second = co_await Stream->WriteSome(Payload);
        const auto Closed = Stream->Close();
        const auto Drained = co_await Stream->Activity()->Drain();
        co_return WriteOutcome{
            First, Second, Failure, Raw->WriteRequests(), Raw->Written(), Raw->WriteCalls(),
            FirstWriteCalls, static_cast<bool>(Closed), static_cast<bool>(Drained)};
    }

    auto RunOverreportedPayloadWithTerminal(Net::any_io_executor Executor)
        -> Net::awaitable<WriteOutcome>
    {
        const auto Failure = ProtocolFailureWithNativeReset();
        const std::array<std::byte, 3> Payload{
            std::byte{0x61}, std::byte{0x62}, std::byte{0x63}};
        auto Raw = std::make_shared<ScriptedWriteTransmission>(Executor,
            std::vector<WriteStep>{{1, {}}, {Payload.size() + 1U, Failure}});
        auto Stream = std::make_shared<Prism::Mux::SingMux::ServerStream>(
            Raw, Prism::Network::Target{}, std::nullopt);
        const auto First = co_await Stream->WriteSome(Payload);
        const auto FirstWriteCalls = Raw->WriteCalls();
        const auto Second = co_await Stream->WriteSome(Payload);
        const auto Closed = Stream->Close();
        const auto Drained = co_await Stream->Activity()->Drain();
        co_return WriteOutcome{
            First, Second, Failure, Raw->WriteRequests(), Raw->Written(), Raw->WriteCalls(),
            FirstWriteCalls, static_cast<bool>(Closed), static_cast<bool>(Drained)};
    }

    auto CollectOutcome(Net::io_context &Io, Net::awaitable<WriteOutcome> Operation) -> RunCapture
    {
        RunCapture Capture;
        Net::co_spawn(Io, std::move(Operation), [&](std::exception_ptr Error, WriteOutcome Value)
        {
            Capture.Failure = Error;
            if (!Error) Capture.Outcome = std::move(Value);
        });
        Io.run();
        return Capture;
    }
}

TEST(SingMuxStreamWriteProgress, PayloadBytesSurviveSameCompletionFailure)
{
    Net::io_context Io;
    auto Capture = CollectOutcome(Io, RunPayloadProgress(Io.get_executor()));

    ASSERT_FALSE(Capture.Failure);
    ASSERT_TRUE(Capture.Outcome);
    const auto &Outcome = *Capture.Outcome;
    EXPECT_EQ(Outcome.First.Bytes, 2U);
    EXPECT_EQ(Outcome.First.Failure.Code, Outcome.ExpectedFailure.Code);
    EXPECT_EQ(Outcome.First.Failure.Native, Outcome.ExpectedFailure.Native);
    ASSERT_EQ(Outcome.WriteRequests.size(), 2U);
    EXPECT_EQ(Outcome.WriteRequests[0], std::vector<std::byte>{std::byte{0x00}});
    EXPECT_EQ(Outcome.WriteRequests[1],
              (std::vector<std::byte>{std::byte{0x31}, std::byte{0x32}, std::byte{0x33}, std::byte{0x34}}));
    EXPECT_EQ(Outcome.Written,
              (std::vector<std::byte>{std::byte{0x00}, std::byte{0x31}, std::byte{0x32}}));
    EXPECT_EQ(Outcome.WriteCalls, 2U);
    EXPECT_TRUE(Outcome.CloseAccepted);
    EXPECT_TRUE(Outcome.Drained);
}

TEST(SingMuxStreamWriteProgress, ZeroProgressStatusReturnsBrokenPipeAndCanRetry)
{
    Net::io_context Io;
    auto Capture = CollectOutcome(Io, RunZeroProgressStatusRetry(Io.get_executor()));

    ASSERT_FALSE(Capture.Failure);
    ASSERT_TRUE(Capture.Outcome);
    const auto &Outcome = *Capture.Outcome;
    EXPECT_EQ(Outcome.First.Bytes, 0U);
    EXPECT_EQ(Outcome.First.Failure.Code, Outcome.ExpectedFailure.Code);
    EXPECT_EQ(Outcome.First.Failure.Native, Outcome.ExpectedFailure.Native);
    EXPECT_EQ(Outcome.FirstWriteCalls, 1U);
    EXPECT_EQ(Outcome.Second.Bytes, 2U);
    EXPECT_FALSE(Outcome.Second.Failure.Failed());
    ASSERT_EQ(Outcome.WriteRequests.size(), 3U);
    EXPECT_EQ(Outcome.WriteRequests[0], std::vector<std::byte>{std::byte{0x00}});
    EXPECT_EQ(Outcome.WriteRequests[1], std::vector<std::byte>{std::byte{0x00}});
    EXPECT_EQ(Outcome.WriteRequests[2], (std::vector<std::byte>{std::byte{0x51}, std::byte{0x52}}));
    EXPECT_EQ(Outcome.Written,
              (std::vector<std::byte>{std::byte{0x00}, std::byte{0x51}, std::byte{0x52}}));
    EXPECT_EQ(Outcome.WriteCalls, 3U);
    EXPECT_TRUE(Outcome.CloseAccepted);
    EXPECT_TRUE(Outcome.Drained);
}

TEST(SingMuxStreamWriteProgress, OverreportedPayloadDoesNotCountBytesOrRetryStatus)
{
    Net::io_context Io;
    auto Capture = CollectOutcome(Io, RunOverreportedPayloadWithTerminal(Io.get_executor()));

    ASSERT_FALSE(Capture.Failure);
    ASSERT_TRUE(Capture.Outcome);
    const auto &Outcome = *Capture.Outcome;
    EXPECT_EQ(Outcome.First.Bytes, 0U);
    EXPECT_EQ(Outcome.First.Failure.Code, Outcome.ExpectedFailure.Code);
    EXPECT_EQ(Outcome.First.Failure.Native, Outcome.ExpectedFailure.Native);
    EXPECT_EQ(Outcome.FirstWriteCalls, 2U);
    EXPECT_EQ(Outcome.Second.Bytes, 0U);
    EXPECT_EQ(Outcome.Second.Failure.Code, Outcome.ExpectedFailure.Code);
    EXPECT_EQ(Outcome.Second.Failure.Native, Outcome.ExpectedFailure.Native);
    ASSERT_EQ(Outcome.WriteRequests.size(), 3U);
    EXPECT_EQ(Outcome.WriteRequests[0], std::vector<std::byte>{std::byte{0x00}});
    EXPECT_EQ(Outcome.WriteRequests[1],
              (std::vector<std::byte>{std::byte{0x61}, std::byte{0x62}, std::byte{0x63}}));
    EXPECT_EQ(Outcome.WriteRequests[2],
              (std::vector<std::byte>{std::byte{0x61}, std::byte{0x62}, std::byte{0x63}}));
    EXPECT_EQ(Outcome.WriteCalls, 3U);
    EXPECT_TRUE(Outcome.CloseAccepted);
    EXPECT_TRUE(Outcome.Drained);
}

TEST(SingMuxStreamWriteProgress, SentStatusIsNotRetriedAfterSameCompletionFailure)
{
    Net::io_context Io;
    auto Capture = CollectOutcome(Io, RunStatusProgress(Io.get_executor()));

    ASSERT_FALSE(Capture.Failure);
    ASSERT_TRUE(Capture.Outcome);
    const auto &Outcome = *Capture.Outcome;
    EXPECT_EQ(Outcome.First.Bytes, 0U);
    EXPECT_EQ(Outcome.First.Failure.Code, Outcome.ExpectedFailure.Code);
    EXPECT_EQ(Outcome.First.Failure.Native, Outcome.ExpectedFailure.Native);
    EXPECT_EQ(Outcome.Second.Bytes, 0U);
    EXPECT_EQ(Outcome.Second.Failure.Code, Outcome.ExpectedFailure.Code);
    EXPECT_EQ(Outcome.Second.Failure.Native, Outcome.ExpectedFailure.Native);
    ASSERT_EQ(Outcome.WriteRequests.size(), 2U);
    EXPECT_EQ(Outcome.WriteRequests[0], std::vector<std::byte>{std::byte{0x00}});
    EXPECT_EQ(Outcome.WriteRequests[1], (std::vector<std::byte>{std::byte{0x41}, std::byte{0x42}}));
    EXPECT_EQ(Outcome.Written, std::vector<std::byte>{std::byte{0x00}});
    EXPECT_EQ(Outcome.WriteCalls, 2U);
    EXPECT_TRUE(Outcome.CloseAccepted);
    EXPECT_TRUE(Outcome.Drained);
}
