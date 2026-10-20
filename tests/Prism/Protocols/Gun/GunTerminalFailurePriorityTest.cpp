/**
 * @file GunTerminalFailurePriorityTest.cpp
 * @brief gRPC 服务端和 stream driver 的解析失败终态优先级回归。
 */

#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Gun/Detail/GrpcSession.hpp>
#include <Prism/Protocols/Gun/Detail/GrpcStreamDriver.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Gun = Prism::Gun::Grpc::Detail;

    struct FeedOutcome final
    {
        bool Accepted{false};
        std::error_code Error;
    };

    class ScriptedGrpcTransmission final : public Prism::Transmission
    {
    public:
        ScriptedGrpcTransmission(
            ExecutorType Executor,
            std::vector<std::byte> Input,
            Fault::Failure ReadFailure)
            : Transmission(Executor), Executor_(std::move(Executor)),
              Input_(std::move(Input)), ReadFailure_(std::move(ReadFailure))
        {
        }

        [[nodiscard]] auto ReadCount() const noexcept -> std::size_t { return ReadCount_; }
        [[nodiscard]] auto WriteCount() const noexcept -> std::size_t { return WriteCount_; }
        [[nodiscard]] auto CloseCount() const noexcept -> std::size_t { return CloseCount_; }
        [[nodiscard]] auto IsOpen() const -> bool override { return !Closed_; }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCount_;
            const auto Count = (std::min)(Buffer.size(), Input_.size() - Offset_);
            if (Count != 0U)
            {
                std::memcpy(Buffer.data(), Input_.data() + Offset_, Count);
                Offset_ += Count;
            }
            const auto Failure = ReadDelivered_ ? Fault::Failure{Fault::Code::Eof} : ReadFailure_;
            ReadDelivered_ = true;
            Prism::Transmission::PostResult(Executor_, std::move(Handler), {Count, Failure});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            ++WriteCount_;
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
            Closed_ = true;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override { return {}; }

    private:
        ExecutorType Executor_;
        std::vector<std::byte> Input_;
        Fault::Failure ReadFailure_;
        std::size_t Offset_{0};
        std::size_t ReadCount_{0};
        std::size_t WriteCount_{0};
        std::size_t CloseCount_{0};
        bool ReadDelivered_{false};
        bool Closed_{false};
    };

    struct ServerOutcome final
    {
        Fault::Failure Failure;
        std::size_t ReadCount{0};
        std::size_t WriteCount{0};
        std::size_t CloseCount{0};
        bool CloseAccepted{false};
        bool DrainSucceeded{false};
    };

    struct ServerRequest final
    {
        std::shared_ptr<ScriptedGrpcTransmission> Transport;
        ServerOutcome *Outcome{nullptr};
    };

    [[nodiscard]] auto MakeMalformedSettingsFrame() -> std::vector<std::byte>
    {
        constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        std::vector<std::byte> Wire;
        Wire.reserve(Preface.size() + 10U);
        for (const auto Character : Preface)
        {
            Wire.push_back(static_cast<std::byte>(Character));
        }
        constexpr std::array Frame{
            std::byte{0}, std::byte{0}, std::byte{1}, std::byte{0x04},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}};
        Wire.insert(Wire.end(), Frame.begin(), Frame.end());
        return Wire;
    }

    [[nodiscard]] auto MakePartialSettingsFrame() -> std::vector<std::byte>
    {
        constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
        std::vector<std::byte> Wire;
        Wire.reserve(Preface.size() + 3U);
        for (const auto Character : Preface)
        {
            Wire.push_back(static_cast<std::byte>(Character));
        }
        Wire.insert(Wire.end(), {std::byte{0}, std::byte{0}, std::byte{0}});
        return Wire;
    }

    [[nodiscard]] auto ProbeFeed(
        const std::span<const std::byte> Input,
        Net::any_io_executor Executor) -> FeedOutcome
    {
        Prism::Http2::Session Session(std::move(Executor), true);
        FeedOutcome Outcome;
        Outcome.Accepted = Session.Feed(Input, Outcome.Error);
        return Outcome;
    }

    [[nodiscard]] auto ProcessCompletion(
        const std::vector<std::byte> &Input,
        const Fault::Failure Failure,
        Net::any_io_executor Executor) -> Gun::GrpcReadStep
    {
        Prism::Http2::Session Session(std::move(Executor), true);
        const Gun::GrpcReadCompletion Completion{
            std::span<const std::byte>(Input), Prism::IoResult{Input.size(), Failure}};
        return Gun::ProcessGrpcReadCompletion(Session, Completion);
    }

    auto RunServer(ServerRequest Request) -> Net::awaitable<void>
    {
        auto Session = std::make_shared<Gun::ServerSession>(Request.Transport);
        Request.Outcome->Failure = co_await Session->Run();
        Request.Outcome->ReadCount = Request.Transport->ReadCount();
        Request.Outcome->WriteCount = Request.Transport->WriteCount();
        const auto Closed = Request.Transport->Close();
        Request.Outcome->CloseAccepted = static_cast<bool>(Closed);
        const auto Activity = Request.Transport->Activity();
        if (Activity)
        {
            const auto Drained = co_await Activity->Drain();
            Request.Outcome->DrainSucceeded = static_cast<bool>(Drained);
        }
        Request.Outcome->CloseCount = Request.Transport->CloseCount();
    }

    auto RunCoroutine(Net::io_context &Io, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Io, std::move(Operation),
            [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
        Io.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto RunServerSession(
        Net::io_context &Io,
        std::shared_ptr<ScriptedGrpcTransmission> Transport,
        ServerOutcome &Outcome) -> void
    {
        RunCoroutine(Io, RunServer({std::move(Transport), &Outcome}));
    }

    auto ExpectServerRetired(const ServerOutcome &Outcome) -> void
    {
        EXPECT_EQ(Outcome.ReadCount, 1U);
        EXPECT_EQ(Outcome.WriteCount, 1U);
        EXPECT_EQ(Outcome.CloseCount, 1U);
        EXPECT_TRUE(Outcome.CloseAccepted);
        EXPECT_TRUE(Outcome.DrainSucceeded);
    }

    TEST(GunReadCompletionPriority, CompleteMalformedFramePrecedesEof)
    {
        Net::io_context Io;
        const auto Input = MakeMalformedSettingsFrame();
        const auto Probe = ProbeFeed(Input, Io.get_executor());
        ASSERT_FALSE(Probe.Accepted);
        ASSERT_TRUE(Probe.Error);

        const auto Step = ProcessCompletion(
            Input, {Fault::Code::Eof}, Io.get_executor());

        EXPECT_TRUE(Step.Terminal);
        EXPECT_EQ(Step.Failure.Code, Fault::ToCode(Probe.Error));
        EXPECT_EQ(Step.Failure.Native, Probe.Error);
        EXPECT_NE(Step.Failure.Code, Fault::Code::Eof);
    }

    TEST(GunReadCompletionPriority, CompleteMalformedFramePrecedesNativeReset)
    {
        Net::io_context Io;
        const auto Input = MakeMalformedSettingsFrame();
        const auto Probe = ProbeFeed(Input, Io.get_executor());
        ASSERT_FALSE(Probe.Accepted);
        ASSERT_TRUE(Probe.Error);
        const auto Native = std::make_error_code(std::errc::connection_reset);

        const auto Step = ProcessCompletion(
            Input, Fault::FromNative(Native), Io.get_executor());

        EXPECT_TRUE(Step.Terminal);
        EXPECT_EQ(Step.Failure.Code, Fault::ToCode(Probe.Error));
        EXPECT_EQ(Step.Failure.Native, Probe.Error);
        EXPECT_NE(Step.Failure.Native, Native);
    }

    TEST(GunReadCompletionPriority, PartialFramePreservesEof)
    {
        Net::io_context Io;
        const auto Input = MakePartialSettingsFrame();
        const auto Probe = ProbeFeed(Input, Io.get_executor());
        ASSERT_TRUE(Probe.Accepted);
        EXPECT_FALSE(Probe.Error);

        const auto Step = ProcessCompletion(
            Input, {Fault::Code::Eof}, Io.get_executor());

        EXPECT_TRUE(Step.Terminal);
        EXPECT_EQ(Step.Failure.Code, Fault::Code::Eof);
    }

    TEST(GunReadCompletionPriority, PartialFramePreservesNativeReset)
    {
        Net::io_context Io;
        const auto Input = MakePartialSettingsFrame();
        const auto Probe = ProbeFeed(Input, Io.get_executor());
        ASSERT_TRUE(Probe.Accepted);
        EXPECT_FALSE(Probe.Error);
        const auto Native = std::make_error_code(std::errc::connection_reset);

        const auto Step = ProcessCompletion(
            Input, Fault::FromNative(Native), Io.get_executor());

        EXPECT_TRUE(Step.Terminal);
        EXPECT_EQ(Step.Failure.Code, Fault::Code::ConnectionReset);
        EXPECT_EQ(Step.Failure.Native, Native);
    }

    TEST(GunServerTerminalPriority, CompleteMalformedFramePrecedesEof)
    {
        Net::io_context Io;
        const auto Input = MakeMalformedSettingsFrame();
        const auto Probe = ProbeFeed(Input, Io.get_executor());
        ASSERT_FALSE(Probe.Accepted);
        ASSERT_TRUE(Probe.Error);
        auto Transport = std::make_shared<ScriptedGrpcTransmission>(
            Io.get_executor(), Input, Fault::Failure{Fault::Code::Eof});
        ServerOutcome Outcome;

        RunServerSession(Io, Transport, Outcome);

        EXPECT_EQ(Outcome.Failure.Code, Fault::Code::ProtocolError);
        EXPECT_EQ(Outcome.Failure.Native, Probe.Error);
        ExpectServerRetired(Outcome);
    }

    TEST(GunServerTerminalPriority, CompleteMalformedFramePrecedesNativeReset)
    {
        Net::io_context Io;
        const auto Input = MakeMalformedSettingsFrame();
        const auto Probe = ProbeFeed(Input, Io.get_executor());
        ASSERT_FALSE(Probe.Accepted);
        ASSERT_TRUE(Probe.Error);
        const auto Native = std::make_error_code(std::errc::connection_reset);
        auto Transport = std::make_shared<ScriptedGrpcTransmission>(
            Io.get_executor(), Input, Fault::FromNative(Native));
        ServerOutcome Outcome;

        RunServerSession(Io, Transport, Outcome);

        EXPECT_EQ(Outcome.Failure.Code, Fault::Code::ProtocolError);
        EXPECT_EQ(Outcome.Failure.Native, Probe.Error);
        EXPECT_NE(Outcome.Failure.Native, Native);
        ExpectServerRetired(Outcome);
    }

    TEST(GunServerTerminalPriority, PartialFrameEofKeepsIncompleteRequestOutcome)
    {
        Net::io_context Io;
        const auto Input = MakePartialSettingsFrame();
        const auto Probe = ProbeFeed(Input, Io.get_executor());
        ASSERT_TRUE(Probe.Accepted);
        EXPECT_FALSE(Probe.Error);
        auto Transport = std::make_shared<ScriptedGrpcTransmission>(
            Io.get_executor(), Input, Fault::Failure{Fault::Code::Eof});
        ServerOutcome Outcome;

        RunServerSession(Io, Transport, Outcome);

        EXPECT_EQ(Outcome.Failure.Code, Fault::Code::IoError);
        ExpectServerRetired(Outcome);
    }

    TEST(GunServerTerminalPriority, PartialFramePreservesNativeReset)
    {
        Net::io_context Io;
        const auto Input = MakePartialSettingsFrame();
        const auto Probe = ProbeFeed(Input, Io.get_executor());
        ASSERT_TRUE(Probe.Accepted);
        EXPECT_FALSE(Probe.Error);
        const auto Native = std::make_error_code(std::errc::connection_reset);
        auto Transport = std::make_shared<ScriptedGrpcTransmission>(
            Io.get_executor(), Input, Fault::FromNative(Native));
        ServerOutcome Outcome;

        RunServerSession(Io, Transport, Outcome);

        EXPECT_EQ(Outcome.Failure.Code, Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.Failure.Native, Native);
        ExpectServerRetired(Outcome);
    }
} // namespace
