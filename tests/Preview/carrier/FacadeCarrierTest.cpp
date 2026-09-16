/**
 * @file FacadeCarrierTest.cpp
 * @brief Preview carrier facade 的所有权、错误映射与异步状态测试。
 */

#include <Preview/Composition/Carrier/FacadeCarrier.hpp>
#include <Preview/Protocols/Reality/Carrier.hpp>
#include <Preview/Protocols/Restls/Carrier.hpp>
#include <Preview/Protocols/Shadowtls/Carrier.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

namespace
{

    namespace Carrier = Preview::Composition::Carrier;
    namespace Net = boost::asio;

    class TestTransport final : public Preview::Transmission
    {
    public:
        explicit TestTransport(Net::io_context &Context) : Executor_(Context.get_executor())
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer,
                                            std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            ErrorCode.clear();
            (void)Buffer;
            co_return 0;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer,
                                             std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            ErrorCode.clear();
            co_return Buffer.size();
        }

        auto Close() -> void override
        {
            Open_ = false;
        }

        auto Cancel() -> void override
        {
            Cancelled_ = true;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Open_;
        }

        [[nodiscard]] auto Cancelled() const noexcept -> bool
        {
            return Cancelled_;
        }

    private:
        ExecutorType Executor_;
        bool Open_{true};
        bool Cancelled_{false};
    };

    auto MakeReplay() -> Carrier::ReplayBuffer
    {
        const std::array<std::byte, 4> Bytes{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x2a}};
        return Carrier::ReplayBuffer(Bytes);
    }

    auto RunAccept(Net::io_context &Context,
                   Carrier::FacadeCarrier &Facade,
                   Carrier::CarrierAcceptRequest Request)
        -> std::optional<Carrier::CarrierAcceptResult>
    {
        std::optional<Carrier::CarrierAcceptResult> Result;
        std::exception_ptr Failure;
        Net::co_spawn(
            Context,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Facade.Accept(std::move(Request));
            },
            [&](std::exception_ptr Error)
            {
                Failure = std::move(Error);
            });
        Context.run();
        EXPECT_FALSE(Failure);
        return Result;
    }

    TEST(FacadeCarrier, MapsProtocolAndNativeErrorsToTypedFailures)
    {
        const auto Auth = Carrier::MapError(
            Preview::Error::BadAuth, Carrier::HandshakeStage::Committing);
        EXPECT_EQ(Auth.Code, Carrier::CarrierError::AuthFailed);
        EXPECT_EQ(Auth.ProtocolCode, Preview::Error::BadAuth);
        EXPECT_EQ(Auth.Stage, Carrier::HandshakeStage::Committing);

        const auto Cancelled = Carrier::MapError(
            std::make_error_code(std::errc::operation_canceled),
            Carrier::HandshakeStage::Preparing);
        EXPECT_EQ(Cancelled.Code, Carrier::CarrierError::Cancelled);
        EXPECT_EQ(Cancelled.NativeCode, std::make_error_code(std::errc::operation_canceled));

        const auto Timeout = Carrier::MapError(
            std::make_error_code(std::errc::timed_out),
            Carrier::HandshakeStage::Preparing);
        EXPECT_EQ(Timeout.Code, Carrier::CarrierError::Timeout);
    }

    TEST(FacadeCarrier, PreservesReplayAndTransportAcrossAsyncCommit)
    {
        Net::io_context Context;
        auto Transport = std::make_shared<TestTransport>(Context);
        const auto Original = Transport;
        auto Facade = Carrier::FacadeCarrier::Ready(
            Carrier::CarrierKind::Reality,
            [](Carrier::CarrierAcceptRequest Request)
                -> Net::awaitable<Carrier::CarrierAcceptResult>
            {
                EXPECT_TRUE(Request.Transport);
                EXPECT_EQ(Request.Replay.Size(), 4U);
                EXPECT_EQ(Request.State->Current(), Carrier::HandshakeStage::Preparing);
                co_await Net::post(Net::use_awaitable);
                auto Metadata = Carrier::CarrierMetadata{
                    .Kind = Carrier::CarrierKind::Reality,
                    .WireComplete = true,
                    .ReplayBytes = Request.Replay.Size(),
                    .Detail = {}};
                co_return Carrier::CarrierAcceptResult::Accepted(
                    std::move(Request.Transport), Request.Replay, Metadata,
                    std::move(Request.State));
            });

        auto Result = RunAccept(
            Context, Facade, Carrier::CarrierAcceptRequest{Transport, MakeReplay(), {}});
        ASSERT_TRUE(Result.has_value());
        ASSERT_TRUE(Result->Accepted());
        EXPECT_EQ(Result->Transport, Original);
        EXPECT_EQ(Result->Replay.Size(), 4U);
        EXPECT_EQ(Result->Metadata.ReplayBytes, 4U);
        ASSERT_TRUE(Result->State);
        EXPECT_EQ(Result->State->Current(), Carrier::HandshakeStage::Accepted);
    }

    TEST(FacadeCarrier, RejectsInconsistentSuccessWithoutDroppingOwner)
    {
        Net::io_context Context;
        auto Transport = std::make_shared<TestTransport>(Context);
        const auto Original = Transport;
        auto Facade = Carrier::FacadeCarrier::Ready(
            Carrier::CarrierKind::Shadowtls,
            [](Carrier::CarrierAcceptRequest Request)
                -> Net::awaitable<Carrier::CarrierAcceptResult>
            {
                auto Metadata = Carrier::CarrierMetadata{
                    .Kind = Carrier::CarrierKind::Shadowtls,
                    .WireComplete = true,
                    .ReplayBytes = Request.Replay.Size(),
                    .Detail = {}};
                co_return Carrier::CarrierAcceptResult::Accepted(
                    {}, Request.Replay, Metadata, std::move(Request.State));
            });

        auto Result = RunAccept(
            Context, Facade, Carrier::CarrierAcceptRequest{Transport, MakeReplay(), {}});
        ASSERT_TRUE(Result.has_value());
        EXPECT_FALSE(Result->Accepted());
        EXPECT_EQ(Result->Failure.Code, Carrier::CarrierError::InvalidResult);
        EXPECT_EQ(Result->Transport, Original);
        EXPECT_EQ(Result->Replay.Size(), 4U);
        ASSERT_TRUE(Result->State);
        EXPECT_EQ(Result->State->Current(), Carrier::HandshakeStage::Rejected);
    }

    TEST(FacadeCarrier, RejectsSuccessThatDropsReplayOwnership)
    {
        Net::io_context Context;
        auto Transport = std::make_shared<TestTransport>(Context);
        auto Facade = Carrier::FacadeCarrier::Ready(
            Carrier::CarrierKind::Reality,
            [](Carrier::CarrierAcceptRequest Request)
                -> Net::awaitable<Carrier::CarrierAcceptResult>
            {
                auto Metadata = Carrier::CarrierMetadata{
                    .Kind = Carrier::CarrierKind::Reality,
                    .WireComplete = true,
                    .ReplayBytes = 0,
                    .Detail = {}};
                co_return Carrier::CarrierAcceptResult::Accepted(
                    std::move(Request.Transport), {}, Metadata, std::move(Request.State));
            });

        auto Result = RunAccept(
            Context, Facade, Carrier::CarrierAcceptRequest{Transport, MakeReplay(), {}});
        ASSERT_TRUE(Result.has_value());
        EXPECT_FALSE(Result->Accepted());
        EXPECT_EQ(Result->Failure.Code, Carrier::CarrierError::InvalidResult);
        EXPECT_EQ(Result->Transport, Transport);
        EXPECT_EQ(Result->Replay.Size(), 4U);
    }

    TEST(FacadeCarrier, MissingCallbackCannotReportSuccess)
    {
        Net::io_context Context;
        auto Transport = std::make_shared<TestTransport>(Context);
        auto Facade = Carrier::FacadeCarrier::Ready(
            Carrier::CarrierKind::Restls, Carrier::FacadeCarrier::AcceptHandler{});

        auto Result = RunAccept(
            Context, Facade, Carrier::CarrierAcceptRequest{Transport, MakeReplay(), {}});
        ASSERT_TRUE(Result.has_value());
        EXPECT_FALSE(Result->Accepted());
        EXPECT_EQ(Result->Failure.Code, Carrier::CarrierError::MissingCallback);
        EXPECT_EQ(Result->Transport, Transport);
        EXPECT_EQ(Result->Replay.Size(), 4U);
    }

    TEST(FacadeCarrier, UnavailableProtocolBoundaryRetainsOwnerAndReplay)
    {
        const auto RunUnavailable = [](auto MakeFacade)
        {
            Net::io_context Context;
            auto Transport = std::make_shared<TestTransport>(Context);
            const auto Original = Transport;
            auto Facade = MakeFacade();
            auto Result = RunAccept(
                Context, Facade, Carrier::CarrierAcceptRequest{Transport, MakeReplay(), {}});
            ASSERT_TRUE(Result.has_value());
            EXPECT_FALSE(Result->Accepted());
            EXPECT_EQ(Result->Failure.Code, Carrier::CarrierError::WireUnavailable);
            EXPECT_EQ(Result->Transport, Original);
            EXPECT_EQ(Result->Replay.Size(), 4U);
            EXPECT_FALSE(Result->Metadata.WireComplete);
            ASSERT_TRUE(Result->State);
            EXPECT_EQ(Result->State->Current(), Carrier::HandshakeStage::Rejected);
        };

        RunUnavailable([] { return Preview::Reality::MakeFacadeCarrier(); });
        RunUnavailable([] { return Preview::Shadowtls::MakeFacadeCarrier(); });
        RunUnavailable([] { return Preview::Restls::MakeFacadeCarrier(); });
    }

} // namespace
