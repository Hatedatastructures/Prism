/**
 * @file TimeoutRelayTest.cpp
 * @brief 管线超时/背压测试（T4-5 / D9）
 * @details 覆盖：
 *          - 空闲超时关闭隧道（可配 + Context.Timeout 优先）
 *          - 持续活动不关闭
 *          - 0 = 禁用超时
 *          - 背压：写失败（对端关闭）→ 隧道立即终止
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <exception>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

#include <Prism/Runtime/Middleware/Builtin/Relay.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Runtime/Middleware/Pipeline.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>

namespace
{
    namespace Net = boost::asio;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct RelayCompletionState
    {
        explicit RelayCompletionState(Net::any_io_executor Executor)
            : Done(std::make_shared<CompletionChannel>(std::move(Executor), 1))
        {
        }

        std::shared_ptr<CompletionChannel> Done;
        std::exception_ptr Failure;
        std::array<Prism::Fault::Failure, 2> DirectionFailure{};
        std::shared_ptr<Prism::Memory::BytePool> Bytes{std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8})};
        Prism::Fault::Failure Result{};
    };

    struct RelayStartRequest
    {
        std::shared_ptr<RelayCompletionState> State;
        Prism::SharedTransmission Inbound;
        Prism::SharedTransmission Outbound;
        std::chrono::milliseconds IdleTimeout{};
        std::chrono::milliseconds ContextTimeout{};
    };

    struct RelayWaitRequest
    {
        std::shared_ptr<RelayCompletionState> State;
        std::vector<Prism::SharedTransmission> CloseTargets;
    };

    /** @brief 在已拥有的 input/output carrier 上执行真实 relay 协程。 */
    auto RunRelay(RelayStartRequest Request) -> Net::awaitable<void>
    {
        Prism::Middleware::Context Context;
        Context.Inbound() = Request.Inbound;
        Context.Outbound = Request.Outbound;
        Context.Timeout = Request.ContextTimeout;
        Context.Bytes = Request.State->Bytes;
        Prism::Middleware::Builtin::RelayMiddleware Relay(nullptr, Request.IdleTimeout);
        auto Temporary = Context.Inbound();
        Request.State->Result = co_await Relay.Handle(Temporary, Context);
        Request.State->DirectionFailure = Relay.LastDirectionFailures();
    }

    /** @brief 在 carrier 原 executor 启动 relay 并保存最终完成结果。 */
    auto StartRelay(RelayStartRequest Request) -> void
    {
        const auto Executor = Request.Inbound->Executor();
        const auto State = Request.State;
        auto Completion = [State](std::exception_ptr Failure)
        {
            State->Failure = std::move(Failure);
            (void)State->Done->try_send(boost::system::error_code{});
        };
        Net::co_spawn(Executor, RunRelay(std::move(Request)), std::move(Completion));
    }

    auto WaitForRelay(RelayWaitRequest Request) -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Watchdog(Executor);
        Watchdog.expires_after(std::chrono::seconds(5));
        auto Completion = co_await (Request.State->Done->async_receive(Net::use_awaitable) ||
                                    Watchdog.async_wait(Net::use_awaitable));
        if (Completion.index() == 0U)
        {
            co_return true;
        }

        for (const auto &Transport : Request.CloseTargets)
        {
            if (Transport)
            {
                (void)Transport->Cancel();
                (void)Transport->Close();
            }
        }
        Watchdog.expires_after(std::chrono::seconds(1));
        auto Grace = co_await (Request.State->Done->async_receive(Net::use_awaitable) ||
                               Watchdog.async_wait(Net::use_awaitable));
        co_return Grace.index() == 0U;
    }

    auto MakePairShared(Net::io_context &IoContext)
        -> std::pair<std::shared_ptr<MemoryStream>, std::shared_ptr<MemoryStream>>
    {
        auto [Input, Output] = MakeMemoryPair(IoContext.get_executor());
        return {std::make_shared<MemoryStream>(std::move(Input)),
                std::make_shared<MemoryStream>(std::move(Output))};
    }

    /** @brief 拥有一组双向 memory carriers 与 relay 完成状态。 */
    struct MemoryRelayFixture final
    {
        explicit MemoryRelayFixture(Net::io_context &IoContext)
        {
            auto [ClientValue, InboundValue] = MakePairShared(IoContext);
            auto [OutboundValue, ServerValue] = MakePairShared(IoContext);
            Client = std::move(ClientValue);
            Inbound = std::move(InboundValue);
            Outbound = std::move(OutboundValue);
            Server = std::move(ServerValue);
            State = std::make_shared<RelayCompletionState>(IoContext.get_executor());
        }

        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Inbound;
        std::shared_ptr<MemoryStream> Outbound;
        std::shared_ptr<MemoryStream> Server;
        std::shared_ptr<RelayCompletionState> State;
    };

    /** @brief 拥有 mock relay 的入站与出站 transport。 */
    struct MockRelayFixture final
    {
        explicit MockRelayFixture(Net::any_io_executor Executor)
            : Inbound(std::make_shared<Prism::PrismMockTransport>(Executor)),
              Outbound(std::make_shared<Prism::PrismMockTransport>(std::move(Executor))),
              State(std::make_shared<RelayCompletionState>(Inbound->Executor()))
        {
        }

        std::shared_ptr<Prism::PrismMockTransport> Inbound;
        std::shared_ptr<Prism::PrismMockTransport> Outbound;
        std::shared_ptr<RelayCompletionState> State;
    };

    /** @brief 拥有本用例的 io_context，并以真实 run 循环驱动命名场景协程。 */
    class TimeoutRelayFixture final
    {
    public:
        /** @brief 在 Run 前创建并拥有 memory carrier 对。 */
        [[nodiscard]] auto MakeMemoryRelayFixture() -> MemoryRelayFixture
        {
            return MemoryRelayFixture(IoContext_);
        }

        /** @brief 在 Run 前创建并拥有 mock carrier。 */
        [[nodiscard]] auto MakeMockRelayFixture() -> MockRelayFixture
        {
            return MockRelayFixture(IoContext_.get_executor());
        }

        auto Run(Net::awaitable<void> Operation) -> void
        {
            std::exception_ptr Exception;
            Net::co_spawn(IoContext_, std::move(Operation),
                [this, &Exception](std::exception_ptr Failure)
                {
                    Exception = std::move(Failure);
                    IoContext_.stop();
                });
            IoContext_.run();
            if (Exception)
            {
                std::rethrow_exception(Exception);
            }
        }

        /** @brief 验证空闲到期后 relay 以 Timeout 结束。 */
        auto IdleTimeoutClosesTunnel(MemoryRelayFixture Relay) -> Net::awaitable<void>
        {
            StartRelay({Relay.State, Relay.Inbound, Relay.Outbound,
                        std::chrono::milliseconds(50), {}});
            const auto Completed = co_await WaitForRelay(
                {Relay.State, {Relay.Client, Relay.Server, Relay.Inbound, Relay.Outbound}});
            EXPECT_TRUE(Completed);
            EXPECT_FALSE(Relay.State->Failure);
            EXPECT_EQ(Relay.State->Result.Code, Prism::Fault::Code::Timeout);
        }

        /** @brief 验证超过空闲阈值的持续双向活动保持 relay，并在双方关闭后排空。 */
        auto NoTimeoutWhenActive(MemoryRelayFixture Relay) -> Net::awaitable<void>
        {
            StartRelay({Relay.State, Relay.Inbound, Relay.Outbound,
                        std::chrono::milliseconds(100), {}});

            // 立即首包（Relay 启动后马上有活动，避免初始超时窗口）
            const std::string FirstMessage = "FirstMessage";
            std::error_code WriteError;
            const auto FirstWrite = co_await Relay.Client->WriteSome(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(FirstMessage.data()),
                                           FirstMessage.size()));
            WriteError = Prism::Fault::ToNative(FirstWrite.Failure);
            std::array<std::byte, 64> Buffer{};
            std::error_code ReadError;
            const auto InitialRead = co_await Relay.Server->ReadSome(std::span<std::byte>(Buffer));
            ReadError = Prism::Fault::ToNative(InitialRead.Failure);
            const auto InitialCount = InitialRead.Bytes;
            EXPECT_GT(InitialCount, 0);

            // 持续活动（每 20ms 发一次，共 160ms > 超时 100ms）
            for (int Index = 0; Index < 8; ++Index)
            {
                const std::string Message = "keepalive-" + std::to_string(Index);
                const auto Write = co_await Relay.Client->WriteSome(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Message.data()),
                                               Message.size()));
                WriteError = Prism::Fault::ToNative(Write.Failure);
                const auto Read = co_await Relay.Server->ReadSome(std::span<std::byte>(Buffer));
                ReadError = Prism::Fault::ToNative(Read.Failure);
                const auto Count = Read.Bytes;
                EXPECT_GT(Count, 0);
                Net::steady_timer Timer(IoContext_);
                Timer.expires_after(std::chrono::milliseconds(20));
                co_await Timer.async_wait(Net::use_awaitable);
            }
            (void)Relay.Client->Close();
            (void)Relay.Server->Close();
            const auto Completed = co_await WaitForRelay(
                {Relay.State, {Relay.Client, Relay.Server, Relay.Inbound, Relay.Outbound}});
            EXPECT_TRUE(Completed);
            EXPECT_FALSE(Relay.State->Failure);
            EXPECT_TRUE(Relay.State->Result.Succeeded());
        }

        /** @brief 验证零空闲阈值禁用超时并由显式双向关闭结束。 */
        auto ZeroDisablesTimeout(MemoryRelayFixture Relay) -> Net::awaitable<void>
        {
            StartRelay({Relay.State, Relay.Inbound, Relay.Outbound,
                        std::chrono::milliseconds(0), {}});
            // 等 200ms（若超时未禁用，已关闭）
            Net::steady_timer Timer(IoContext_);
            Timer.expires_after(std::chrono::milliseconds(200));
            co_await Timer.async_wait(Net::use_awaitable);
            EXPECT_TRUE(Relay.Inbound->IsOpen());
            (void)Relay.Client->Close(); // 显式关闭入站发送方向
            (void)Relay.Server->Close(); // 显式关闭出站发送方向
            const auto Completed = co_await WaitForRelay(
                {Relay.State, {Relay.Client, Relay.Server, Relay.Inbound, Relay.Outbound}});
            EXPECT_TRUE(Completed);
            EXPECT_FALSE(Relay.State->Failure);
        }

        /** @brief 验证 Context timeout 优先于更长的 relay idle timeout。 */
        auto ContextTimeoutTakesPriority(MemoryRelayFixture Relay) -> Net::awaitable<void>
        {
            StartRelay({Relay.State, Relay.Inbound, Relay.Outbound,
                        std::chrono::seconds(300), std::chrono::milliseconds(40)});
            const auto Completed = co_await WaitForRelay(
                {Relay.State, {Relay.Client, Relay.Server, Relay.Inbound, Relay.Outbound}});
            EXPECT_TRUE(Completed);
            EXPECT_FALSE(Relay.State->Failure);
            EXPECT_EQ(Relay.State->Result.Code, Prism::Fault::Code::Timeout);
        }

        /** @brief 验证 outbound 对端关闭后的写失败立即结束 relay。 */
        auto WriteFailureTerminatesTunnel(MemoryRelayFixture Relay) -> Net::awaitable<void>
        {
            StartRelay({Relay.State, Relay.Inbound, Relay.Outbound,
                        std::chrono::milliseconds(0), {}});

            // 关闭 Outbound 对端（OutputPeer）→ Relay 写 RelayOutput 失败 → 隧道终止
            (void)Relay.Server->Close();
            const std::string Message = "to-dead-peer";
            std::error_code WriteError;
            const auto Write = co_await Relay.Client->WriteSome(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Message.data()),
                                           Message.size()));
            WriteError = Prism::Fault::ToNative(Write.Failure);
            const auto Completed = co_await WaitForRelay(
                {Relay.State, {Relay.Client, Relay.Server, Relay.Inbound, Relay.Outbound}});
            EXPECT_TRUE(Completed);
            EXPECT_FALSE(Relay.State->Failure);
            EXPECT_EQ(Relay.State->Result.Code, Prism::Fault::Code::ConnectionAborted);
        }

        /** @brief 验证 mock 写失败返回 IoError 并关闭两个 transport。 */
        auto WriteFailureReturnsIoError(MockRelayFixture RelayFixture) -> Net::awaitable<void>
        {
            const auto Inbound = RelayFixture.Inbound;
            const auto Outbound = RelayFixture.Outbound;
            Prism::Fault::Failure Result{};

            Net::post(IoContext_, [Inbound]
                      { Inbound->InjectRead({0x01U, 0x02U, 0x03U}); });
            Prism::Middleware::Context Context;
            Context.Inbound() = Inbound;
            Context.Outbound = Outbound;
            Context.Bytes = RelayFixture.State->Bytes;
            Prism::Middleware::Builtin::RelayMiddleware Relay(
                nullptr, std::chrono::milliseconds(0));
            auto Input = Context.Inbound();
            Result = co_await Relay.Handle(Input, Context);

            EXPECT_EQ(Result.Code, Prism::Fault::Code::IoError);
            EXPECT_TRUE(Inbound->IsClosed());
            EXPECT_TRUE(Outbound->IsClosed());
        }

        /** @brief 验证 partial read 后的 timeout 不是清洁 half-close。 */
        auto PartialReadWithErrorIsNotCleanHalfClose(MockRelayFixture RelayFixture)
            -> Net::awaitable<void>
        {
            const auto Inbound = RelayFixture.Inbound;
            const auto Outbound = RelayFixture.Outbound;
            Prism::Fault::Failure Result{};

            Prism::Middleware::Context Context;
            Context.Inbound() = Inbound;
            Context.Outbound = Outbound;
            Context.Bytes = RelayFixture.State->Bytes;
            Prism::Middleware::Builtin::RelayMiddleware Relay(
                nullptr, std::chrono::milliseconds(0));
            auto Input = Context.Inbound();
            Result = co_await Relay.Handle(Input, Context);

            EXPECT_EQ(Result.Code, Prism::Fault::Code::Timeout);
            EXPECT_EQ(Result.Native, std::make_error_code(std::errc::timed_out));
            EXPECT_EQ(Outbound->Written, (std::vector<std::uint8_t>{0x01U, 0x02U, 0x03U}));
            EXPECT_TRUE(Inbound->IsClosed());
            EXPECT_TRUE(Outbound->IsClosed());
        }

        /** @brief 验证 partial write 超时关闭 relay 两个方向。 */
        auto PartialWriteWithErrorClosesRelay(MockRelayFixture RelayFixture)
            -> Net::awaitable<void>
        {
            const auto Inbound = RelayFixture.Inbound;
            const auto Outbound = RelayFixture.Outbound;
            Prism::Fault::Failure Result{};

            Prism::Middleware::Context Context;
            Context.Inbound() = Inbound;
            Context.Outbound = Outbound;
            Context.Bytes = RelayFixture.State->Bytes;
            Prism::Middleware::Builtin::RelayMiddleware Relay(
                nullptr, std::chrono::milliseconds(0));
            auto Input = Context.Inbound();
            Result = co_await Relay.Handle(Input, Context);

            EXPECT_EQ(Result.Code, Prism::Fault::Code::Timeout);
            EXPECT_EQ(Result.Native, std::make_error_code(std::errc::timed_out));
            EXPECT_EQ(Outbound->Written, (std::vector<std::uint8_t>{0x11U, 0x12U, 0x13U}));
            EXPECT_TRUE(Inbound->IsClosed());
            EXPECT_TRUE(Outbound->IsClosed());
        }

        /** @brief 验证同时上传和下载均完整传输后再关闭并排空 relay。 */
        auto ConcurrentBidirectionalTransfer(MemoryRelayFixture Relay) -> Net::awaitable<void>
        {
            StartRelay({Relay.State, Relay.Inbound, Relay.Outbound,
                        std::chrono::milliseconds(0), {}});

            const std::string Uplink = "Uplink payload with Input different length";
            const std::string Downlink = "Downlink";
            std::error_code WriteError;
            const auto UplinkWrite = co_await Relay.Client->WriteSome(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Uplink.data()),
                                           Uplink.size()));
            WriteError = Prism::Fault::ToNative(UplinkWrite.Failure);
            const auto DownlinkWrite = co_await Relay.Server->WriteSome(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Downlink.data()),
                                           Downlink.size()));
            WriteError = Prism::Fault::ToNative(DownlinkWrite.Failure);
            EXPECT_FALSE(WriteError);

            std::string ReceivedUplink(Uplink.size(), '\0');
            std::string ReceivedDownlink(Downlink.size(), '\0');
            std::error_code ReadEc;
            const auto UplinkRead = co_await Relay.Server->ReadExact(
                std::span<std::byte>(reinterpret_cast<std::byte *>(ReceivedUplink.data()),
                                     ReceivedUplink.size()));
            ReadEc = Prism::Fault::ToNative(UplinkRead.Failure);
            const auto UplinkCount = UplinkRead.Bytes;
            EXPECT_FALSE(ReadEc);
            EXPECT_EQ(UplinkCount, Uplink.size());
            EXPECT_EQ(ReceivedUplink, Uplink);

            const auto DownlinkRead = co_await Relay.Client->ReadExact(
                std::span<std::byte>(reinterpret_cast<std::byte *>(ReceivedDownlink.data()),
                                     ReceivedDownlink.size()));
            ReadEc = Prism::Fault::ToNative(DownlinkRead.Failure);
            const auto DownlinkCount = DownlinkRead.Bytes;
            EXPECT_FALSE(ReadEc);
            EXPECT_EQ(DownlinkCount, Downlink.size());
            EXPECT_EQ(ReceivedDownlink, Downlink);

            (void)Relay.Client->Close();
            (void)Relay.Server->Close();
            const auto Completed = co_await WaitForRelay(
                {Relay.State, {Relay.Client, Relay.Server, Relay.Inbound, Relay.Outbound}});
            EXPECT_TRUE(Completed);
            EXPECT_FALSE(Relay.State->Failure);
        }

        /** @brief 验证请求方向半关闭后，反向响应仍可传输且最终收到 EOF。 */
        auto HalfCloseKeepsReverseDirection(MemoryRelayFixture Relay) -> Net::awaitable<void>
        {
            StartRelay({Relay.State, Relay.Inbound, Relay.Outbound,
                        std::chrono::milliseconds(0), {}});

            const std::string Request = "Request before half Close";
            const std::string Response = "response after half Close";
            std::error_code ErrorCode;
            const auto RequestWrite = co_await Relay.Client->WriteSome(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.data()),
                                           Request.size()));
            ErrorCode = Prism::Fault::ToNative(RequestWrite.Failure);
            (void)co_await Relay.Client->WriteShutdown();

            std::string ReceivedRequest(Request.size(), '\0');
            const auto RequestRead = co_await Relay.Server->ReadExact(
                std::span<std::byte>(reinterpret_cast<std::byte *>(ReceivedRequest.data()),
                                     ReceivedRequest.size()));
            ErrorCode = Prism::Fault::ToNative(RequestRead.Failure);
            const auto RequestCount = RequestRead.Bytes;
            EXPECT_FALSE(ErrorCode);
            EXPECT_EQ(RequestCount, Request.size());
            EXPECT_EQ(ReceivedRequest, Request);

            const auto ResponseWrite = co_await Relay.Server->WriteSome(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Response.data()),
                                           Response.size()));
            ErrorCode = Prism::Fault::ToNative(ResponseWrite.Failure);
            (void)co_await Relay.Server->WriteShutdown();

            std::string ReceivedResponse(Response.size(), '\0');
            const auto ResponseRead = co_await Relay.Client->ReadExact(
                std::span<std::byte>(reinterpret_cast<std::byte *>(ReceivedResponse.data()),
                                     ReceivedResponse.size()));
            ErrorCode = Prism::Fault::ToNative(ResponseRead.Failure);
            const auto ResponseCount = ResponseRead.Bytes;
            EXPECT_FALSE(ErrorCode);
            EXPECT_EQ(ResponseCount, Response.size());
            EXPECT_EQ(ReceivedResponse, Response);

            std::array<std::byte, 1> EofBuffer{};
            const auto EofRead = co_await Relay.Client->ReadSome(EofBuffer);
            // 旧 read_some 在对端半关闭时清空错误码并返回 0 字节；新前门把清洁 EOF 作为正式
            // Code::Eof 报告，这里保留原断言「读方向干净结束即无错误」的语义。
            if (EofRead.Failure.Code == Prism::Fault::Code::Eof)
            {
                ErrorCode.clear();
            }
            else
            {
                ErrorCode = Prism::Fault::ToNative(EofRead.Failure);
            }
            const auto EofCount = EofRead.Bytes;
            EXPECT_FALSE(ErrorCode);
            EXPECT_EQ(EofCount, 0U);

            const auto Completed = co_await WaitForRelay(
                {Relay.State, {Relay.Client, Relay.Server, Relay.Inbound, Relay.Outbound}});
            EXPECT_TRUE(Completed);
            EXPECT_FALSE(Relay.State->Failure);
            EXPECT_FALSE(Relay.State->DirectionFailure[0].Failed() ||
                         Relay.State->DirectionFailure[1].Failed());
        }

    private:
        Net::io_context IoContext_;
    };

    TEST(TimeoutRelay, IdleTimeoutClosesTunnel)
    {
        TimeoutRelayFixture Fixture;
        Fixture.Run(Fixture.IdleTimeoutClosesTunnel(Fixture.MakeMemoryRelayFixture()));
    }

    TEST(TimeoutRelay, NoTimeoutWhenActive)
    {
        TimeoutRelayFixture Fixture;
        Fixture.Run(Fixture.NoTimeoutWhenActive(Fixture.MakeMemoryRelayFixture()));
    }

    TEST(TimeoutRelay, ZeroDisablesTimeout)
    {
        TimeoutRelayFixture Fixture;
        Fixture.Run(Fixture.ZeroDisablesTimeout(Fixture.MakeMemoryRelayFixture()));
    }

    TEST(TimeoutRelay, ContextTimeoutTakesPriority)
    {
        TimeoutRelayFixture Fixture;
        Fixture.Run(Fixture.ContextTimeoutTakesPriority(Fixture.MakeMemoryRelayFixture()));
    }

    TEST(TimeoutRelay, WriteFailureTerminatesTunnel)
    {
        TimeoutRelayFixture Fixture;
        Fixture.Run(Fixture.WriteFailureTerminatesTunnel(Fixture.MakeMemoryRelayFixture()));
    }

    TEST(TimeoutRelay, WriteFailureReturnsIoError)
    {
        TimeoutRelayFixture Fixture;
        auto Relay = Fixture.MakeMockRelayFixture();
        Relay.Outbound->FailNextWrite = true;
        Fixture.Run(Fixture.WriteFailureReturnsIoError(std::move(Relay)));
    }

    TEST(TimeoutRelay, PartialReadWithErrorIsNotCleanHalfClose)
    {
        TimeoutRelayFixture Fixture;
        auto Relay = Fixture.MakeMockRelayFixture();
        Relay.Inbound->ToRead = {0x01U, 0x02U, 0x03U};
        Relay.Inbound->ReadErrorBytes = 3;
        Relay.Inbound->SetReadError(std::make_error_code(std::errc::timed_out));
        Relay.Outbound->EofOnDrain = true;
        Fixture.Run(Fixture.PartialReadWithErrorIsNotCleanHalfClose(std::move(Relay)));
    }

    TEST(TimeoutRelay, PartialWriteWithErrorClosesRelay)
    {
        TimeoutRelayFixture Fixture;
        auto Relay = Fixture.MakeMockRelayFixture();
        Relay.Inbound->ToRead = {0x11U, 0x12U, 0x13U};
        Relay.Inbound->EofOnDrain = true;
        Relay.Outbound->WriteErrorBytes = 3;
        Relay.Outbound->SetWriteError(std::make_error_code(std::errc::timed_out));
        Fixture.Run(Fixture.PartialWriteWithErrorClosesRelay(std::move(Relay)));
    }

    TEST(TimeoutRelay, ConcurrentBidirectionalTransfer)
    {
        TimeoutRelayFixture Fixture;
        Fixture.Run(Fixture.ConcurrentBidirectionalTransfer(Fixture.MakeMemoryRelayFixture()));
    }

    TEST(TimeoutRelay, HalfCloseKeepsReverseDirection)
    {
        TimeoutRelayFixture Fixture;
        Fixture.Run(Fixture.HalfCloseKeepsReverseDirection(Fixture.MakeMemoryRelayFixture()));
    }

} // namespace
