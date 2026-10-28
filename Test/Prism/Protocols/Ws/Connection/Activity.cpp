/**
 * @file Activity.cpp
 * @brief 验证成功 WebSocket 建连返回的活动回执覆盖已接收下层 owner。
 */
#include "../Admission/FactorySupport.hpp"
#include "SessionSupport.hpp"
#include <boost/asio/io_context.hpp>
#include <boost/asio/this_coro.hpp>
#include <atomic>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Protocols/Ws/Ws.hpp>
#include <Prism/Transport/ActivityGroupFactory.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Ws = Prism::Ws;
    namespace TestSupport = Prism::Tests::WsConnSessionSupport;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using TestSupport::RunCoro;
    using TestSupport::SpawnEager;
    using TestSupport::StreamPairRequest;
    using TestSupport::TestKey;
    using TestSupport::WaitEager;

    /**
     * @brief 模拟已接收的排队 writer，其历史错误与物理退休相互独立。
     */
    class PendingWriterReceipt final : public Prism::Contract::CarrierActivity
    {
    public:
        explicit PendingWriterReceipt(Net::any_io_executor Executor)
            : Executor_(std::move(Executor))
        {
        }

        auto Seal() noexcept -> void override
        {
            Sealed_.store(true, std::memory_order_release);
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Sealed_.load(std::memory_order_acquire) &&
                   CloseDelivered_.load(std::memory_order_acquire) &&
                   QueueRetired_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            Seal();
            if (!IsRetired())
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }

        auto MarkCloseDelivered() noexcept -> void
        {
            CloseDelivered_.store(true, std::memory_order_release);
        }

        auto RetireQueuedWrite() noexcept -> void
        {
            QueueRetired_.store(true, std::memory_order_release);
        }

    private:
        Net::any_io_executor Executor_;
        std::atomic<bool> Sealed_{false};
        std::atomic<bool> CloseDelivered_{false};
        std::atomic<bool> QueueRetired_{false};
    };

    /**
     * @brief 带独立排队 writer 回执的已接收传输测试 owner。
     * @details 关闭实际委托给底层 MemoryStream；排队 writer 的历史错误只从 Drain 返回，
     *          物理完成则由 PendingWriterReceipt::IsRetired 独立报告。
     */
    class AcceptedTransport final : public Prism::Transmission
    {
    public:
        AcceptedTransport(
            std::shared_ptr<Prism::Transmission> Upstream,
            std::shared_ptr<PendingWriterReceipt> Receipt)
            : Prism::Transmission(Upstream->Executor()),
              Upstream_(std::move(Upstream)),
              Receipt_(std::move(Receipt)),
              Activity_(Prism::Transport::MakeActivityGroup(
                  Prism::Transmission::Activity(),
                  std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>>{
                      Upstream_->Activity(), Receipt_}))
        {
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto NextLayer() noexcept
            -> Prism::Transmission * override
        {
            return Upstream_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept
            -> const Prism::Transmission * override
        {
            return Upstream_.get();
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler)
            -> void override
        {
            Upstream_->ReadSome(Buffer, std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler)
            -> void override
        {
            Upstream_->WriteSome(Buffer, std::move(Handler));
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Upstream_->WriteShutdown(std::move(Handler));
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            const auto Result = Upstream_->Close();
            if (Result)
            {
                Receipt_->MarkCloseDelivered();
            }
            return Result;
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return Upstream_->Cancel();
        }

    private:
        std::shared_ptr<Prism::Transmission> Upstream_;
        std::shared_ptr<PendingWriterReceipt> Receipt_;
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity_;
    };

    /** @brief 完成真实 WebSocket 服务端 Upgrade 并交付连接 owner。 */
    auto AcceptWebSocket(
        std::shared_ptr<Prism::Transmission> Server,
        std::shared_ptr<std::shared_ptr<Ws::StreamTransport>> Result)
        -> Net::awaitable<void>
    {
        auto Accepted = co_await Ws::Accept(
            Ws::AcceptOptions{
                Server,
                Prism::Tests::WsFactorySupport::WebSocketTestBytes(),
                Ws::ServerOptions{}});
        EXPECT_TRUE(Accepted);
        if (!Accepted)
        {
            co_return;
        }
        EXPECT_EQ(Accepted->Key, TestKey);
        *Result = std::move(Accepted->Connection);
    }

    /** @brief 对客户端与服务端成功返回的连接核对下层物理退休回执。 */
    auto RunAcceptedActivityReceipt(StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto ClientMemory = std::make_shared<MemoryStream>(
            std::move(Request.Client));
        auto ServerMemory = std::make_shared<MemoryStream>(
            std::move(Request.Server));
        auto ClientReceipt = std::make_shared<PendingWriterReceipt>(
            ClientMemory->Executor());
        auto ServerReceipt = std::make_shared<PendingWriterReceipt>(
            ServerMemory->Executor());
        auto ClientOwner = std::make_shared<AcceptedTransport>(
            ClientMemory, ClientReceipt);
        auto ServerOwner = std::make_shared<AcceptedTransport>(
            ServerMemory, ServerReceipt);
        auto ServerConnection =
            std::make_shared<std::shared_ptr<Ws::StreamTransport>>();
        auto ServerTask = SpawnEager(
            ServerOwner->Executor(),
            AcceptWebSocket(ServerOwner, ServerConnection));

        const Ws::ClientOptions ClientOptions{"example.com", TestKey};
        auto Connected = co_await Ws::Connect(Ws::ConnectOptions{
            ClientOwner,
            Prism::Tests::WsFactorySupport::WebSocketTestBytes(),
            ClientOptions});
        co_await WaitEager(std::move(ServerTask));
        EXPECT_TRUE(Connected);
        EXPECT_TRUE(*ServerConnection);
        if (!Connected || !*ServerConnection)
        {
            const auto ClientClose = ClientOwner->Close();
            EXPECT_TRUE(ClientClose);
            const auto ServerClose = ServerOwner->Close();
            EXPECT_TRUE(ServerClose);
            ClientReceipt->RetireQueuedWrite();
            ServerReceipt->RetireQueuedWrite();
            (void)co_await ClientOwner->Activity()->Drain();
            (void)co_await ServerOwner->Activity()->Drain();
            co_return;
        }

        auto ClientConnection = std::move(Connected->Connection);
        auto ServerConnectionOwner = std::move(*ServerConnection);
        const auto ClientActivity = ClientConnection->Activity();
        const auto ServerActivity = ServerConnectionOwner->Activity();
        EXPECT_FALSE(ClientActivity->IsRetired());
        EXPECT_FALSE(ServerActivity->IsRetired());

        const auto ClientClose = ClientConnection->Close();
        EXPECT_TRUE(ClientClose);
        const auto ServerClose = ServerConnectionOwner->Close();
        EXPECT_TRUE(ServerClose);
        EXPECT_FALSE(ClientActivity->IsRetired());
        EXPECT_FALSE(ServerActivity->IsRetired());

        const auto PendingClientDrain = co_await ClientActivity->Drain();
        const auto PendingServerDrain = co_await ServerActivity->Drain();
        EXPECT_FALSE(PendingClientDrain);
        EXPECT_FALSE(PendingServerDrain);
        if (!PendingClientDrain)
        {
            EXPECT_EQ(PendingClientDrain.error().Code,
                      Prism::Fault::Code::Blocked);
        }
        if (!PendingServerDrain)
        {
            EXPECT_EQ(PendingServerDrain.error().Code,
                      Prism::Fault::Code::Blocked);
        }
        EXPECT_FALSE(ClientActivity->IsRetired());
        EXPECT_FALSE(ServerActivity->IsRetired());

        ClientReceipt->RetireQueuedWrite();
        ServerReceipt->RetireQueuedWrite();
        const auto ClientDrain = co_await ClientActivity->Drain();
        const auto ServerDrain = co_await ServerActivity->Drain();
        EXPECT_FALSE(ClientDrain);
        EXPECT_FALSE(ServerDrain);
        if (!ClientDrain)
        {
            EXPECT_EQ(ClientDrain.error().Code,
                      Prism::Fault::Code::ResourceUnavailable);
        }
        if (!ServerDrain)
        {
            EXPECT_EQ(ServerDrain.error().Code,
                      Prism::Fault::Code::ResourceUnavailable);
        }
        EXPECT_TRUE(ClientActivity->IsRetired());
        EXPECT_TRUE(ServerActivity->IsRetired());

        const auto ClientReleased = ClientConnection->Release();
        const auto ServerReleased = ServerConnectionOwner->Release();
        EXPECT_EQ(ClientReleased.get(), ClientOwner.get());
        EXPECT_EQ(ServerReleased.get(), ServerOwner.get());
    }

    TEST(WsConnSession, AcceptedTransportActivityTracksPhysicalRetirement)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunAcceptedActivityReceipt(
                               StreamPairRequest{
                                   std::move(Client), std::move(Server)}));
    }
}
