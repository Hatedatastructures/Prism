/**
 * @file WsConnResource.cpp
 * @brief 验证 WebSocket 掩码写入的资源失败与取消退栈。
 */
#include "WsConnSessionSupport.hpp"
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <array>
#include <atomic>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Ws/Ws.hpp>
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
    using TestSupport::TestKey;    using PendingWriteSignal =
        Net::experimental::channel<void(boost::system::error_code)>;

    /**
     * @brief 握手后可挂起真实类型化写操作的测试下层。
     * @details 读写半关闭与最终关闭继续委托实际 MemoryStream；闸门只控制一笔写，
     *          Cancel/Close 以 Canceled 恰好完成该笔操作，不伪造成功或替代 WS 帧逻辑。
     */
    class PendingWriteTransmission final : public Prism::Transmission
    {
    public:
        explicit PendingWriteTransmission(
            std::shared_ptr<Prism::Transmission> Upstream)
            : Prism::Transmission(Upstream->Executor()),
              Upstream_(std::move(Upstream)),
              PendingWriteReady_(Upstream_->Executor(), 1)
        {
        }

        auto ArmWriteGate() noexcept -> void
        {
            HoldWrites_.store(true, std::memory_order_release);
        }

        auto WaitForPendingWrite() -> Net::awaitable<void>
        {
            (void)co_await PendingWriteReady_.async_receive(Net::use_awaitable);
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
        auto StartRead(
            std::span<std::byte> Buffer,
            Completion Handler) -> void override
        {
            Upstream_->ReadSome(Buffer, std::move(Handler));
        }

        auto StartWrite(
            std::span<const std::byte> Buffer,
            Completion Handler) -> void override
        {
            if (!HoldWrites_.load(std::memory_order_acquire))
            {
                Upstream_->WriteSome(Buffer, std::move(Handler));
                return;
            }
            if (PendingWrite_)
            {
                Prism::Transport::Detail::PostResult(
                    Executor(), std::move(Handler),
                    Prism::IoResult{0, {Prism::Fault::Code::WouldBlock}});
                return;
            }
            PendingWrite_.emplace(std::move(Handler));
            (void)PendingWriteReady_.try_send(boost::system::error_code{});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Upstream_->WriteShutdown(std::move(Handler));
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            CompletePendingWrite(
                Prism::IoResult{0, {Prism::Fault::Code::Canceled}});
            return Upstream_->Close();
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            CompletePendingWrite(
                Prism::IoResult{0, {Prism::Fault::Code::Canceled}});
            return Upstream_->Cancel();
        }

    private:
        auto CompletePendingWrite(Prism::IoResult Result) -> void
        {
            if (!PendingWrite_)
            {
                return;
            }
            auto Handler = std::move(*PendingWrite_);
            PendingWrite_.reset();
            Prism::Transport::Detail::PostResult(
                Executor(), std::move(Handler), std::move(Result));
        }

        std::shared_ptr<Prism::Transmission> Upstream_;
        PendingWriteSignal PendingWriteReady_;
        std::atomic_bool HoldWrites_{false};
        std::optional<Completion> PendingWrite_;
    };

    /** @brief 用显式服务端池完成 Upgrade 并返回真实协议连接 owner。 */
    auto AcceptWsForResourceTest(
        Ws::AcceptOptions Input,
        std::shared_ptr<std::shared_ptr<Ws::StreamTransport>> Result)
        -> Net::awaitable<void>
    {
        auto Accepted = co_await Ws::Accept(std::move(Input));
        EXPECT_TRUE(Accepted);
        if (!Accepted)
        {
            co_return;
        }
        EXPECT_EQ(Accepted->Key, TestKey);
        *Result = std::move(Accepted->Connection);
    }

    /** @brief 池耗尽拒绝 masked frame 前门且检查 peer 收到零帧字节。 */
    auto RunMaskedPoolExhaustion(StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto ClientBytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{1024U, 1U});
        auto ServerBytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{1024U, 1U});
        auto HeldLease = ClientBytes->TryAcquire(1U);
        if (!HeldLease)
        {
            ADD_FAILURE() << "单块测试池未能建立占用租约";
            co_return;
        }

        auto ServerConnection = std::make_shared<std::shared_ptr<Ws::StreamTransport>>();
        auto ServerTask = SpawnEager(
            Server->Executor(),
            AcceptWsForResourceTest(
                Ws::AcceptOptions{Server, ServerBytes, Ws::ServerOptions{}},
                ServerConnection));
        auto ClientResult = co_await Ws::Connect(
            Ws::ConnectOptions{
                Client, ClientBytes, Ws::ClientOptions{"example.com", TestKey}});
        co_await TestSupport::WaitEager(std::move(ServerTask));
        EXPECT_TRUE(ClientResult);
        std::shared_ptr<Ws::StreamTransport> ClientConnection;
        if (ClientResult)
        {
            ClientConnection = std::move(ClientResult->Connection);
        }
        if (!ClientConnection || !*ServerConnection)
        {
            ADD_FAILURE() << "资源拒绝场景的 Upgrade 未完成";
            const auto ClientClose = Client->Close();
            EXPECT_TRUE(ClientClose);
            const auto ServerClose = Server->Close();
            EXPECT_TRUE(ServerClose);
            co_return;
        }

        const std::string Payload = "client mask wire payload";
        const auto Write = co_await ClientConnection->WriteSome(
            Prism::AsBytes(Prism::AsU8Span(Payload)));
        EXPECT_EQ(Write.Bytes, 0U);
        EXPECT_EQ(Write.Failure.Code, Prism::Fault::Code::ResourceUnavailable);
        const auto ExpectedFailure = Prism::Fault::make_error_code(
            Prism::Fault::Code::ResourceUnavailable);
        EXPECT_EQ(Write.Failure.Native.category(), ExpectedFailure.category());
        EXPECT_EQ(Write.Failure.Native.value(), ExpectedFailure.value());
        EXPECT_EQ(ClientBytes->AvailableBlocks(), 0U);
        EXPECT_EQ(ClientBytes->UsedBytes(), ClientBytes->BlockSize());

        const auto ClientDrain = co_await ClientConnection->Activity()->Drain();
        EXPECT_TRUE(ClientDrain);
        const auto CarrierDrain = co_await Client->Activity()->Drain();
        EXPECT_TRUE(CarrierDrain);
        EXPECT_FALSE(Client->IsOpen());

        std::array<std::byte, 32> PeerFrame{};
        const auto PeerRead = co_await Server->ReadSome(PeerFrame);
        EXPECT_EQ(PeerRead.Bytes, 0U);
        EXPECT_EQ(PeerRead.Failure.Code, Prism::Fault::Code::Eof);

        const auto ServerClose = (*ServerConnection)->Close();
        EXPECT_TRUE(ServerClose);
        const auto ServerDrain =
            co_await (*ServerConnection)->Activity()->Drain();
        EXPECT_TRUE(ServerDrain);
        const auto ServerCarrierDrain = co_await Server->Activity()->Drain();
        EXPECT_TRUE(ServerCarrierDrain);
        HeldLease->Release();
        EXPECT_EQ(ClientBytes->AvailableBlocks(), 1U);
    }

    /** @brief 取消挂起帧头写，丢弃外部 Conn 句柄并检查两层退栈。 */
    auto RunCanceledPendingMaskedWrite(StreamPairRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        auto Gated = std::make_shared<PendingWriteTransmission>(Client);
        auto ClientBytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{1024U, 1U});
        auto ServerBytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{1024U, 1U});
        auto ServerConnection = std::make_shared<std::shared_ptr<Ws::StreamTransport>>();
        auto ServerTask = SpawnEager(
            Server->Executor(),
            AcceptWsForResourceTest(
                Ws::AcceptOptions{Server, ServerBytes, Ws::ServerOptions{}},
                ServerConnection));
        auto ClientResult = co_await Ws::Connect(
            Ws::ConnectOptions{
                Gated, ClientBytes, Ws::ClientOptions{"example.com", TestKey}});
        co_await TestSupport::WaitEager(std::move(ServerTask));
        EXPECT_TRUE(ClientResult);
        std::shared_ptr<Ws::StreamTransport> ClientConnection;
        if (ClientResult)
        {
            ClientConnection = std::move(ClientResult->Connection);
        }
        if (!ClientConnection || !*ServerConnection)
        {
            ADD_FAILURE() << "挂起写场景的 Upgrade 未完成";
            const auto ClientClose = Gated->Close();
            EXPECT_TRUE(ClientClose);
            const auto ServerClose = Server->Close();
            EXPECT_TRUE(ServerClose);
            co_return;
        }

        Gated->ArmWriteGate();
        const std::array<std::byte, 8> Payload{
            std::byte{'m'}, std::byte{'a'}, std::byte{'s'}, std::byte{'k'},
            std::byte{'e'}, std::byte{'d'}, std::byte{'!'}, std::byte{'!'}};
        auto WriteDone = std::make_shared<TestSupport::CompletionChannel>(
            ClientConnection->Executor(), 1);
        auto CompletionCount = std::make_shared<std::atomic_size_t>(0U);
        auto WriteResult = std::make_shared<Prism::IoResult>();
        ClientConnection->WriteSome(
            std::span<const std::byte>(Payload),
            [WriteDone, CompletionCount, WriteResult](Prism::IoResult Result)
            {
                CompletionCount->fetch_add(1U, std::memory_order_relaxed);
                *WriteResult = Result;
                (void)WriteDone->try_send(boost::system::error_code{});
            });
        co_await Gated->WaitForPendingWrite();
        EXPECT_EQ(ClientBytes->AvailableBlocks(), 0U);
        EXPECT_EQ(ClientBytes->UsedBytes(), ClientBytes->BlockSize());

        auto ClientActivity = ClientConnection->Activity();
        std::weak_ptr<Ws::Detail::StreamOwner<>> WeakConnection = ClientConnection;
        const auto CancelResult = ClientConnection->Cancel();
        EXPECT_TRUE(CancelResult);
        if (!CancelResult)
        {
            const auto CloseResult = ClientConnection->Close();
            EXPECT_TRUE(CloseResult);
        }
        ClientConnection.reset();
        EXPECT_FALSE(WeakConnection.expired());

        (void)co_await WriteDone->async_receive(Net::use_awaitable);
        EXPECT_EQ(CompletionCount->load(std::memory_order_relaxed), 1U);
        EXPECT_EQ(WriteResult->Bytes, 0U);
        EXPECT_EQ(WriteResult->Failure.Code, Prism::Fault::Code::Canceled);
        const auto ClientDrain = co_await ClientActivity->Drain();
        EXPECT_TRUE(ClientDrain);
        const auto GateDrain = co_await Gated->Activity()->Drain();
        EXPECT_TRUE(GateDrain);
        const auto CarrierDrain = co_await Client->Activity()->Drain();
        EXPECT_TRUE(CarrierDrain);
        EXPECT_EQ(CompletionCount->load(std::memory_order_relaxed), 1U);
        EXPECT_EQ(ClientBytes->AvailableBlocks(), 1U);
        EXPECT_EQ(ClientBytes->UsedBytes(), 0U);
        EXPECT_TRUE(WeakConnection.expired());
        EXPECT_FALSE(Gated->IsOpen());

        std::array<std::byte, 32> PeerFrame{};
        const auto PeerRead = co_await Server->ReadSome(PeerFrame);
        EXPECT_EQ(PeerRead.Bytes, 0U);
        EXPECT_EQ(PeerRead.Failure.Code, Prism::Fault::Code::Eof);
        const auto ServerClose = (*ServerConnection)->Close();
        EXPECT_TRUE(ServerClose);
        const auto ServerDrain =
            co_await (*ServerConnection)->Activity()->Drain();
        EXPECT_TRUE(ServerDrain);
        const auto ServerCarrierDrain = co_await Server->Activity()->Drain();
        EXPECT_TRUE(ServerCarrierDrain);
    }

    TEST(WsConnSession, MaskedWriteResourceFailureLeavesNoFrame)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunMaskedPoolExhaustion(
                               StreamPairRequest{std::move(Client), std::move(Server)}));
    }

    TEST(WsConnSession, PendingMaskedWriteCancelRetiresLeaseAndOwner)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunCanceledPendingMaskedWrite(
                               StreamPairRequest{std::move(Client), std::move(Server)}));
    }
}
