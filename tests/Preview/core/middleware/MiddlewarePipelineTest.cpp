/**
 * @file MiddlewarePipelineTest.cpp
 * @brief 中间件管线联通性测试
 * @details 验证 Middleware 管线（Dial → relay）在内存流上
 * 的数据转发正确性：
 * 1. DialMiddleware 注入内存"上游"
 * 2. RelayMiddleware 双向转发
 * 3. 客户端写入数据 → 经管线 → 上游收到；回显 → 客户端收到
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <algorithm>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Middleware/Pipeline.hpp>
#include <Preview/Runtime/Middleware/Builtin/Dial.hpp>
#include <Preview/Runtime/Middleware/Builtin/Relay.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Foundation/Fault/Code.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Preview::Fault;
    namespace Middleware = Preview::Middleware;
    namespace Network = Preview::Network;
    using Preview::SharedTransmission;
    using Preview::Transmission;

    /// Preview::Transport 内存 mock（成对传输）
    class MemoryTransport final : public Transmission
    {
    public:
        explicit MemoryTransport(Net::any_io_executor Executor) : Ex_(std::move(Executor))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            while (true)
            {
                if (!RecvBuffer_.empty())
                {
                    const auto BytesRead = (std::min)(Buffer.size(), RecvBuffer_.size());
                    std::memcpy(Buffer.data(), RecvBuffer_.data(), BytesRead);
                    RecvBuffer_.erase(RecvBuffer_.begin(),
                                     RecvBuffer_.begin() + static_cast<std::ptrdiff_t>(BytesRead));
                    ErrorCode.clear();
                    co_return BytesRead;
                }
                if (Closed_)
                {
                    ErrorCode = std::make_error_code(std::errc::broken_pipe);
                    co_return 0;
                }
                co_await Net::post(Ex_, Net::use_awaitable);
            }
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            if (!Peer_ || Closed_)
            {
                ErrorCode = std::make_error_code(std::errc::broken_pipe);
                co_return 0;
            }
            Peer_->RecvBuffer_.insert(Peer_->RecvBuffer_.end(), Buffer.begin(), Buffer.end());
            ErrorCode.clear();
            co_return Buffer.size();
        }

        void Close() override
        {
            Closed_ = true;
        }

        void Cancel() override
        {
        }

        void BindPeer(const std::shared_ptr<MemoryTransport> &Peer)
        {
            Peer_ = Peer;
        }

    private:
        Net::any_io_executor Ex_;                       ///< 执行器
        std::shared_ptr<MemoryTransport> Peer_;         ///< 对端
        std::vector<std::byte> RecvBuffer_;             ///< 接收缓冲（对端写入）
        bool Closed_{false};                            ///< 关闭标志
    };

    /// 回显上游：读到的数据原样写回
    auto EchoUpstream(SharedTransmission ClientSide)
        -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> Buffer{};
        std::error_code ErrorCode;
        while (true)
        {
            const auto BytesRead = co_await ClientSide->async_read_some(std::span<std::byte>(Buffer), ErrorCode);
            if (ErrorCode || BytesRead == 0)
            {
                break;
            }
            co_await ClientSide->async_write_some(
                std::span<const std::byte>(Buffer.data(), BytesRead), ErrorCode);
            if (ErrorCode)
            {
                break;
            }
        }
        ClientSide->Close();
    }

    TEST(MiddlewarePipeline, DialRelayEcho)
    {
        Net::io_context IoContext;
        std::exception_ptr Exception;
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // 客户端连接对：ClientSide（客户端）↔ Inbound（代理入站）
            auto ClientSide = std::make_shared<MemoryTransport>(IoContext.get_executor());
            auto Inbound = std::make_shared<MemoryTransport>(IoContext.get_executor());
            ClientSide->BindPeer(Inbound);
            Inbound->BindPeer(ClientSide);

            // 上游连接对：Outbound（代理出站）↔ Upstream（上游服务器）
            auto Outbound = std::make_shared<MemoryTransport>(IoContext.get_executor());
            auto Upstream = std::make_shared<MemoryTransport>(IoContext.get_executor());
            Outbound->BindPeer(Upstream);
            Upstream->BindPeer(Outbound);

            // 管线：Dial（注入已建立的 Outbound 作为"上游"）→ relay
            Middleware::Context Context;
            Context.Target.Positive = true;

            auto Dial = std::make_shared<Middleware::Builtin::DialMiddleware>(
                [Outbound](const Network::Target &) -> Net::awaitable<
                    std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return std::pair{Fault::Code::Success, Outbound};
                });

            Middleware::Pipeline Pipeline;
            Pipeline.Add(Dial).Add(std::make_shared<Middleware::Builtin::RelayMiddleware>(
                nullptr, std::chrono::milliseconds(100)));

            // 启动管线（detached，relay 内部跑隧道）
            Net::co_spawn(
                IoContext.get_executor(),
                [&Pipeline, Inbound, &Context]() -> Net::awaitable<void>
                {
                    co_await Pipeline.Run(Inbound, Context);
                },
                Net::detached);

            // 客户端写入 → 代理入站 → relay 上行 → 上游收到
            const std::string Payload = "Middleware Pipeline echo test";
            std::error_code WriteErrorCode;
            co_await ClientSide->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                           Payload.size()),
                WriteErrorCode);

            std::array<std::byte, 512> ServerBuffer{};
            std::error_code ServerErrorCode;
            std::size_t ServerTotal = 0;
            while (ServerTotal < Payload.size())
            {
                const auto BytesRead = co_await Upstream->async_read_some(
                    std::span<std::byte>(ServerBuffer.data() + ServerTotal, ServerBuffer.size() - ServerTotal), ServerErrorCode);
                if (ServerErrorCode || BytesRead == 0)
                {
                    break;
                }
                ServerTotal += BytesRead;
            }
            const std::string ServerPayload(reinterpret_cast<const char *>(ServerBuffer.data()), ServerTotal);
            EXPECT_EQ(ServerPayload, Payload);

            // 上游回写 → relay 下行 → 客户端收到
            std::error_code WriteErrorCode2;
            co_await Upstream->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                           Payload.size()),
                WriteErrorCode2);

            std::array<std::byte, 512> ClientBuffer{};
            std::error_code ReadErrorCode;
            std::size_t Total = 0;
            while (Total < Payload.size())
            {
                const auto BytesRead = co_await ClientSide->async_read_some(
                    std::span<std::byte>(ClientBuffer.data() + Total, ClientBuffer.size() - Total), ReadErrorCode);
                if (ReadErrorCode || BytesRead == 0)
                {
                    break;
                }
                Total += BytesRead;
            }

            const std::string Received(reinterpret_cast<const char *>(ClientBuffer.data()), Total);
            EXPECT_EQ(Received, Payload);

            ClientSide->Close();
            IoContext.stop();
        };

        Net::co_spawn(IoContext, Coroutine(), [&](std::exception_ptr e) { Exception = e; IoContext.stop(); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

} // namespace
