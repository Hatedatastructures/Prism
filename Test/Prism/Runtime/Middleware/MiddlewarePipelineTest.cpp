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
#include <boost/asio/deferred.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <algorithm>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Runtime/Middleware/Pipeline.hpp>
#include <Prism/Runtime/Middleware/Builtin/Dial.hpp>
#include <Prism/Runtime/Middleware/Builtin/Relay.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Foundation/Fault/Code.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Middleware = Prism::Middleware;
    namespace Network = Prism::Network;
    using Prism::SharedTransmission;
    using Prism::Transmission;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    /// Prism::Transport 内存 mock（成对传输）
    class MemoryTransport final : public Transmission
    {
    public:
        explicit MemoryTransport(Net::any_io_executor Executor)
            : Prism::Transmission(Executor), Ex_(std::move(Executor))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(ReadWork{}, Ex_), Handler,
                ReadInput{std::static_pointer_cast<MemoryTransport>(Prism::Transmission::shared_from_this()), Buffer});
        }

        /** @brief 旧同步写体原位保留；一次性投递正式结果，不引入协同帧。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code Error;
            std::size_t Count = 0;
            if (!Peer_ || Closed_)
            {
                Error = std::make_error_code(std::errc::broken_pipe);
            }
            else
            {
                Peer_->RecvBuffer_.insert(Peer_->RecvBuffer_.end(), Buffer.begin(), Buffer.end());
                Error.clear();
                Count = Buffer.size();
            }
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), Prism::IoResult{Count, Prism::Fault::FromNative(Error)});
        }

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际 inner 转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto *Inner = NextLayer())
            {
                Inner->WriteShutdown(std::move(Handler));
                return;
            }
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
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

        void BindPeer(const std::shared_ptr<MemoryTransport> &Peer)
        {
            Peer_ = Peer;
        }

    private:
        struct ReadInput final
        {
            std::shared_ptr<MemoryTransport> Owner;
            std::span<std::byte> Buffer;
        };
        /** @brief 原协程体原位保留，新前门一次性映射正式结果。 */
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                co_return std::tuple{co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadSomeAwaitable(Input.Buffer), Net::deferred)};
            }
        };
        [[nodiscard]] auto ReadSomeAwaitable(std::span<std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            std::error_code Error;
            const auto Count = co_await ReadPartial(Buffer, Error);
            co_return Prism::IoResult{Count, Prism::Fault::FromNative(Error)};
        }
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t>
        {
            while (true)
            {
                if (!RecvBuffer_.empty())
                {
                    const auto BytesRead = (std::min)(Buffer.size(), RecvBuffer_.size());
                    std::memcpy(Buffer.data(), RecvBuffer_.data(), BytesRead);
                    RecvBuffer_.erase(RecvBuffer_.begin(),
                                     RecvBuffer_.begin() + static_cast<std::ptrdiff_t>(BytesRead));
                    Error.clear();
                    co_return BytesRead;
                }
                if (Closed_)
                {
                    Error = std::make_error_code(std::errc::broken_pipe);
                    co_return 0;
                }
                co_await Net::post(Ex_, Net::use_awaitable);
            }
        }
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
            const auto Read = co_await ClientSide->ReadSome(std::span<std::byte>(Buffer));
            ErrorCode = Prism::Fault::ToNative(Read.Failure);
            const auto BytesRead = Read.Bytes;
            if (ErrorCode || BytesRead == 0)
            {
                break;
            }
            const auto Write = co_await ClientSide->WriteSome(
                std::span<const std::byte>(Buffer.data(), BytesRead));
            ErrorCode = Prism::Fault::ToNative(Write.Failure);
            if (ErrorCode)
            {
                break;
            }
        }
        (void)ClientSide->Close();
    }

    struct MiddlewarePipelineRequest final
    {
        std::shared_ptr<Middleware::Pipeline> PipelineOwner;
        SharedTransmission Inbound;
        std::shared_ptr<Middleware::Context> ContextOwner;
    };

    struct MiddlewarePipelineCompletion final
    {
        explicit MiddlewarePipelineCompletion(Net::any_io_executor Executor)
            : Done(std::make_shared<CompletionChannel>(std::move(Executor), 1))
        {
        }

        std::shared_ptr<CompletionChannel> Done;
        Prism::Fault::Failure Result{};
        std::exception_ptr Failure;
    };

    /**
     * @brief 在拥有的 Pipeline/Context 上运行 typed middleware 管线。
     * @param Request 管线、上下文和入站传输 owner。
     * @return 管线返回的 Fault code。
     * @details shared owner 使 detached relay 不依赖调用方栈上的管线和上下文。
     */
    auto RunMiddlewarePipeline(MiddlewarePipelineRequest Request)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        Request.ContextOwner->Inbound() = std::move(Request.Inbound);
        co_return co_await Request.PipelineOwner->Run(*Request.ContextOwner);
    }

    /**
     * @brief 驱动 Dial → Relay 管线并验证双向 payload 回显。
     * @param IoContext 管线和 memory transport 使用的执行器。
     * @return 完成入站写入、上游读取、回写和客户端读取的异步操作。
     * @details detached pipeline 由 RunMiddlewarePipeline 的 shared owner 保持到 relay 完成。
     */
    auto RunMiddlewarePipelineScenario(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        auto ClientSide = std::make_shared<MemoryTransport>(IoContext.get_executor());
        auto Inbound = std::make_shared<MemoryTransport>(IoContext.get_executor());
        ClientSide->BindPeer(Inbound);
        Inbound->BindPeer(ClientSide);

        auto Outbound = std::make_shared<MemoryTransport>(IoContext.get_executor());
        auto Upstream = std::make_shared<MemoryTransport>(IoContext.get_executor());
        Outbound->BindPeer(Upstream);
        Upstream->BindPeer(Outbound);

        auto Context = std::make_shared<Middleware::Context>();
        Context->Target().Route = Prism::Network::RouteKind::Forward;
        Context->Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{Context->BufferSize, 2U});
        auto Dial = std::make_shared<Middleware::Builtin::DialMiddleware>(
            [Outbound](const Network::Target &) -> Net::awaitable<
                std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
            {
                co_return Outbound;
            });

        auto Pipeline = std::make_shared<Middleware::Pipeline>();
        Pipeline->Add(Dial).Add(std::make_shared<Middleware::Builtin::RelayMiddleware>(
            nullptr, std::chrono::milliseconds(100)));
        auto Completion = std::make_shared<MiddlewarePipelineCompletion>(
            IoContext.get_executor());
        Net::co_spawn(
            IoContext.get_executor(),
            RunMiddlewarePipeline(MiddlewarePipelineRequest{Pipeline, Inbound, Context}),
            [Completion](std::exception_ptr Failure, const Prism::Fault::Failure Result)
            {
                Completion->Failure = std::move(Failure);
                if (!Completion->Failure)
                {
                    Completion->Result = Result;
                }
                (void)Completion->Done->try_send(boost::system::error_code{});
            });

        const std::string Payload = "Middleware Pipeline echo test";
        std::error_code WriteErrorCode;
        const auto ClientWrite = co_await ClientSide->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                       Payload.size()));
        WriteErrorCode = Prism::Fault::ToNative(ClientWrite.Failure);

        std::array<std::byte, 512> ServerBuffer{};
        std::error_code ServerErrorCode;
        std::size_t ServerTotal = 0;
        while (ServerTotal < Payload.size())
        {
            const auto Read = co_await Upstream->ReadSome(
                std::span<std::byte>(ServerBuffer.data() + ServerTotal,
                                     ServerBuffer.size() - ServerTotal));
            ServerErrorCode = Prism::Fault::ToNative(Read.Failure);
            const auto BytesRead = Read.Bytes;
            if (ServerErrorCode || BytesRead == 0)
            {
                break;
            }
            ServerTotal += BytesRead;
        }
        const std::string ServerPayload(
            reinterpret_cast<const char *>(ServerBuffer.data()), ServerTotal);
        EXPECT_EQ(ServerPayload, Payload);

        std::error_code WriteErrorCode2;
        const auto UpstreamWrite = co_await Upstream->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                       Payload.size()));
        WriteErrorCode2 = Prism::Fault::ToNative(UpstreamWrite.Failure);

        std::array<std::byte, 512> ClientBuffer{};
        std::error_code ReadErrorCode;
        std::size_t Total = 0;
        while (Total < Payload.size())
        {
            const auto Read = co_await ClientSide->ReadSome(
                std::span<std::byte>(ClientBuffer.data() + Total,
                                     ClientBuffer.size() - Total));
            ReadErrorCode = Prism::Fault::ToNative(Read.Failure);
            const auto BytesRead = Read.Bytes;
            if (ReadErrorCode || BytesRead == 0)
            {
                break;
            }
            Total += BytesRead;
        }
        const std::string Received(
            reinterpret_cast<const char *>(ClientBuffer.data()), Total);
        EXPECT_EQ(Received, Payload);

        // 关闭双方实际 endpoint，让 relay 的两个 pump 观察 broken_pipe 并完成最终 Close。
        (void)ClientSide->Close();
        (void)Inbound->Close();
        (void)Outbound->Close();
        (void)Upstream->Close();
        co_await Completion->Done->async_receive(Net::use_awaitable);
        EXPECT_FALSE(Completion->Failure);
        EXPECT_EQ(Completion->Result.Code, Fault::Code::IoError);
        if (Completion->Failure)
        {
            std::rethrow_exception(Completion->Failure);
        }
    }

    TEST(MiddlewarePipeline, DialRelayEcho)
    {
        Net::io_context IoContext;
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, RunMiddlewarePipelineScenario(IoContext),
                      [&](std::exception_ptr Error)
                      {
                          Exception = Error;
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

} // namespace
