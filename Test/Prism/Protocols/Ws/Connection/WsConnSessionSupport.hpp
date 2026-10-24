/**
 * @file WsConnSessionSupport.hpp
 * @brief WebSocket 会话测试共用的请求状态和协程驱动器。
 * @details 仅供多个 WsConnSession 目标源文件共享；不包含 GoogleTest 用例正文。
 */
#pragma once
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <exception>
#include <memory>
#include <string>
#include <utility>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Ws/Ws.hpp>
namespace Prism::Tests::WsConnSessionSupport
{
    namespace Net = boost::asio;
    using Prism::Error;
    using Prism::MemoryStream;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code)>;

    struct EagerTask final
    {
        std::shared_ptr<CompletionChannel> Done;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    struct StreamPairRequest final
    {
        MemoryStream Client;
        MemoryStream Server;
    };

    struct PairCompletion final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
        EagerTask ServerTask;
    };

    struct EchoRequest final
    {
        StreamPairRequest Pair;
        std::string Payload;
    };

    struct MaskedFrameRequest final
    {
        StreamPairRequest Pair;
        std::string Payload;
        std::shared_ptr<bool> Result;
    };

    struct ErrorWireRequest final
    {
        StreamPairRequest Pair;
        std::string Request;
        Prism::Fault::Code Expected;
    };

    struct ResponseRejectRequest final
    {
        StreamPairRequest Pair;
        std::string Response;
        Prism::Fault::Code Expected;
    };

    struct HeaderRequest final
    {
        StreamPairRequest Pair;
        std::string Request;
        std::shared_ptr<bool> Result;
    };

    inline constexpr const char *TestKey = "dGhlIHNhbXBsZSBub25jZQ==";

    /** @brief 立即启动 owning operation 并保存首异常。 */
    inline auto SpawnEager(Net::any_io_executor Executor,
                           Net::awaitable<void> Operation) -> EagerTask
    {
        EagerTask State{
            std::make_shared<CompletionChannel>(Executor, 1),
            std::make_shared<std::exception_ptr>()};
        Net::co_spawn(
            Executor,
            std::move(Operation),
            [State](std::exception_ptr ErrorValue)
            {
                *State.Failure = ErrorValue;
                (void)State.Done->try_send(boost::system::error_code{});
            });
        return State;
    }

    /** @brief 等待 owning operation 的真实 completion 并重抛首异常。 */
    inline auto WaitEager(EagerTask State) -> Net::awaitable<void>
    {
        (void)co_await State.Done->async_receive(Net::use_awaitable);
        if (*State.Failure)
        {
            std::rethrow_exception(*State.Failure);
        }
    }

    /** @brief 关闭双方传输并等待已经启动的 server。 */
    inline auto CloseAndWait(PairCompletion Request) -> Net::awaitable<void>
    {
        Request.Client->Close();
        Request.Server->Close();
        co_await WaitEager(std::move(Request.ServerTask));
    }

    /** @brief 已写完整输入时先等 server 处理完成，再交付双方最终关闭。 */
    inline auto WaitThenClose(PairCompletion Request) -> Net::awaitable<void>
    {
        std::exception_ptr Failure;
        try
        {
            co_await WaitEager(std::move(Request.ServerTask));
        }
        catch (...)
        {
            Failure = std::current_exception();
        }
        Request.Client->Close();
        Request.Server->Close();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    /** @brief 运行顶层协程并把异常交回测试线程。 */
    template <typename Awaitable>
    inline auto RunCoro(Net::io_context &IoContext, Awaitable Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(
            IoContext,
            std::move(Coroutine),
            [&](std::exception_ptr ErrorValue)
            {
                Exception = ErrorValue;
                IoContext.stop();
            });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }
}
