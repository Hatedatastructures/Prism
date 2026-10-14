#pragma once

/**
 * @file Socks5ConnSessionSupport.hpp
 * @brief SOCKS5 Conn 测试共享的 owning completion 与传输请求模型。
 * @details 仅提供多个 Conn 场景 CPP 共同使用的生命周期操作，不承载 TEST 正文。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Protocols/Socks5/Socks5.hpp>
#include <Preview/Transport/MemoryStream.hpp>

namespace Preview::Socks5ConnTestSupport
{
    namespace Net = boost::asio;
    namespace Socks5 = Preview::Socks5;
    using MemoryStream = Preview::MemoryStream;

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

    /** @brief 立即启动 owning operation 并记录首个异常。 */
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

    /** @brief 等待 operation 的真实 completion，并重新抛出首异常。 */
    inline auto WaitEager(EagerTask State) -> Net::awaitable<void>
    {
        (void)co_await State.Done->async_receive(Net::use_awaitable);
        if (*State.Failure)
        {
            std::rethrow_exception(*State.Failure);
        }
    }

    /** @brief 半关闭 client 写方向，等待 server operation 后关闭并 drain 双方。 */
    inline auto CloseAndWait(std::shared_ptr<MemoryStream> Client,
                             std::shared_ptr<MemoryStream> Server,
                             EagerTask ServerTask) -> Net::awaitable<bool>
    {
        const auto Shutdown = co_await Client->WriteShutdown();
        if (!Shutdown)
        {
            const auto ClientClose = Client->Close();
            (void)ClientClose;
        }
        co_await WaitEager(std::move(ServerTask));
        const auto ClientClose = Client->Close();
        const auto ServerClose = Server->Close();
        const auto ClientDrain = co_await Client->Activity()->Drain();
        const auto ServerDrain = co_await Server->Activity()->Drain();
        co_return Shutdown.has_value() && ClientClose.has_value() &&
                  ServerClose.has_value() && ClientDrain.has_value() &&
                  ServerDrain.has_value();
    }

    /** @brief 部分读取：一次交付真实字节数并把失败还原为原生错误。 */
    inline auto ReadInto(Preview::Transmission &Stream, std::span<std::byte> Buffer,
                         std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        const auto Read = co_await Stream.ReadSome(Buffer);
        ErrorCode = Preview::Fault::ToNative(Read.Failure);
        co_return Read.Bytes;
    }

    /** @brief 部分写入：一次交付真实字节数并把失败还原为原生错误。 */
    inline auto WriteInto(Preview::Transmission &Stream,
                          std::span<const std::byte> Buffer,
                          std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        const auto Write = co_await Stream.WriteSome(Buffer);
        ErrorCode = Preview::Fault::ToNative(Write.Failure);
        co_return Write.Bytes;
    }

    /** @brief 精确读取：一次交付真实字节数并把失败还原为原生错误。 */
    inline auto ReadExactInto(Preview::Transmission &Stream, std::span<std::byte> Buffer,
                              std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        const auto Read = co_await Stream.ReadExact(Buffer);
        ErrorCode = Preview::Fault::ToNative(Read.Failure);
        co_return Read.Bytes;
    }

    /** @brief 运行顶层协程并把异常交回 GoogleTest 调用方。 */
    template <typename Awaitable>
    inline auto RunCoroutine(Net::io_context &IoContext, Awaitable Coroutine)
        -> void
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

    /** @brief 构造 SOCKS5 目标地址。 */
    inline auto MakeAddress(Socks5::AddressType Type, std::string Host,
                            std::uint16_t Port) -> Socks5::Address
    {
        Socks5::Address Address{};
        Address.Type = Type;
        Address.Host = std::move(Host);
        Address.Port = Port;
        return Address;
    }
}
