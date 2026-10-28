/**
 * @file MemorySupport.hpp
 * @brief CarrierMemory 多个测试 CPP 共用的协程完成与等待夹具。
 */
#pragma once

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <exception>
#include <memory>
#include <utility>

namespace Prism::Tests::Integration::Layering::CarrierMemorySupport
{
    namespace Net = boost::asio;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    /** @brief 消费异步服务器的一次完成信号。 */
    [[nodiscard]] inline auto WaitForCompletion(
        const std::shared_ptr<CompletionChannel> &Completion) -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        auto Receive = Completion->async_receive(
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        co_await std::move(Receive);
    }

    /** @brief 驱动测试协程并在回调中保存并重抛异常。 */
    template <typename Coroutine>
    inline auto RunCoroutine(Net::io_context &IoContext, Coroutine Task) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Task),
                      [&](std::exception_ptr Error)
                      {
                          Exception = Error;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }
}
