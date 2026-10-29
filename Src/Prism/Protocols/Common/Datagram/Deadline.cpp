/** @file Deadline.cpp @brief 数据报交换期限实现。 */

#include <Prism/Protocols/Common/Datagram/Deadline.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <utility>
#include <variant>

namespace Prism::Protocols
{
    auto AwaitDatagramDeadline(
        boost::asio::awaitable<Prism::Fault::Code> Operation,
        DatagramDeadline Deadline) -> boost::asio::awaitable<Prism::Fault::Code>
    {
        if (Deadline.Timeout.count() <= 0) co_return co_await std::move(Operation);
        boost::asio::steady_timer Timer(Deadline.Executor);
        Timer.expires_after(Deadline.Timeout);
        using boost::asio::experimental::awaitable_operators::operator||;
        auto Result = co_await (std::move(Operation) || Timer.async_wait(boost::asio::use_awaitable));
        if (Result.index() == 1) co_return Prism::Fault::Code::Timeout;
        co_return std::get<0>(Result);
    }
} // namespace Prism::Protocols
