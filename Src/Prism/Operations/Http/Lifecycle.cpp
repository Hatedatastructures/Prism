/** @file Lifecycle.cpp @brief HTTP 连接状态与 socket 关闭实现。 */
#include <Prism/Operations/Http/Detail/Lifecycle.hpp>

#include <utility>

namespace Prism::Operations::HttpConnection
{
    ConnectionState::ConnectionState(Net::any_io_executor Executor)
        : Strand(Net::make_strand(std::move(Executor))),
          Socket(std::make_shared<Tcp::socket>(Strand))
    {
    }

    auto CloseSocketOnConnectionStrand(
        const std::shared_ptr<ConnectionState> &Connection) noexcept -> void
    {
        if (Connection->HandlerActive.load(std::memory_order_acquire))
        {
            Connection->CloseRequested.store(true, std::memory_order_release);
            return;
        }
        boost::system::error_code Error;
        Connection->Socket->cancel(Error);
        Connection->Socket->shutdown(Tcp::socket::shutdown_both, Error);
        Connection->Socket->close(Error);
    }

    auto CloseCompletedResponseOnConnectionStrand(
        const std::shared_ptr<ConnectionState> &Connection) noexcept -> void
    {
        if (Connection->HandlerActive.load(std::memory_order_acquire))
        {
            Connection->CloseRequested.store(true, std::memory_order_release);
            return;
        }
        boost::system::error_code Error;
        Connection->Socket->shutdown(Tcp::socket::shutdown_send, Error);
        Error.clear();
        Connection->Socket->close(Error);
    }
}
