#include <forward-engine/channel/health.hpp>

namespace ngx::channel
{
    namespace net = boost::asio;

    [[nodiscard]] socket_state health(const net::ip::tcp::socket &s)
    {
        if (!s.is_open())
        {
            return socket_state::invalid;
        }

        // 1. 检查 SO_ERROR
        boost::system::error_code ec;
        const auto fd = const_cast<net::ip::tcp::socket &>(s).native_handle();
        int error = 0;
        socklen_t len = sizeof(error);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&error), &len) != 0)
        {
            return socket_state::error;
        }
        if (error != 0)
        {
            return socket_state::error;
        }

        // 2. 检查 available
        const std::size_t avail = const_cast<net::ip::tcp::socket &>(s).available(ec);
        if (ec)
        {
            return socket_state::error;
        }
        if (avail == 0)
        {
            // 无数据可用，执行 peek 进一步确认
            std::array<std::byte, 1> peek_buf{};
            auto &socket = const_cast<net::ip::tcp::socket &>(s);
            // 保存原来的非阻塞状态
            const bool was_non_blocking = socket.non_blocking();
            if (!was_non_blocking)
            {
                socket.non_blocking(true, ec);
                if (ec)
                {
                    return socket_state::error;
                }
            }
            const auto n = socket.receive(net::buffer(peek_buf), net::socket_base::message_peek, ec);
            // 恢复原来的非阻塞状态
            if (!was_non_blocking)
            {
                boost::system::error_code ignore;
                socket.non_blocking(was_non_blocking, ignore);
            }
            if (ec == net::error::would_block || ec == net::error::try_again)
            {
                return socket_state::healthy;
            }
            if (n == 0)
            {
                return socket_state::fin;
            }
            return socket_state::has_data;
        }

        return socket_state::has_data;
    }

    [[nodiscard]] bool healthy_fast(const net::ip::tcp::socket &s)
    {
        if (!s.is_open())
        {
            return false;
        }

        // 检查 SO_ERROR
        boost::system::error_code ec;
        const auto fd = const_cast<net::ip::tcp::socket &>(s).native_handle();
        int error = 0;
        socklen_t len = sizeof(error);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&error), &len) != 0)
        {
            return false;
        }
        if (error != 0)
        {
            return false;
        }

        // 检查 available
        const std::size_t avail = const_cast<net::ip::tcp::socket &>(s).available(ec);
        if (ec)
        {
            return false;
        }
        if (avail > 0)
        {
            // 有待读数据，不适合复用（可能残留上一轮的脏数据）
            return false;
        }

        // available == 0 时，通过非阻塞 recv(MSG_PEEK) 检测 FIN
        // FIN 不产生"可用数据"，available() 检测不到，必须 peek
        std::array<std::byte, 1> peek_buf{};
        auto &socket = const_cast<net::ip::tcp::socket &>(s);
        const auto n = socket.receive(net::buffer(peek_buf), net::socket_base::message_peek, ec);

        if (ec == net::error::would_block || ec == net::error::try_again)
        {
            // 无数据无 FIN，连接健康
            return true;
        }
        if (n == 0)
        {
            // 对端已发 FIN
            return false;
        }
        // 其他错误
        return false;
    }
} // namespace ngx::channel
