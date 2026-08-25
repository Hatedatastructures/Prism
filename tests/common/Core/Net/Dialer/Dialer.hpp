/**
 * @file Dialer.hpp
 * @brief TCP 拨号抽象（async_connect + 超时 + 取消）
 * @details 封装 boost::asio::tcp::socket 的异步拨号：
 *          - async_connect：连接指定端点（超时 + 取消）
 *          - 返回 Reliable 传输（Transmission 接口）
 * @note 参照主项目 net/connection/Dialer 语义，Preview 风格
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <common/Core/Error.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Core/Transport/Reliable.hpp>

namespace Preview::Network::Dialer
{

    namespace net = boost::asio;
    using Tcp = net::ip::tcp;

    /**
     * @struct DialOptions
     * @brief 拨号选项
     */
    struct DialOptions
    {
        std::chrono::milliseconds timeout{std::chrono::seconds(10)}; ///< 拨号超时
        bool EnableIpv6{true};                                     ///< 是否允许 IPv6
    };

    /**
     * @class Dialer
     * @brief TCP 拨号器
     * @details 异步拨号：解析 + 连接（带超时与取消）。
     *          Connect() 返回 SharedTransmission（Reliable 包装）。
     */
    class Dialer
    {
    public:
        /**
         * @brief 构造
         * @param ex 执行器
         * @param opts 拨号选项
         */
        explicit Dialer(net::any_io_executor ex, DialOptions opts = {})
            : ex_(std::move(ex)), opts_(opts)
        {
        }

        /**
         * @brief 拨号连接（域名/IP + 端口）
         * @param host 主机名或 IP
         * @param port 端口
         * @return 连接成功的传输；失败返回 nullptr
         * @details 超时取消挂起连接，返回 nullptr 且 ec 置 timed_out。
         */
        [[nodiscard]] auto Connect(std::string_view host, std::uint16_t port, std::error_code &ec)
            -> net::awaitable<SharedTransmission>
        {
            using boost::asio::experimental::awaitable_operators::operator||;

            auto socket = std::make_shared<Tcp::socket>(ex_);
            net::steady_timer timer(ex_);
            timer.expires_after(opts_.timeout);

            // 尝试 IP 字面量直连，否则解析
            boost::system::error_code AddrEc;
            const auto addr = net::ip::make_address(host, AddrEc);
            if (!AddrEc)
            {
                if (addr.is_v6() && !opts_.EnableIpv6)
                {
                    ec = make_error_code(Error::not_supported);
                    co_return nullptr;
                }
                const net::ip::tcp::endpoint ep(addr, port);
                auto DoConnect = [&]() -> net::awaitable<bool>
                {
                    boost::system::error_code CEc;
                    co_await socket->async_connect(ep, net::redirect_error(net::use_awaitable, CEc));
                    co_return !CEc;
                };
                const auto Result = co_await (DoConnect() || timer.async_wait(net::use_awaitable));
                if (Result.index() == 1)
                {
                    ec = std::make_error_code(std::errc::timed_out);
                    co_return nullptr;
                }
                if (!std::get<0>(Result))
                {
                    ec = std::make_error_code(std::errc::connection_refused);
                    co_return nullptr;
                }
                co_return std::make_shared<Preview::Transport::Reliable>(std::move(*socket));
            }

            // 域名解析
            Tcp::resolver resolver(ex_);
            boost::system::error_code REc;
            auto results = co_await resolver.async_resolve(host, std::to_string(port),
                                                           net::redirect_error(net::use_awaitable, REc));
            if (REc)
            {
                ec = std::make_error_code(std::errc::no_such_file_or_directory);
                co_return nullptr;
            }
            for (const auto &res : results)
            {
                if (res.endpoint().address().is_v6() && !opts_.EnableIpv6)
                {
                    continue;
                }
                timer.expires_after(opts_.timeout);
                auto DoConnect = [&]() -> net::awaitable<bool>
                {
                    boost::system::error_code CEc;
                    co_await socket->async_connect(res.endpoint(), net::redirect_error(net::use_awaitable, CEc));
                    co_return !CEc;
                };
                const auto Result = co_await (DoConnect() || timer.async_wait(net::use_awaitable));
                if (Result.index() == 0 && std::get<0>(Result))
                {
                    co_return std::make_shared<Preview::Transport::Reliable>(std::move(*socket));
                }
            }
            ec = std::make_error_code(std::errc::connection_refused);
            co_return nullptr;
        }

    private:
        net::any_io_executor ex_;
        DialOptions opts_;
    };

} // namespace Preview::Network::Dialer
