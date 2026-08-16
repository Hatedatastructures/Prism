/**
 * @file dialer.hpp
 * @brief TCP 拨号抽象（async_connect + 超时 + 取消）
 * @details 封装 boost::asio::tcp::socket 的异步拨号：
 *          - async_connect：连接指定端点（超时 + 取消）
 *          - 返回 reliable 传输（transmission 接口）
 * @note 参照主项目 net/connection/dialer 语义，psmtest 风格
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

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/core/transport/reliable.hpp>

namespace psmtest::net_dialer
{

    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    /**
     * @struct dial_options
     * @brief 拨号选项
     */
    struct dial_options
    {
        std::chrono::milliseconds timeout{std::chrono::seconds(10)}; ///< 拨号超时
        bool enable_ipv6{true};                                     ///< 是否允许 IPv6
    };

    /**
     * @class dialer
     * @brief TCP 拨号器
     * @details 异步拨号：解析 + 连接（带超时与取消）。
     *          connect() 返回 shared_transmission（reliable 包装）。
     */
    class dialer
    {
    public:
        /**
         * @brief 构造
         * @param ex 执行器
         * @param opts 拨号选项
         */
        explicit dialer(net::any_io_executor ex, dial_options opts = {})
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
        [[nodiscard]] auto connect(std::string_view host, std::uint16_t port, std::error_code &ec)
            -> net::awaitable<shared_transmission>
        {
            using boost::asio::experimental::awaitable_operators::operator||;

            auto socket = std::make_shared<tcp::socket>(ex_);
            net::steady_timer timer(ex_);
            timer.expires_after(opts_.timeout);

            // 尝试 IP 字面量直连，否则解析
            boost::system::error_code addr_ec;
            const auto addr = net::ip::make_address(host, addr_ec);
            if (!addr_ec)
            {
                if (addr.is_v6() && !opts_.enable_ipv6)
                {
                    ec = make_error_code(error::not_supported);
                    co_return nullptr;
                }
                const tcp::endpoint ep(addr, port);
                auto do_connect = [&]() -> net::awaitable<bool>
                {
                    boost::system::error_code c_ec;
                    co_await socket->async_connect(ep, net::redirect_error(net::use_awaitable, c_ec));
                    co_return !c_ec;
                };
                const auto result = co_await (do_connect() || timer.async_wait(net::use_awaitable));
                if (result.index() == 1)
                {
                    ec = std::make_error_code(std::errc::timed_out);
                    co_return nullptr;
                }
                if (!std::get<0>(result))
                {
                    ec = std::make_error_code(std::errc::connection_refused);
                    co_return nullptr;
                }
                co_return std::make_shared<psmtest::transport::reliable>(std::move(*socket));
            }

            // 域名解析
            tcp::resolver resolver(ex_);
            boost::system::error_code r_ec;
            auto results = co_await resolver.async_resolve(host, std::to_string(port),
                                                           net::redirect_error(net::use_awaitable, r_ec));
            if (r_ec)
            {
                ec = std::make_error_code(std::errc::no_such_file_or_directory);
                co_return nullptr;
            }
            for (const auto &res : results)
            {
                if (res.endpoint().address().is_v6() && !opts_.enable_ipv6)
                {
                    continue;
                }
                timer.expires_after(opts_.timeout);
                auto do_connect = [&]() -> net::awaitable<bool>
                {
                    boost::system::error_code c_ec;
                    co_await socket->async_connect(res.endpoint(), net::redirect_error(net::use_awaitable, c_ec));
                    co_return !c_ec;
                };
                const auto result = co_await (do_connect() || timer.async_wait(net::use_awaitable));
                if (result.index() == 0 && std::get<0>(result))
                {
                    co_return std::make_shared<psmtest::transport::reliable>(std::move(*socket));
                }
            }
            ec = std::make_error_code(std::errc::connection_refused);
            co_return nullptr;
        }

    private:
        net::any_io_executor ex_;
        dial_options opts_;
    };

} // namespace psmtest::net_dialer
