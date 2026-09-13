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

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Transport/Reliable.hpp>

namespace Preview::Network::Dialer
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    /**
     * @struct DialOptions
     * @brief 拨号选项
     */
    struct DialOptions
    {
        std::chrono::milliseconds Timeout{std::chrono::seconds(10)}; ///< 拨号超时
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
        explicit Dialer(Net::any_io_executor Executor, DialOptions Options = {})
            : Ex_(std::move(Executor)), Opts_(Options)
        {
        }

        /**
         * @brief 拨号连接（域名/IP + 端口）
         * @param host 主机名或 IP
         * @param port 端口
         * @return 连接成功的传输；失败返回 nullptr
         * @details 超时取消挂起连接，返回 nullptr 且 ec 置 timed_out。
         */
        [[nodiscard]] auto Connect(std::string_view Host, std::uint16_t Port,
                                   std::error_code &ErrorCode)
            -> Net::awaitable<SharedTransmission>
        {
            using Net::experimental::awaitable_operators::operator||;

            auto Socket = std::make_shared<Tcp::socket>(Ex_);
            Net::steady_timer Timer(Ex_);
            Timer.expires_after(Opts_.Timeout);

            // 尝试 IP 字面量直连，否则解析
            boost::system::error_code AddrEc;
            const auto Addr = Net::ip::make_address(Host, AddrEc);
            if (!AddrEc)
            {
                if (Addr.is_v6() && !Opts_.EnableIpv6)
                {
                    ErrorCode = make_error_code(Error::NotSupported);
                    co_return nullptr;
                }
                const Net::ip::tcp::endpoint Endpoint(Addr, Port);
                auto ConnectOperation = [&]() -> Net::awaitable<bool>
                {
                    boost::system::error_code CEc;
                    co_await Socket->async_connect(Endpoint,
                                                   Net::redirect_error(Net::use_awaitable, CEc));
                    co_return !CEc;
                };
                const auto Result = co_await (ConnectOperation() || Timer.async_wait(Net::use_awaitable));
                if (Result.index() == 1)
                {
                    ErrorCode = std::make_error_code(std::errc::timed_out);
                    co_return nullptr;
                }
                if (!std::get<0>(Result))
                {
                    ErrorCode = std::make_error_code(std::errc::connection_refused);
                    co_return nullptr;
                }
                co_return std::make_shared<Preview::Transport::Reliable>(std::move(*Socket));
            }

            // 域名解析
            Tcp::resolver Resolver(Ex_);
            boost::system::error_code REc;
            auto Results = co_await Resolver.async_resolve(Host, std::to_string(Port),
                                                           Net::redirect_error(Net::use_awaitable, REc));
            if (REc)
            {
                ErrorCode = std::make_error_code(std::errc::no_such_file_or_directory);
                co_return nullptr;
            }
            for (const auto &res : Results)
            {
                if (res.endpoint().address().is_v6() && !Opts_.EnableIpv6)
                {
                    continue;
                }
                Timer.expires_after(Opts_.Timeout);
                const auto Endpoint = res.endpoint();
                auto ConnectOperation = [&]() -> Net::awaitable<bool>
                {
                    boost::system::error_code CEc;
                    co_await Socket->async_connect(Endpoint,
                                                   Net::redirect_error(Net::use_awaitable, CEc));
                    co_return !CEc;
                };
                const auto Result = co_await (ConnectOperation() || Timer.async_wait(Net::use_awaitable));
                if (Result.index() == 0 && std::get<0>(Result))
                {
                    co_return std::make_shared<Preview::Transport::Reliable>(std::move(*Socket));
                }
            }
            ErrorCode = std::make_error_code(std::errc::connection_refused);
            co_return nullptr;
        }

    private:
        Net::any_io_executor Ex_;
        DialOptions Opts_;
    };

} // namespace Preview::Network::Dialer
