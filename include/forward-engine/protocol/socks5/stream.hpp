#pragma once

#include <boost/asio.hpp>
#include <array>
#include <string>
#include <abnormal.hpp>
#include <forward-engine/memory.hpp>

#include <forward-engine/protocol/socks5/constants.hpp>
#include <forward-engine/protocol/socks5/types.hpp>

namespace ngx::protocol::socks5
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    /**
     * @brief SOCKS5 协议流封装
     * @tparam Transport 传输层 Socket 类型
     */
    template <typename Transport>
    class stream
    {
    public:
        explicit stream(Transport socket)
            : socket_(std::move(socket))
        {
        }

        /**
         * @brief 执行 SOCKS5 握手
         * @return target_information 解析出的目标地址信息
         */
        net::awaitable<target_information> handshake()
        {
            // 1. 方法协商
            // 客户端发送: VER(1) | NMETHODS(1) | METHODS(1-255)
            std::array<uint8_t, 2> header{};
            co_await net::async_read(socket_, net::buffer(header), net::use_awaitable);

            if (header[0] != 0x05)
            {
                throw abnormal::protocol("Invalid SOCKS version");
            }

            int nmethods = header[1];
            std::vector<uint8_t> methods(nmethods);
            co_await net::async_read(socket_, net::buffer(methods), net::use_awaitable);

            // 检查是否支持无认证 (0x00)
            bool no_auth_supported = false;
            for (auto method : methods)
            {
                if (method == 0x00)
                {
                    no_auth_supported = true;
                    break;
                }
            }

            if (!no_auth_supported)
            {
                // 发送无支持的方法响应 (0xFF)
                uint8_t response[] = {0x05, 0xFF};
                co_await net::async_write(socket_, net::buffer(response), net::use_awaitable);
                throw abnormal::security("No supported authentication method");
            }

            // 发送选中无认证方法 (0x00)
            uint8_t response[] = {0x05, 0x00};
            co_await net::async_write(socket_, net::buffer(response), net::use_awaitable);

            // 2. 请求处理
            // 客户端发送: VER(1) | CMD(1) | RSV(1) | ATYP(1) | DST.ADDR | DST.PORT
            std::array<uint8_t, 4> request_header{};
            co_await net::async_read(socket_, net::buffer(request_header), net::use_awaitable);

            if (request_header[0] != 0x05)
            {
                throw abnormal::protocol("Invalid SOCKS version in request");
            }

            target_information info{};
            info.cmd = static_cast<command>(request_header[1]);
            info.atyp = static_cast<address_type>(request_header[3]);

            if (info.cmd != command::connect)
            {
                co_await send_error(reply_code::command_not_supported);
                throw abnormal::protocol("Unsupported SOCKS5 command (only CONNECT is supported)");
            }

            // 解析地址
            if (info.atyp == address_type::ipv4)
            {
                std::array<uint8_t, 4> ip{};
                co_await net::async_read(socket_, net::buffer(ip), net::use_awaitable);
                info.host = net::ip::make_address_v4(ip).to_string();
            }
            else if (info.atyp == address_type::domain)
            {
                uint8_t len = 0;
                co_await net::async_read(socket_, net::buffer(&len, 1), net::use_awaitable);
                std::string domain(len, '\0');
                co_await net::async_read(socket_, net::buffer(domain), net::use_awaitable);
                info.host = std::move(domain);
            }
            else if (info.atyp == address_type::ipv6)
            {
                std::array<uint8_t, 16> ip{};
                co_await net::async_read(socket_, net::buffer(ip), net::use_awaitable);
                info.host = net::ip::make_address_v6(ip).to_string();
            }
            else
            {
                throw abnormal::protocol("Unsupported address type");
            }

            // 解析端口
            uint16_t port_n = 0;
            co_await net::async_read(socket_, net::buffer(&port_n, 2), net::use_awaitable);
            info.port = ntohs(port_n);

            co_return info;
        }

        /**
         * @brief 发送成功响应
         * @param info 绑定的地址信息（通常是 0.0.0.0:0）
         */
        net::awaitable<void> send_success(const target_information &info)
        {
            // 响应: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
            // 简化：总是返回 0.0.0.0:0
            std::array<uint8_t, 10> response = {
                0x05, static_cast<uint8_t>(reply_code::succeeded), 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, // 0.0.0.0
                0x00, 0x00              // Port 0
            };
            co_await net::async_write(socket_, net::buffer(response), net::use_awaitable);
        }

        /**
         * @brief 发送错误响应
         */
        net::awaitable<void> send_error(reply_code code)
        {
            std::array<uint8_t, 10> response = {
                0x05, static_cast<uint8_t>(code), 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00};
            try
            {
                co_await net::async_write(socket_, net::buffer(response), net::use_awaitable);
            }
            catch (...)
            {
                // 忽略发送错误时的异常
            }
        }

        /**
         * @brief 读取数据
         */
        net::awaitable<std::size_t> async_read(net::mutable_buffer buffer)
        {
            co_return co_await socket_.async_read_some(buffer, net::use_awaitable);
        }

        /**
         * @brief 写入数据
         */
        net::awaitable<std::size_t> async_write(net::const_buffer buffer)
        {
            co_return co_await net::async_write(socket_, buffer, net::use_awaitable);
        }

        /**
         * @brief 关闭连接
         */
        net::awaitable<void> close()
        {
            boost::system::error_code ec;
            socket_.close(ec);
            co_return;
        }

        Transport &socket() { return socket_; }

    private:
        Transport socket_;
    };
}
