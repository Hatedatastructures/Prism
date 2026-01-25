#pragma once

#include <boost/asio.hpp>
#include <array>
#include <abnormal.hpp>
#include <forward-engine/protocol/socks5/constants.hpp>
#include <forward-engine/protocol/socks5/message.hpp>
#include <forward-engine/protocol/socks5/wire.hpp>

namespace ngx::protocol::socks5
{
    namespace net = boost::asio;

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
         * @details 在握手之后，就能拿到上游的地址和端口了
         * @return `request` 解析出的请求信息
         */
        net::awaitable<request> handshake()
        {
            // 1. 方法协商
            // 客户端发送: VER(1) | NMETHODS(1) | METHODS(1-255)
            // 最大长度: 1 + 1 + 255 = 257
            std::array<std::uint8_t, 257> methods_buffer{};

            // 读取版本和方法数量
            co_await net::async_read(socket_, net::buffer(methods_buffer, 2), net::use_awaitable);

            if (methods_buffer[0] != 0x05)
            {   // 只支持 SOCKS5 协议
                throw abnormal::protocol("Invalid SOCKS version");
            }

            // 读取方法数量的数量
            std::uint8_t nmethods = methods_buffer[1];

            // 读取方法列表
            co_await net::async_read(socket_, net::buffer(methods_buffer.data() + 2, nmethods), net::use_awaitable);

            /**
             * METHODS 字段
             * 0x00 不加密
             * 0x01 GSSAPI
             * 0x02 用户名、密码认证
             * 0x03 - 0x7F 由IANA分配（保留）
             * 0x80 - 0xFE 为私人方法保留
             * 0xFF 无可接受的方法
             */

            // 检查是否支持无认证 (0x00)
            bool no_auth_supported = false;
            std::span<const std::uint8_t> methods(methods_buffer.data() + 2, nmethods);
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
                constexpr std::uint8_t response[] = {0x05, 0xFF};
                co_await net::async_write(socket_, net::buffer(response), net::use_awaitable);
                throw abnormal::security("No supported authentication method");
            }

            // 发送选中无认证方法 (0x00)
            constexpr std::uint8_t response[] = {0x05, 0x00};
            co_await net::async_write(socket_, net::buffer(response), net::use_awaitable);

            // 2. 请求处理
            // 客户端发送: VER(1) | CMD(1) | RSV(1) | ATYP(1) | DST.ADDR | DST.PORT
            // 先读头部 4 字节
            std::array<std::uint8_t, 4> request_header{};
            co_await net::async_read(socket_, net::buffer(request_header), net::use_awaitable);

            auto [ec_header, header] = wire::decode_header(request_header);
            if (ec_header)
            {
                throw abnormal::protocol("Invalid request header");
            }

            request req{};
            req.cmd = header.cmd;

            if (req.cmd != command::connect)
            {
                co_await send_error(reply_code::command_not_supported);
                throw abnormal::protocol("Unsupported SOCKS5 command (only CONNECT is supported)");
            }

            // 解析地址
            if (header.atyp == address_type::ipv4)
            {  
                // IPv4 地址(4) + Port(2) = 6 字节
                std::array<std::uint8_t, 6> buffer{};
                co_await net::async_read(socket_, net::buffer(buffer), net::use_awaitable);
                
                auto [ec, ip] = wire::decode_ipv4(std::span<const std::uint8_t>(buffer.data(), 4));
                if (ec) throw abnormal::protocol("Invalid IPv4 address");
                req.destination_address = ip;

                auto [ec_port, port] = wire::decode_port(std::span<const std::uint8_t>(buffer.data() + 4, 2));
                if (ec_port) throw abnormal::protocol("Invalid port");
                req.destination_port = port;
            }
            else if (header.atyp == address_type::ipv6)
            {
                // IPv6 地址(16) + Port(2) = 18 字节
                std::array<std::uint8_t, 18> buffer{};
                co_await net::async_read(socket_, net::buffer(buffer), net::use_awaitable);

                auto [ec, ip] = wire::decode_ipv6(std::span<const std::uint8_t>(buffer.data(), 16));
                if (ec) throw abnormal::protocol("Invalid IPv6 address");
                req.destination_address = ip;

                auto [ec_port, port] = wire::decode_port(std::span<const std::uint8_t>(buffer.data() + 16, 2));
                if (ec_port) throw abnormal::protocol("Invalid port");
                req.destination_port = port;
            }
            else if (header.atyp == address_type::domain)
            {
                std::uint8_t len = 0;
                co_await net::async_read(socket_, net::buffer(&len, 1), net::use_awaitable);

                // 域名内容(len) + Port(2)
                // 域名最大 255 字节 + 2 字节端口 = 257
                std::array<std::uint8_t, 257> buffer{};
                // buffer[0] 用于存放长度，以便复用 decode_domain
                buffer[0] = len;
                
                // 读取 len + 2 字节到 buffer[1] 开始的位置
                co_await net::async_read(socket_, net::buffer(buffer.data() + 1, len + 2), net::use_awaitable);

                auto [ec, domain] = wire::decode_domain(std::span<const std::uint8_t>(buffer.data(), len + 1));
                if (ec) throw abnormal::protocol("Invalid domain address");
                req.destination_address = domain;

                auto [ec_port, port] = wire::decode_port(std::span<const std::uint8_t>(buffer.data() + 1 + len, 2));
                if (ec_port) throw abnormal::protocol("Invalid port");
                req.destination_port = port;
            }
            else
            {
                throw abnormal::protocol("Unsupported address type");
            }

            co_return req;
        }

        /**
         * @brief 发送成功响应
         * @param info 请求信息 (用于回显绑定地址，此处简化总是返回 0.0.0.0:0)
         */
        net::awaitable<void> send_success(const request &info)
        {
            // 响应: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
            // 简化：总是返回 0.0.0.0:0
            constexpr std::array<std::uint8_t, 10> response = 
            {
                0x05, static_cast<std::uint8_t>(reply_code::succeeded), 0x00, 0x01,
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
            const std::array<std::uint8_t, 10> response = 
            {
                0x05, static_cast<uint8_t>(code), 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            };
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
