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
            if (!co_await negotiate_methods())
            {
                throw abnormal::security("No supported authentication method");
            }

            // 2. 请求处理
            auto header = co_await read_request_header();

            request req{};
            req.cmd = header.cmd;

            if (req.cmd != command::connect)
            {
                co_await send_error(reply_code::command_not_supported);
                throw abnormal::protocol("Unsupported SOCKS5 command (only CONNECT is supported)");
            }

            // 3. 解析地址 + 端口
            switch (header.atyp)
            {
            case address_type::ipv4:
            {
                auto [addr, port] = co_await read_ip_address_and_port<4>(wire::decode_ipv4, "Invalid IPv4 address");
                req.destination_address = addr;
                req.destination_port = port;
                break;
            }
            case address_type::ipv6:
            {
                auto [addr, port] = co_await read_ip_address_and_port<16>(wire::decode_ipv6, "Invalid IPv6 address");
                req.destination_address = addr;
                req.destination_port = port;
                break;
            }
            case address_type::domain:
            {
                auto [addr, port] = co_await read_domain_address_and_port();
                req.destination_address = addr;
                req.destination_port = port;
                break;
            }
            default:
                throw abnormal::protocol("Unsupported address type");
            }

            co_return req;
        }

        /**
         * @brief 发送成功响应
         * @param info 请求信息 (用于回显绑定地址和端口)
         */
        net::awaitable<void> send_success(const request &info)
        {
            auto response = build_success_response(info);
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
        /**
         * @brief 协商认证方法
         * @return bool 是否支持无认证 (0x00)
         */
        net::awaitable<bool> negotiate_methods()
        {
            // 客户端发送: VER(1) | NMETHODS(1) | METHODS(1-255)
            // 最大长度: 1 + 1 + 255 = 257
            std::array<std::uint8_t, 257> methods_buffer{};

            // 读取版本和方法数量
            co_await net::async_read(socket_, net::buffer(methods_buffer, 2), net::use_awaitable);

            if (methods_buffer[0] != 0x05)
            { // 只支持 SOCKS5 协议
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
                co_return false;
            }

            // 发送选中无认证方法 (0x00)
            constexpr std::uint8_t response[] = {0x05, 0x00};
            co_await net::async_write(socket_, net::buffer(response), net::use_awaitable);
            co_return true;
        }

        /**
         * @brief 读取请求头部
         * @return `wire::header_parse` 包含解析后的命令和地址类型
         * @throws abnormal::protocol 如果头部无效
         */
        net::awaitable<wire::header_parse> read_request_header()
        {
            std::array<std::uint8_t, 4> request_header{};
            co_await net::async_read(socket_, net::buffer(request_header), net::use_awaitable);

            auto [ec_header, header] = wire::decode_header(request_header);
            if (ec_header)
            {
                throw abnormal::protocol("Invalid request header");
            }
            co_return header;
        }

        /**
         * @brief 读取 IP 地址和端口
         * @param decoder 地址解码器
         * @param error_msg 错误消息
         * @return `std::pair<address, uint16_t>` 包含解析后的地址和端口
         * @throws abnormal::protocol 如果地址或端口无效
         */
        template <size_t N, typename Decoder>
        net::awaitable<std::pair<address, uint16_t>> read_ip_address_and_port(Decoder &&decoder, const char *error_msg)
        {
            std::array<std::uint8_t, N + 2> buffer{}; // IP(N) + Port(2)
            co_await net::async_read(socket_, net::buffer(buffer), net::use_awaitable);

            auto [ec, ip] = decoder(std::span<const std::uint8_t>(buffer.data(), N));
            if (ec)
            {
                throw abnormal::protocol(error_msg);
            }

            auto [ec_port, port] = wire::decode_port(std::span<const std::uint8_t>(buffer.data() + N, 2));
            if (ec_port)
            {
                throw abnormal::protocol("Invalid port");
            }

            co_return std::pair{ip, port};
        }

        /**
         * @brief 读取域名地址和端口
         */
        /**
         * @brief 读取域名地址和端口
         * @return `std::pair<address, uint16_t>` 包含解析后的域名和端口
         * @throws abnormal::protocol 如果域名或端口无效
         */
        net::awaitable<std::pair<address, uint16_t>> read_domain_address_and_port()
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
            if (ec)
            {
                throw abnormal::protocol("Invalid domain address");
            }

            auto [ec_port, port] = wire::decode_port(std::span<const std::uint8_t>(buffer.data() + 1 + len, 2));
            if (ec_port)
            {
                throw abnormal::protocol("Invalid port");
            }

            co_return std::pair{domain, port};
        }

        /**
         * @brief 构建 SOCKS5 成功响应
         * @param req 请求信息，用于获取地址类型和绑定地址
         * @return std::vector<std::uint8_t> 编码后的响应数据
         */
        std::vector<std::uint8_t> build_success_response(const request &req)
        {
            std::vector<std::uint8_t> response;
            response.reserve(32); // 预分配合理大小

            // 固定头部: VER | REP | RSV | ATYP
            response.push_back(0x05);                                             // VER
            response.push_back(static_cast<std::uint8_t>(reply_code::succeeded)); // REP
            response.push_back(0x00);                                             // RSV

            // 编码地址和端口
            auto address_function = [&response]<typename Address>(const Address &addr)
            {
                if constexpr (std::is_same_v<Address, ipv4_address>)
                {
                    response.push_back(0x01); // ATYP = IPv4
                    response.insert(response.end(), addr.bytes.begin(), addr.bytes.end());
                }
                else if constexpr (std::is_same_v<Address, ipv6_address>)
                {
                    response.push_back(0x04); // ATYP = IPv6
                    response.insert(response.end(), addr.bytes.begin(), addr.bytes.end());
                }
                else if constexpr (std::is_same_v<Address, domain_address>)
                {
                    response.push_back(0x03);        // ATYP = Domain
                    response.push_back(addr.length); // 域名长度
                    response.insert(response.end(), addr.value.begin(), addr.value.begin() + addr.length);
                }
            };
            std::visit(address_function, req.destination_address);

            // 编码端口 (大端序)
            response.push_back(static_cast<std::uint8_t>((req.destination_port >> 8) & 0xFF));
            response.push_back(static_cast<std::uint8_t>(req.destination_port & 0xFF));

            return response;
        }

        Transport socket_;
    };
}
