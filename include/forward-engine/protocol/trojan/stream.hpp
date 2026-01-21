#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <array>
#include <string>
#include <string_view>
#include <vector>
#include <abnormal.hpp>
#include <forward-engine/memory.hpp>
#include <openssl/sha.h>

#include <forward-engine/protocol/trojan/constants.hpp>
#include <forward-engine/protocol/trojan/types.hpp>

namespace ngx::protocol::trojan
{
    namespace net = boost::asio;
    namespace ssl = boost::asio::ssl;
    using tcp = net::ip::tcp;

    /**
     * @brief Trojan 协议流封装
     * @tparam Transport 底层传输 Socket 类型
     */
    template <typename Transport>
    class stream
    {
    public:
        using stream_type = ssl::stream<Transport>;

        /**
         * @brief 构造函数
         * @param socket 底层 Socket (将被移动到 ssl stream 中)
         * @param ctx SSL 上下文
         * @param password_verifier 密码验证回调 (可选，用于服务器端验证)
         */
        stream(Transport socket, std::shared_ptr<ssl::context> ctx,
               std::function<bool(std::string_view)> password_verifier = nullptr)
            : stream_ptr_(std::make_shared<stream_type>(std::move(socket), *ctx)), verifier_(std::move(password_verifier))
        {
        }

        /**
         * @brief 构造函数 (使用已握手的 SSL Stream)
         * @param stream 已握手的 SSL Stream
         * @param password_verifier 密码验证回调
         */
        stream(std::shared_ptr<stream_type> stream,
               std::function<bool(std::string_view)> password_verifier = nullptr)
            : stream_ptr_(stream), verifier_(std::move(password_verifier))
        {
        }

        /**
         * @brief 执行 Trojan 握手 (包括 SSL 握手和协议头解析)
         */
        net::awaitable<target_information> handshake()
        {
            // 1. SSL 握手
            co_await stream_ptr_->async_handshake(ssl::stream_base::server, net::use_awaitable);

            // 2. 读取 Trojan 请求头
            std::string handshake_buffer;
            co_return co_await handshake_internal(handshake_buffer);
        }

        /**
         * @brief 执行 Trojan 握手 (使用预读数据)
         */
        net::awaitable<target_information> handshake_with_preread(std::string_view pre_read_data)
        {
            // 将预读数据放入缓冲区，并继续握手
            std::string buffer(pre_read_data);
            co_return co_await handshake_internal(buffer);
        }

        /**
         * @brief 读取数据
         */
        net::awaitable<std::size_t> async_read(net::mutable_buffer buffer)
        {
            co_return co_await stream_ptr_->async_read_some(buffer, net::use_awaitable);
        }

        /**
         * @brief 写入数据
         */
        net::awaitable<std::size_t> async_write(net::const_buffer buffer)
        {
            co_return co_await net::async_write(*stream_ptr_, buffer, net::use_awaitable);
        }

        /**
         * @brief 关闭连接
         */
        net::awaitable<void> close()
        {
            // 优雅关闭 SSL
            boost::system::error_code ec;
            co_await stream_ptr_->async_shutdown(net::redirect_error(net::use_awaitable, ec));
            stream_ptr_->next_layer().close(ec);
        }

        stream_type &get_stream() { return *stream_ptr_; }

    private:
        // 辅助函数：从缓冲区或流中读取指定字节
        net::awaitable<void> read_n(std::string &buffer, void *dest, std::size_t n)
        {
            std::size_t copied = 0;
            if (!buffer.empty())
            {
                std::size_t to_copy = std::min(n, buffer.size());
                std::memcpy(dest, buffer.data(), to_copy);
                buffer.erase(0, to_copy);
                copied = to_copy;
            }

            if (copied < n)
            {
                co_await net::async_read(*stream_ptr_,
                                         net::buffer(static_cast<char *>(dest) + copied, n - copied),
                                         net::use_awaitable);
            }
        }

        /**
         * @brief 内部握手处理函数
         */
        net::awaitable<target_information> handshake_internal(std::string &buffer)
        {
            // 1. 读取/检查密码哈希 (56 chars) + CRLF (2 chars) = 58 bytes

            // 如果缓冲区不足 58 字节，先读够
            if (buffer.size() < 58)
            {
                std::size_t needed = 58 - buffer.size();
                std::string temp(needed, '\0');
                co_await net::async_read(*stream_ptr_, net::buffer(temp), net::use_awaitable);
                buffer += temp;
            }

            // 此时 buffer 至少有 58 字节，但也可能更多（如果之前 pre_read 读多了）
            // 我们只取出 58 字节进行校验，剩下的留在 buffer 中给后续步骤。
            std::string_view received_hash = std::string_view(buffer).substr(0, 56);
            std::string_view crlf = std::string_view(buffer).substr(56, 2);

            if (crlf != "\r\n")
            {
                throw abnormal::protocol("Invalid Trojan request: missing CRLF after password");
            }

            // 验证密码
            if (verifier_)
            {
                if (!verifier_(received_hash))
                {
                    throw abnormal::security("Trojan authentication failed");
                }
            }

            // 消耗掉这 58 字节
            buffer.erase(0, 58);

            co_return co_await parse_request_body(buffer);
        }

        /**
         * @brief 解析 Trojan 请求体
         */
        net::awaitable<target_information> parse_request_body(std::string &buffer)
        {
            target_information info{};

            // 读取命令 (1 byte)
            std::uint8_t cmd_byte;
            co_await read_n(buffer, &cmd_byte, 1);
            info.cmd = static_cast<command>(cmd_byte);

            if (info.cmd != command::connect && info.cmd != command::udp_associate)
            {
                throw abnormal::protocol("Unsupported Trojan command");
            }

            // 读取地址类型 (1 byte)
            uint8_t atyp_byte;
            co_await read_n(buffer, &atyp_byte, 1);
            info.atyp = static_cast<address_type>(atyp_byte);

            // 解析地址
            if (info.atyp == address_type::ipv4)
            {
                std::array<uint8_t, 4> ip{};
                co_await read_n(buffer, ip.data(), 4);
                info.host = net::ip::make_address_v4(ip).to_string();
            }
            else if (info.atyp == address_type::domain)
            {
                uint8_t len = 0;
                co_await read_n(buffer, &len, 1);

                std::string domain(len, '\0');
                co_await read_n(buffer, domain.data(), len);
                info.host = std::move(domain);
            }
            else if (info.atyp == address_type::ipv6)
            {
                std::array<uint8_t, 16> ip{};
                co_await read_n(buffer, ip.data(), 16);
                info.host = net::ip::make_address_v6(ip).to_string();
            }
            else
            {
                throw abnormal::protocol("Unsupported address type");
            }

            // 解析端口 (2 bytes)
            uint16_t port_n = 0;
            co_await read_n(buffer, &port_n, 2);
            info.port = ntohs(port_n);

            // 读取最后的 CRLF (2 bytes)
            std::array<char, 2> final_crlf;
            co_await read_n(buffer, final_crlf.data(), 2);

            if (final_crlf[0] != '\r' || final_crlf[1] != '\n')
            {
                throw abnormal::protocol("Invalid Trojan request: missing final CRLF");
            }

            co_return info;
        }

        std::shared_ptr<stream_type> stream_ptr_;
        std::function<bool(std::string_view)> verifier_;
    };
}
