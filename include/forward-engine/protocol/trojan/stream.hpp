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
#include <forward-engine/protocol/trojan/message.hpp>
#include <forward-engine/protocol/trojan/wire.hpp>

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
        net::awaitable<request> handshake()
        {
            // 1. SSL 握手
            co_await stream_ptr_->async_handshake(ssl::stream_base::server, net::use_awaitable);

            // 2. 读取 Trojan 请求头
            co_return co_await handshake_internal({});
        }

        /**
         * @brief 执行 Trojan 握手 (使用预读数据)
         */
        net::awaitable<request> handshake_preread(std::string_view pre_read_data)
        {
            // 继续握手，优先消耗预读数据
            co_return co_await handshake_internal(pre_read_data);
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
        /**
         * @brief 从预读缓冲区或流中读取指定字节
         * @param buffer 预读缓冲区引用
         * @param dest 目标内存地址
         * @param n 要读取的字节数
         * @note 如果预读缓冲区有足够数据，会先从缓冲区读取；否则从流中读取
         */
        net::awaitable<void> read_specified_bytes(std::string_view &buffer, void *dest, std::size_t n)
        {
            std::size_t copied = 0;
            if (!buffer.empty())
            {
                std::size_t to_copy = std::min(n, buffer.size());
                std::memcpy(dest, buffer.data(), to_copy);
                buffer.remove_prefix(to_copy);
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
         * @param buffer 预读缓冲区
         * @return request 解析后的 `Trojan` 协议请求
         * @note 如果传进来的 `buffer` 为空那么就直接去调用 `async_read` 去读取 `"read_specified_bytes"` 函数
         */
        net::awaitable<request> handshake_internal(std::string_view buffer)
        {
            // 1. 读取 Hash(56) + CRLF(2) + Cmd(1) + Atyp(1) = 60 bytes
            // 一次性读取，减少 IO 次数
            std::array<std::uint8_t, 60> head_buffer;
            co_await read_specified_bytes(buffer, head_buffer.data(), 60);

            // 解析 Hash
            auto [ec_hash, hash] = wire::decode_hash(std::span<const std::uint8_t>(head_buffer.data(), 56));
            if (ec_hash)
            {
                throw abnormal::protocol("Invalid Trojan request: invalid password hash");
            }

            // 验证密码
            if (verifier_)
            {
                if (!verifier_(std::string_view(hash.data(), 56)))
                {
                    throw abnormal::security("Trojan authentication failed");
                }
            }

            // 验证 CRLF
            if (auto ec = wire::decode_crlf(std::span<const std::uint8_t>(head_buffer.data() + 56, 2)); ec)
            {
                throw abnormal::protocol("Invalid Trojan request: missing CRLF after password");
            }

            // 解析 Cmd + Atyp
            auto [ec_head, head] = wire::decode_cmd_atyp(std::span<const std::uint8_t>(head_buffer.data() + 58, 2));
            if (ec_head)
            {
                throw abnormal::protocol("Invalid Trojan request: invalid command or address type");
            }

            request req;
            req.password_hash = hash;
            req.cmd = head.cmd;

            if (req.cmd != command::connect && req.cmd != command::udp_associate)
            {
                throw abnormal::protocol("Unsupported Trojan command");
            }

            // 2. 解析地址 + 端口 + CRLF
            // 根据 Atyp 读取后续数据
            if (head.atyp == address_type::ipv4)
            {
                // IPv4(4) + Port(2) + CRLF(2) = 8 bytes
                std::array<std::uint8_t, 8> data_buffer;
                co_await read_specified_bytes(buffer, data_buffer.data(), 8);

                auto [ec, ip] = wire::decode_ipv4(std::span<const std::uint8_t>(data_buffer.data(), 4));
                if (ec) throw abnormal::protocol("Invalid IPv4 address");
                req.destination_address = ip;

                auto [ec_port, port] = wire::decode_port(std::span<const std::uint8_t>(data_buffer.data() + 4, 2));
                if (ec_port) throw abnormal::protocol("Invalid port");
                req.port = port;

                if (auto ec_crlf = wire::decode_crlf(std::span<const std::uint8_t>(data_buffer.data() + 6, 2)); ec_crlf)
                    throw abnormal::protocol("Invalid Trojan request: missing final CRLF");
            }
            else if (head.atyp == address_type::ipv6)
            {
                // IPv6(16) + Port(2) + CRLF(2) = 20 bytes
                std::array<std::uint8_t, 20> data_buffer;
                co_await read_specified_bytes(buffer, data_buffer.data(), 20);

                auto [ec, ip] = wire::decode_ipv6(std::span<const std::uint8_t>(data_buffer.data(), 16));
                if (ec) throw abnormal::protocol("Invalid IPv6 address");
                req.destination_address = ip;

                auto [ec_port, port] = wire::decode_port(std::span<const std::uint8_t>(data_buffer.data() + 16, 2));
                if (ec_port) throw abnormal::protocol("Invalid port");
                req.port = port;

                if (auto ec_crlf = wire::decode_crlf(std::span<const std::uint8_t>(data_buffer.data() + 18, 2)); ec_crlf)
                    throw abnormal::protocol("Invalid Trojan request: missing final CRLF");
            }
            else if (head.atyp == address_type::domain)
            {
                // Domain: Length(1) -> Read N -> Port(2) -> CRLF(2)
                std::uint8_t len = 0;
                co_await read_specified_bytes(buffer, &len, 1);
                
                // Read Domain Body(len) + Port(2) + CRLF(2)
                // Max domain len 255 + 4 = 259
                std::array<std::uint8_t, 259> data_buffer;
                co_await read_specified_bytes(buffer, data_buffer.data(), len + 4);
                
                // Reconstruct domain buffer for decoder: Length(1) + Value(N)
                // wire::decode_domain expects [Length, Value...]
                // We have Length separately, and Value in data_buffer.
                // To reuse wire::decode_domain easily, we can construct a temp buffer or just manual copy
                // But wire::decode_domain expects the buffer start with len.
                
                std::array<std::uint8_t, 256> dom_decoder_buf;
                dom_decoder_buf[0] = len;
                std::memcpy(dom_decoder_buf.data() + 1, data_buffer.data(), len);

                auto [ec, dom] = wire::decode_domain(std::span<const std::uint8_t>(dom_decoder_buf.data(), len + 1));
                if (ec) throw abnormal::protocol("Invalid domain address");
                req.destination_address = dom;

                auto [ec_port, port] = wire::decode_port(std::span<const std::uint8_t>(data_buffer.data() + len, 2));
                if (ec_port) throw abnormal::protocol("Invalid port");
                req.port = port;

                if (auto ec_crlf = wire::decode_crlf(std::span<const std::uint8_t>(data_buffer.data() + len + 2, 2)); ec_crlf)
                    throw abnormal::protocol("Invalid Trojan request: missing final CRLF");
            }
            else
            {
                throw abnormal::protocol("Unsupported address type");
            }

            co_return req;
        }

        std::shared_ptr<stream_type> stream_ptr_;
        std::function<bool(std::string_view)> verifier_;
    };
}
