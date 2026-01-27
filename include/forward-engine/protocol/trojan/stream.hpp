#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <array>
#include <string>
#include <string_view>
#include <forward-engine/gist.hpp>

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
        net::awaitable<std::pair<gist::code, request>> handshake()
        {
            // 1. SSL 握手
            boost::system::error_code ec;
            co_await stream_ptr_->async_handshake(ssl::stream_base::server, net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                co_return std::pair<gist::code, request>{gist::code::tls_handshake_failed, request{}};
            }

            // 2. 读取 Trojan 请求头
            co_return co_await handshake_internal({});
        }

        /**
         * @brief 执行 Trojan 握手 (使用预读数据)
         */
        net::awaitable<std::pair<gist::code, request>> handshake_preread(const std::string_view pre_read_data)
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
        static gist::code error_convert(const boost::system::error_code &ec) noexcept
        {
            if (!ec)
            {
                return gist::code::success;
            }
            if (ec == net::error::eof)
            {
                return gist::code::eof;
            }
            if (ec == net::error::operation_aborted)
            {
                return gist::code::canceled;
            }
            if (ec == net::error::would_block || ec == net::error::try_again)
            {
                return gist::code::would_block;
            }
            return gist::code::io_error;
        }

        /**
         * @brief 从预读缓冲区或流中读取指定字节
         * @param buffer 预读缓冲区引用
         * @param dest 目标内存地址
         * @param n 要读取的字节数
         * @note 如果预读缓冲区有足够数据，会先从缓冲区读取；否则从流中读取
         */
        net::awaitable<gist::code> read_specified_bytes(std::string_view &buffer, void *dest, const std::size_t n)
        {
            std::size_t copied = 0;
            if (!buffer.empty())
            {
                const std::size_t to_copy = std::min(n, buffer.size());
                std::memcpy(dest, buffer.data(), to_copy);
                buffer.remove_prefix(to_copy);
                copied = to_copy;
            }

            if (copied < n)
            {
                boost::system::error_code ec;
                auto buffer_container = net::buffer(static_cast<char *>(dest) + copied, n - copied);
                co_await net::async_read(*stream_ptr_,buffer_container,
                net::redirect_error(net::use_awaitable, ec));
                if (ec)
                {
                    co_return error_convert(ec);
                }
            }
            co_return gist::code::success;
        }

        /**
         * @brief 解析端口和 CRLF
         * @param req 请求对象引用
         * @param data 包含端口和 CRLF 的数据视图
         * @throws abnormal::protocol 如果端口或 CRLF 无效
         */
        static gist::code parse_port_and_crlf(request &req, const std::span<const std::uint8_t> data)
        {
            auto [ec_port, port] = wire::decode_port(data.subspan(0, 2));
            if (ec_port != gist::code::success)
            {
                return ec_port;
            }
            req.port = port;

            if (const auto ec = wire::decode_crlf(data.subspan(2, 2)); ec != gist::code::success)
            {
                return ec;
            }
            return gist::code::success;
        }

        /**
         * @brief 读取 IP 地址类型的请求
         * @param buffer 预读缓冲区引用
         * @param req 请求对象引用
         * @param decoder IP 地址解码器函数对象
         * @param error_msg 错误消息字符串
         * @throws abnormal::protocol 如果 IP 地址或端口无效
         */
        template <size_t N, typename Decoder>
        net::awaitable<gist::code> read_ip_address(std::string_view &buffer, request &req, Decoder &&decoder)
        {
            std::array<std::uint8_t, N + 4> data; // IP(N) + Port(2) + CRLF(2)
            if (auto ec = co_await read_specified_bytes(buffer, data.data(), N + 4); ec != gist::code::success)
            {
                co_return ec;
            }

            auto [ec_decode, ip] = decoder(std::span<const std::uint8_t>(data.data(), N));
            if (ec_decode != gist::code::success)
            {
                co_return ec_decode;
            }
            req.destination_address = ip;

            co_return parse_port_and_crlf(req, std::span<const std::uint8_t>(data.data() + N, 4));
        }

        /**
         * @brief 读取域名类型的请求
         * @param buffer 预读缓冲区引用
         * @param req 请求对象引用
         * @throws abnormal::protocol 如果域名或端口无效
         */
        net::awaitable<gist::code> read_domain_address(std::string_view &buffer, request &req)
        {
            std::uint8_t len = 0;
            if (auto ec = co_await read_specified_bytes(buffer, &len, 1); ec != gist::code::success)
            {
                co_return ec;
            }

            std::array<std::uint8_t, 259> data{}; // Max domain(255) + Port(2) + CRLF(2)
            if (auto ec = co_await read_specified_bytes(buffer, data.data(), len + 4); ec != gist::code::success)
            {
                co_return ec;
            }

            // 构造 decode_domain 需要的 [len, body...] 格式
            std::array<std::uint8_t, 256> dom_buf{};
            dom_buf[0] = len;
            std::memcpy(dom_buf.data() + 1, data.data(), len);

            auto [ec, dom] = wire::decode_domain(std::span<const std::uint8_t>(dom_buf.data(), len + 1));
            if (ec != gist::code::success)
            {
                co_return ec;
            }
            req.destination_address = dom;

            co_return parse_port_and_crlf(req, std::span<const std::uint8_t>(data.data() + len, 4));
        }

        /**
         * @brief 头部信息结构体
         * @details 包含密码哈希和头部解析结果
         */
        struct header_information
        {
            std::array<char, 56> hash; // 密码哈希
            wire::header_parse head;
        };

        /**
         * @brief 读取并验证头部
         * @param buffer 预读缓冲区引用
         * @return `header_information` 包含密码哈希和头部解析结果
         * @throws abnormal::protocol 如果密码哈希、CRLF、命令或地址类型无效
         */
        net::awaitable<std::pair<gist::code, header_information>> read_header(std::string_view &buffer)
        {
            // 读取 Hash(56) + CRLF(2) + Cmd(1) + Atyp(1) = 60 bytes
            std::array<std::uint8_t, 60> head_buffer{};
            if (auto ec = co_await read_specified_bytes(buffer, head_buffer.data(), 60); ec != gist::code::success)
            {
                co_return std::pair<gist::code, header_information>{ec, header_information{}};
            }

            // 解析 Hash
            auto [ec_hash, hash] = wire::decode_hash(std::span<const std::uint8_t>(head_buffer.data(), 56));
            if (ec_hash != gist::code::success)
            {
                co_return std::pair<gist::code, header_information>{ec_hash, header_information{}};
            }

            // 验证密码
            if (verifier_)
            {
                if (!verifier_(std::string_view(hash.data(), 56)))
                {
                    co_return std::pair<gist::code, header_information>{gist::code::auth_failed, header_information{}};
                }
            }

            // 验证 CRLF
            if (auto ec = wire::decode_crlf(std::span<const std::uint8_t>(head_buffer.data() + 56, 2)); ec != gist::code::success)
            {
                co_return std::pair<gist::code, header_information>{ec, header_information{}};
            }

            // 解析 Cmd + Atyp
            auto [ec_head, head] = wire::decode_cmd_atyp(std::span<const std::uint8_t>(head_buffer.data() + 58, 2));
            if (ec_head != gist::code::success)
            {
                co_return std::pair<gist::code, header_information>{ec_head, header_information{}};
            }

            co_return std::pair<gist::code, header_information>{gist::code::success, header_information{hash, head}};
        }

        /**
         * @brief 内部握手处理函数
         * @param buffer 预读缓冲区视图
         * @return `request` 包含解析后的请求信息
         * @throws abnormal::protocol 如果头部、命令、地址类型或地址无效
         */
        net::awaitable<std::pair<gist::code, request>> handshake_internal(std::string_view buffer)
        {
            // 1. 读取并验证头部
            auto [ec_header, head_info] = co_await read_header(buffer);
            if (ec_header != gist::code::success)
            {
                co_return std::pair<gist::code, request>{ec_header, request{}};
            }

            request req;
            req.password_hash = head_info.hash;
            req.cmd = head_info.head.cmd;

            if (req.cmd != command::connect && req.cmd != command::udp_associate)
            { // 校验命令是否支持
                co_return std::pair<gist::code, request>{gist::code::unsupported_command, request{}};
            }

            // 2. 解析地址 + 端口 + CRLF
            gist::code ec = gist::code::success;
            switch (head_info.head.atyp)
            {
            case address_type::ipv4:
                ec = co_await read_ip_address<4>(buffer, req, wire::decode_ipv4);
                break;
            case address_type::ipv6:
                ec = co_await read_ip_address<16>(buffer, req, wire::decode_ipv6);
                break;
            case address_type::domain:
                ec = co_await read_domain_address(buffer, req);
                break;
            default:
                ec = gist::code::unsupported_address;
            }

            if (ec != gist::code::success)
            {
                co_return std::pair<gist::code, request>{ec, request{}};
            }

            co_return std::pair<gist::code, request>{gist::code::success, req};
        }

        std::shared_ptr<stream_type> stream_ptr_;
        std::function<bool(std::string_view)> verifier_;
    };
}
