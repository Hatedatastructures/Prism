/**
 * @file stream.hpp
 * @brief Trojan 协议流封装
 * @details 封装了 Trojan 握手（SSL + 协议头）、预读数据处理和流读写操作。
 */
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
     * @tparam Transport 底层传输 `socket` 类型
     * @details 管理 SSL 流和 Trojan 协议的握手过程。
     */
    template <typename Transport>
    class stream
    {
    public:
        using stream_type = ssl::stream<Transport>;

        /**
         * @brief 构造函数
         * @param socket 底层 `socket` (将被移动到 SSL stream 中)
         * @param ctx SSL 上下文
         * @param credential_verifier 用户凭据验证回调 (可选，用于服务器端验证)
         */
        stream(Transport socket, std::shared_ptr<ssl::context> ctx,
               std::function<bool(std::string_view)> credential_verifier = nullptr)
            : stream_ptr_(std::make_shared<stream_type>(std::move(socket), *ctx)), verifier_(std::move(credential_verifier))
        {
        }

        /**
         * @brief 构造函数 (使用已握手的 SSL Stream)
         * @param stream 已握手的 SSL Stream
         * @param credential_verifier 用户凭据验证回调
         */
        stream(std::shared_ptr<stream_type> stream,
               std::function<bool(std::string_view)> credential_verifier = nullptr)
            : stream_ptr_(stream), verifier_(std::move(credential_verifier))
        {
        }

        /**
         * @brief 执行 Trojan 握手
         * @details 包括 SSL 握手和 Trojan 协议头读取与验证。
         * @return `std::pair<gist::code, request>` 握手结果和请求信息
         */
        auto handshake()
            -> net::awaitable<std::pair<gist::code, request>>
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
         * @details 如果在外部已经预读了部分 SSL 数据（如为了探测协议），则通过此函数继续握手。
         * @param pre_read_data 预读的数据
         * @return `std::pair<gist::code, request>` 握手结果和请求信息
         */
        auto handshake_preread(const std::string_view pre_read_data)
            -> net::awaitable<std::pair<gist::code, request>>
        {
            // 继续握手，优先消耗预读数据
            co_return co_await handshake_internal(pre_read_data);
        }

        /**
         * @brief 异步读取数据
         * @param buffer 接收缓冲区
         * @return `std::size_t` 读取的字节数
         */
        auto async_read(net::mutable_buffer buffer)
            -> net::awaitable<std::size_t>
        {
            co_return co_await stream_ptr_->async_read_some(buffer, net::use_awaitable);
        }

        /**
         * @brief 异步写入数据
         * @param buffer 发送缓冲区
         * @return `std::size_t` 写入的字节数
         */
        auto async_write(net::const_buffer buffer)
            -> net::awaitable<std::size_t>
        {
            co_return co_await net::async_write(*stream_ptr_, buffer, net::use_awaitable);
        }

        /**
         * @brief 关闭连接
         */
        auto close()
            -> net::awaitable<void>
        {
            // 优雅关闭 SSL
            boost::system::error_code ec;
            co_await stream_ptr_->async_shutdown(net::redirect_error(net::use_awaitable, ec));
            stream_ptr_->next_layer().close(ec);
        }

        /**
         * @brief 获取底层的 SSL Stream
         * @return stream_type& SSL Stream 引用
         */
        stream_type &get_stream() { return *stream_ptr_; }

    private:
        static auto error_convert(const boost::system::error_code &ec) noexcept
            -> gist::code
        {
            if (!ec)
            {
                return gist::code::success;
            }
            if (ec == net::error::eof || ec == ssl::error::stream_truncated)
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
         * @note 如果预读缓冲区有足够数据，会先从缓冲区读取；否则从流中读取。
         * @return `gist::code` 操作结果
         */
        auto read_specified_bytes(std::string_view &buffer, void *dest, const std::size_t n)
            -> net::awaitable<gist::code>
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
         * @return `gist::code` 解析结果
         */
        static auto parse_port_and_crlf(request &req, const std::span<const std::uint8_t> data) noexcept
            -> gist::code
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
         * @tparam N IP 地址字节数
         * @tparam Decoder 解码器类型
         * @param buffer 预读缓冲区引用
         * @param req 请求对象引用
         * @param decoder IP 地址解码器函数对象
         * @return `gist::code` 操作结果
         */
        template <size_t N, typename Decoder>
        auto read_ip_address(std::string_view &buffer, request &req, Decoder &&decoder)
            -> net::awaitable<gist::code>
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
         * @return `gist::code` 操作结果 (co_await 结果)
         */
        auto read_domain_address(std::string_view &buffer, request &req)
            -> net::awaitable<gist::code>
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
         * @details 包含用户凭据和头部解析结果
         */
        struct header_information
        {
            std::array<char, 56> credential; // 用户凭据
            wire::header_parse head; // 头部解析结果
        };

        /**
         * @brief 读取并验证头部
         * @param buffer 预读缓冲区引用
         * @return `std::pair<gist::code, header_information>` 操作结果和头部信息
         */
        auto read_header(std::string_view &buffer)
            -> net::awaitable<std::pair<gist::code, header_information>>
        {
            // 读取 Credential(56) + CRLF(2) + Cmd(1) + Atyp(1) = 60 bytes
            std::array<std::uint8_t, 60> head_buffer{};
            if (auto ec = co_await read_specified_bytes(buffer, head_buffer.data(), 60); ec != gist::code::success)
            {
                co_return std::pair<gist::code, header_information>{ec, header_information{}};
            }

            // 解析 Credential
            auto [ec_cred, credential] = wire::decode_credential(std::span<const std::uint8_t>(head_buffer.data(), 56));
            if (ec_cred != gist::code::success)
            {
                co_return std::pair<gist::code, header_information>{ec_cred, header_information{}};
            }

            // 验证用户凭据
            if (verifier_)
            {
                if (!verifier_(std::string_view(credential.data(), 56)))
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

            co_return std::pair<gist::code, header_information>{gist::code::success, header_information{credential, head}};
        }

        /**
         * @brief 内部握手处理函数
         * @param buffer 预读缓冲区视图
         * @return `std::pair<gist::code, request>` 握手结果和请求信息
         */
        auto handshake_internal(std::string_view buffer)
            -> net::awaitable<std::pair<gist::code, request>>
        {
            // 1. 读取并验证头部
            auto [ec_header, head_info] = co_await read_header(buffer);
            if (ec_header != gist::code::success)
            {
                co_return std::pair<gist::code, request>{ec_header, request{}};
            }

            request req;
            req.credential = head_info.credential;
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
