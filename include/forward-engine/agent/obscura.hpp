#pragma once

#include <http.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/websocket/ssl.hpp>

// 伪装层


namespace ngx::agent
{
    namespace net = boost::asio;
    namespace ssl = boost::asio::ssl;
    namespace beast = boost::beast;
    namespace websocket = beast::websocket;

    /**
     * @brief awaitable 概念  
     * @tparam T awaitable 类型
     * @note awaitable 类型必须满足以下要求：
     * 
     * - 必须有 `value_type` 类型别名，且必须是 `std::size_t` 类型
     */
    template<typename T>
    concept awaitable_size = requires
    {
        typename std::decay_t<T>::value_type;   // awaitable 必有 value_type
        requires std::convertible_to<typename std::decay_t<T>::value_type, std::size_t>;
    };

    /**
     * @brief 流式 socket 概念
     * @tparam T socket 类型
     * @note 必须满足基础 socket 行为，并支持流式读写
     */
    template <typename T>
    concept stream_concept = requires(T& s, net::mutable_buffer mb, net::const_buffer cb)
    {
        { s.async_read_some(mb, net::use_awaitable) } -> awaitable_size;
        { s.async_write_some(cb, net::use_awaitable) } -> awaitable_size;
    };

    /**
     * @brief 数据报 socket 概念
     * @tparam T socket 类型
     * @note 必须满足基础 socket 行为，并支持数据报式读写
     */
    template <typename T>
    concept datagram_socket = requires(T& s, net::mutable_buffer mb, net::const_buffer cb)
    {
        { s.async_receive(mb, net::use_awaitable) } -> awaitable_size;
        { s.async_send(cb, net::use_awaitable) } -> awaitable_size;
    };

    /**
     * @brief socket 概念
     * @tparam T socket 类型
     * @note 必须满足基础 socket 行为（Executor、Close），并支持流式或数据报式读写
     */
    template <typename T>
    concept socket_concept = requires(T& s)
    {
        { s.get_executor() };
        { s.close() };
        requires stream_concept<T> || datagram_socket<T>;
    };

    /**
     * @brief 协议概念
     * @tparam protocol_type 协议类型
     * @note 协议类型必须满足以下要求：
     * 
     * - 必须有 `endpoint` 类型别名
     * 
     * - 必须有 `resolver` 类型别名
     * 
     * - 必须有 `socket` 类型别名，且必须是 `socket_concept` 类型
     */
    template <typename protocol_type>
    concept protocol_concept = requires
    {
       typename protocol_type::endpoint;
       typename protocol_type::resolver;
       typename protocol_type::socket;
       requires socket_concept<typename protocol_type::socket>;
    };

    /**
     * @brief 角色枚举
     * @note 角色枚举用于指定 obscura 实例的角色，分为 client 和 server 两种模式。
     */
    enum class role
    {
        /**
         * @brief 客户端角色
         */
        client,
        /**
         * @brief 服务端角色
         */
        server
    };

    /**
     * @brief 暗箱容器
     * @tparam protocol_concept 协议类型
     * @note obscura 暗箱容器用于实现建立伪装流量的暗箱通道，支持 client 和 server 两种模式
     */
    template <protocol_concept protocol>
    class obscura : public std::enable_shared_from_this<obscura<protocol>>
    {
        using ssl_request = beast::http::request<beast::http::empty_body>;
    public:
        using socket_type = typename protocol::socket;

        /**
         * @brief 构造函数
         * @param socket 原始 socket
         * @param ssl_context SSL 上下文（共享所有权）
         * @param r 角色
         */
        obscura(socket_type socket, std::shared_ptr<net::ssl::context> ssl_context, role r = role::server);
        obscura(const obscura&) = delete;
        obscura& operator=(const obscura&) = delete;

        net::awaitable<std::string> handshake(std::string_view host = "", std::string_view path = "/");

        // 读取数据到外部缓冲区，返回读取字节数
        net::awaitable<std::size_t> async_read(beast::flat_buffer& buffer);
        net::awaitable<void> async_write(std::string_view data);

        net::awaitable<void> close()
        {
            co_await wsocket.async_close(websocket::close_code::normal, net::use_awaitable);
        }

    private:
        role role_;
        std::shared_ptr<ssl::context> ssl_context_;
        ssl::stream<socket_type> ssl_stream;
        websocket::stream<ssl::stream<socket_type>&> wsocket{ssl_stream};
    }; // class obscura

    template <protocol_concept protocol>
    obscura<protocol>::obscura(socket_type socket, std::shared_ptr<net::ssl::context> context, role r)
    : role_(r), ssl_context_(std::move(context)), ssl_stream(std::move(socket), *ssl_context_), wsocket(ssl_stream)
    {
        wsocket.binary(true);
    }

    /**
     * @brief 握手
     * @param host 目标主机（仅 Client 模式需要，Server 模式忽略）
     * @param path 请求路径（仅 Client 模式需要，Server 模式忽略）
     * @return std::string 对于 Server 模式，返回请求的目标路径；对于 Client 模式，返回空串。
     */
    template <protocol_concept protocol>
    net::awaitable<std::string> obscura<protocol>::handshake(std::string_view host, std::string_view path)
    {
        if (role_ == role::server)
        {
            // Server 模式：SSL 握手 -> 接收 HTTP -> 升级 WebSocket
            co_await ssl_stream.async_handshake(ssl::stream_base::server, net::use_awaitable);
            
            beast::flat_buffer buffer;
            beast::http::request<beast::http::string_body> req;
            co_await beast::http::async_read(ssl_stream, buffer, req, net::use_awaitable);

            // 传递 buffer 以处理预读数据，Beast 会消耗掉它
            co_await wsocket.async_accept(req, net::use_awaitable);
            
            co_return std::string(req.target());
        }
        else
        {
            // Client 模式：SSL 握手 -> 发送 HTTP -> 升级 WebSocket
            
            // 如果提供了 host，可以设置 SNI (Server Name Indication)
            if (!host.empty())
            {
                if(!SSL_set_tlsext_host_name(ssl_stream.native_handle(), std::string(host).c_str()))
                {
                    // SNI 设置失败通常不是致命的，但为了健壮性可以记录或抛出
                    // 这里暂时忽略，继续握手
                }
            }

            co_await ssl_stream.async_handshake(ssl::stream_base::client, net::use_awaitable);
            
            std::string h = host.empty() ? "localhost" : std::string(host);
            co_await wsocket.async_handshake(h, path, net::use_awaitable);
            
            co_return "";
        }
    }

    /**
     * @brief 读取数据
     * @param buffer 外部缓冲区
     * @return std::size_t 读取到的字节数
     */
    template <protocol_concept protocol>
    net::awaitable<std::size_t> obscura<protocol>::async_read(beast::flat_buffer& buffer)
    {
        // 直接读取到外部 buffer
        // 之前这里的 buffer_ 逻辑已移除，因为 handshake 中的 buffer 是局部的，不会有残留问题
        std::size_t n = co_await wsocket.async_read(buffer, net::use_awaitable);
        co_return n;
    }

    /**
     * @brief 写入数据
     * @param data 要写入的数据
     */
    template <protocol_concept protocol>
    net::awaitable<void> obscura<protocol>::async_write(std::string_view data)
    {
        co_await wsocket.async_write(net::buffer(data), net::use_awaitable);
    }
} // namespace ngx::agent