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

    using openssl_context = SSL*;

    static inline constinit std::string_view fingerprint = {
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"};

    /**
     * @brief awaitable 概念  
     * @tparam T awaitable 类型
     * @note awaitable 类型必须满足以下要求：
     * 
     * - 必须有 `value_type` 类型别名，且必须是 `std::size_t` 类型
     */
    template<typename T>
    concept AwaitableSize = requires
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
    concept StreamConcept = requires(T& s, net::mutable_buffer mb, net::const_buffer cb)
    {
        { s.async_read_some(mb, net::use_awaitable) } -> AwaitableSize;
        { s.async_write_some(cb, net::use_awaitable) } -> AwaitableSize;
    };

    /**
     * @brief 数据报 socket 概念
     * @tparam T socket 类型
     * @note 必须满足基础 socket 行为，并支持数据报式读写
     */
    template <typename T>
    concept DatagramSocket = requires(T& s, net::mutable_buffer mb, net::const_buffer cb)
    {
        { s.async_receive(mb, net::use_awaitable) } -> AwaitableSize;
        { s.async_send(cb, net::use_awaitable) } -> AwaitableSize;
    };

    /**
     * @brief socket 概念
     * @tparam T socket 类型
     * @note 必须满足基础 socket 行为（Executor、Close），并支持流式或数据报式读写
     */
    template <typename T>
    concept SocketConcept = requires(T& s)
    {
        { s.get_executor() };
        { s.close() };
        requires StreamConcept<T> || DatagramSocket<T>;
    };

    /**
     * @brief 协议概念
     * @tparam ProtocolType 协议类型
     * @note 协议类型必须满足以下要求：
     * 
     * - 必须有 `endpoint` 类型别名
     * 
     * - 必须有 `resolver` 类型别名
     * 
     * - 必须有 `socket` 类型别名，且必须是 `SocketConcept` 类型
     */
    template <typename ProtocolType>
    concept ProtocolConcept = requires
    {
       typename ProtocolType::endpoint;
       typename ProtocolType::resolver;
       typename ProtocolType::socket;
       requires SocketConcept<typename ProtocolType::socket>;
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
     * @tparam Protocol 协议类型
     * @note obscura 暗箱容器用于实现建立伪装流量的暗箱通道，支持 client 和 server 两种模式
     */
    template <ProtocolConcept Protocol>
    class obscura : public std::enable_shared_from_this<obscura<Protocol>>
    {
        using ssl_request = beast::http::request<beast::http::empty_body>;
    public:
        using socket_type = typename Protocol::socket;

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
            co_await wsocket_.async_close(websocket::close_code::normal, net::use_awaitable);
        }

    private:
        role role_;
        std::shared_ptr<ssl::context> ssl_context_;
        ssl::stream<socket_type> ssl_stream_;
        websocket::stream<ssl::stream<socket_type>&> wsocket_{ssl_stream_};
    }; // class obscura

    template <ProtocolConcept Protocol>
    obscura<Protocol>::obscura(socket_type socket, std::shared_ptr<net::ssl::context> context, role r)
    : role_(r), ssl_context_(std::move(context)), ssl_stream_(std::move(socket), *ssl_context_), wsocket_(ssl_stream_)
    {
        wsocket_.binary(true);
    }

    /**
     * @brief 握手
     * @param host 目标主机（仅 Client 模式需要，Server 模式忽略）
     * @param path 请求路径（仅 Client 模式需要，Server 模式忽略）
     * @return std::string 对于 Server 模式，返回请求的目标路径；对于 Client 模式，返回空串。
     */
    template <ProtocolConcept Protocol>
    net::awaitable<std::string> obscura<Protocol>::handshake(std::string_view host, std::string_view path)
    {
        beast::get_lowest_layer(wsocket_).expires_never();
        wsocket_.set_option(websocket::stream_base::timeout::suggested(static_cast<beast::role_type>(role_)));

        auto camouflage = [](websocket::request_type &req)
        {
            req.set(beast::http::field::user_agent,
                std::string(BOOST_BEAST_VERSION_STRING) + " websocket-client-coro");
        };
        // 2. 伪装 WebSocket User-Agent
        wsocket_.set_option(websocket::stream_base::decorator(camouflage));

        // ==============================================================
        // 核心修改：BoringSSL 指纹注入 & 显式 TLS 握手
        // ==============================================================
        
        // 获取 WebSocket 包裹的底层 SSL 流
        auto& ssl_stream = wsocket_.next_layer();
        
        // 获取 BoringSSL 原生句柄
        openssl_context ssl = ssl_stream.native_handle();

        if (role_ == role::client)
        {
            // [Step 1] 配置 BoringSSL 指纹 (必须在握手前完成)
            
            // A. 设置 SNI (即使是 IP 直连，BoringSSL 也最好设置这个，防止报错)
            if (!host.empty())
            {
                SSL_set_tlsext_host_name(ssl, std::string(host).c_str());
            }

            // B. 强制设置加密套件 (模拟 Chrome)
            // 使用你定义的 fingerprint 变量
            SSL_set_cipher_list(ssl, fingerprint.data());

            // C. 设置 ALPN (关键：宣称支持 h2 和 http/1.1)
            // 格式：[长度][字符]...
            constexpr unsigned char alpn[] = "\x02h2\x08http/1.1";
            SSL_set_alpn_protos(ssl, alpn, sizeof(alpn) - 1);

            // [Step 2] 先进行 SSL 握手
            // WebSocket 握手是应用层数据，必须跑在 TLS 隧道建立之后
            co_await ssl_stream.async_handshake(ssl::stream_base::client, net::use_awaitable);

            // [Step 3] 再进行 WebSocket 握手
            co_await wsocket_.async_handshake(host, path, net::use_awaitable);
        }
        else // Server 模式
        {
            // [Step 1] 服务端 SSL 握手
            co_await ssl_stream.async_handshake(ssl::stream_base::server, net::use_awaitable);

            // [Step 2] 服务端 WebSocket 握手 (Accept)
            co_await wsocket_.async_accept(net::use_awaitable);
        }

        co_return "";
    }

    /**
     * @brief 读取数据
     * @param buffer 外部缓冲区
     * @return std::size_t 读取到的字节数
     */
    template <ProtocolConcept protocol>
    net::awaitable<std::size_t> obscura<protocol>::async_read(beast::flat_buffer& buffer)
    {
        // 直接读取到外部 buffer
        // 之前这里的 buffer_ 逻辑已移除，因为 handshake 中的 buffer 是局部的，不会有残留问题
        std::size_t n = co_await wsocket_.async_read(buffer, net::use_awaitable);
        co_return n;
    }

    /**
     * @brief 写入数据
     * @param data 要写入的数据
     */
    template <ProtocolConcept protocol>
    net::awaitable<void> obscura<protocol>::async_write(std::string_view data)
    {
        co_await wsocket_.async_write(net::buffer(data), net::use_awaitable);
    }
} // namespace ngx::agent