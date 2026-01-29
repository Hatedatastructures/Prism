#pragma once

#include <forward-engine/protocol/http.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/websocket/ssl.hpp>

// 伪装器

/**
 * @namespace ngx::transport
 * @brief 传输层 (Data Plane)
 * @details 负责底层的数据搬运、连接管理和协议封装。
 */
namespace ngx::transport
{
    namespace net = boost::asio;
    namespace ssl = boost::asio::ssl;
    namespace beast = boost::beast;
    namespace websocket = beast::websocket;

    using openssl_context = SSL *;

    /**
     * @brief TLS 指纹 (JA3/JA4)
     * @details 用于模拟 Chrome 浏览器的 TLS 指纹，以绕过流量识别。
     */
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
    template <typename T>
    concept AwaitableSize = requires
    {
        typename std::decay_t<T>::value_type; // awaitable 必有 value_type
        requires std::convertible_to<typename std::decay_t<T>::value_type, std::size_t>;
    };

    /**
     * @brief 流式 socket 概念
     * @tparam T socket 类型
     * @note 必须满足基础 socket 行为，并支持流式读写
     */
    template <typename T>
    concept StreamConcept = requires(T &s, net::mutable_buffer mb, net::const_buffer cb)
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
    concept DatagramSocket = requires(T &s, net::mutable_buffer mb, net::const_buffer cb)
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
    concept SocketConcept = requires(T &s)
    {
        { s.get_executor() };
        { s.close() };
        requires StreamConcept<T> || DatagramSocket<T>;
    };

    /**
     * @brief 传输概念
     * @tparam TransportType 传输类型
     * @note 传输类型必须满足以下要求：
     *
     * - 必须有 `endpoint` 类型别名
     *
     * - 必须有 `resolver` 类型别名
     *
     * - 必须有 `socket` 类型别名，且必须是 `SocketConcept` 类型
     */
    template <typename TransportType>
    concept TransportConcept = requires
    {
        typename TransportType::endpoint;
        typename TransportType::resolver;
        typename TransportType::socket;
        requires SocketConcept<typename TransportType::socket>;
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
     * @brief 暗箱容器 (Obscura)
     * @tparam Transport 传输类型
     * @details `obscura` 是一个高级传输封装，用于将普通的 TCP 流量伪装成 WebSocket + TLS 流量。
     * 
     * **工作原理**：
     * 1. **TLS 握手**：首先建立 TLS 安全连接，并注入 Chrome 指纹。
     * 2. **WebSocket 握手**：在 TLS 之上建立 WebSocket 连接，伪装成普通的 Web 浏览行为。
     * 3. **数据传输**：将实际数据作为 WebSocket 二进制帧传输。
     * 
     * @note 支持 Client 和 Server 两种模式。
     */
    template <TransportConcept Transport>
    class obscura : public std::enable_shared_from_this<obscura<Transport>>
    {
        using ssl_request = beast::http::request<beast::http::empty_body>;
        using ssl_stream_type = ssl::stream<typename Transport::socket>;

    public:
        using socket_type = typename Transport::socket;

        /**
         * @brief 构造函数
         * @param socket 原始 socket
         * @param context SSL 上下文（共享所有权）
         * @param r 角色
         */
        obscura(socket_type socket, std::shared_ptr<ssl::context> context, role r = role::server);

        /**
         * @brief 构造函数 (使用已握手的 SSL Stream)
         * @param stream 已握手的 SSL Stream
         * @param r 角色
         */
        explicit obscura(std::shared_ptr<ssl_stream_type> stream, const role r = role::server)
            : role_(r), ssl_stream_ptr_(stream), wsocket_(*ssl_stream_ptr_)
        {
            wsocket_.binary(true);
        }

        obscura(const obscura &) = delete;
        obscura &operator=(const obscura &) = delete;

        /**
         * @brief 执行握手
         * @param host 目标主机 (Client 模式)
         * @param path 请求路径 (Client 模式)
         * @return `std::string` 对于 Server，返回请求路径；对于 Client，返回空串。
         */
        auto handshake(std::string_view host = "", std::string_view path = "/")
            -> net::awaitable<std::string>;

        /**
         * @brief 执行握手 (预读模式)
         * @details 专门用于处理已读取了部分数据的 SSL Stream (例如经过协议探测后)。
         * @param pre_read_data 之前 peek 到的数据
         * @return `std::string` 请求路径
         */
        auto handshake_preread(std::string_view pre_read_data)
            -> net::awaitable<std::string>;

        /**
         * @brief 异步读取数据
         * @param buffer 外部缓冲区
         * @return `std::size_t` 读取的字节数
         */
        auto async_read(beast::flat_buffer &buffer)
            -> net::awaitable<std::size_t>;
        
        /**
         * @brief 写入数据
         * @param data 要写入的数据
         */
        auto async_write(std::string_view data)
            -> net::awaitable<void>;

        /**
         * @brief 关闭连接
         * @details 发送 WebSocket 关闭帧并断开连接。
         */
        auto close()
            -> net::awaitable<void>
        {
            co_await wsocket_.async_close(websocket::close_code::normal, net::use_awaitable);
        }

    private:
        role role_;
        std::shared_ptr<ssl::context> ssl_context_;

        // 兼容两种模式：
        // 1. 拥有 socket 的 stream (构造时传入 socket)
        // 2. 引用外部 stream (构造时传入 stream shared_ptr)

        // 方案：统一使用 shared_ptr<ssl::stream>
        // 如果是构造 1，则 make_shared 创建
        std::shared_ptr<ssl_stream_type> ssl_stream_ptr_;

        websocket::stream<ssl_stream_type &> wsocket_;
    }; // class obscura

    template <TransportConcept Transport>
    obscura<Transport>::obscura(socket_type socket, std::shared_ptr<ssl::context> context, role r)
        : role_(r), ssl_context_(std::move(context)),
          ssl_stream_ptr_(std::make_shared<ssl_stream_type>(std::move(socket), *ssl_context_)),
          wsocket_(*ssl_stream_ptr_)
    {
        wsocket_.binary(true);
    }


    /**
     * @brief 握手
     * @param host 目标主机（仅 Client 模式需要，Server 模式忽略）
     * @param path 请求路径（仅 Client 模式需要，Server 模式忽略）
     * @return std::string 对于 Server 模式，返回请求的目标路径；对于 Client 模式，返回空串。
     */
    template <TransportConcept Transport>
    auto obscura<Transport>::handshake(std::string_view host, std::string_view path)
        -> net::awaitable<std::string>
    {
        /**
         * @bug 原生 Asio Socket 没有 expires_never() 这个函数。它默认就是永不超时。
         */
        // beast::get_lowest_layer(wsocket_).expires_never();

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
        auto &ssl_stream = wsocket_.next_layer();

        // 获取 BoringSSL 原生句柄
        openssl_context ssl = ssl_stream.native_handle();

        if (role_ == role::client)
        {
            // ... (Client 逻辑保持不变，因为 Session 只做 Server)
            // [Step 1] 配置 BoringSSL 指纹
            // ...
            // [Step 2] 先进行 SSL 握手
            co_await ssl_stream.async_handshake(ssl::stream_base::client, net::use_awaitable);

            // [Step 3] 再进行 WebSocket 握手
            co_await wsocket_.async_handshake(host, path, net::use_awaitable);
        }
        if (role_ == role::server)
        {
            // [Step 1] 服务端 SSL 握手
            co_await ssl_stream.async_handshake(ssl::stream_base::server, net::use_awaitable);

            // [Step 2] 服务端 WebSocket 握手 (Accept)
            ssl_request req;
            co_await wsocket_.async_accept(req, net::use_awaitable);
            co_return std::string(req.target());
        }

        co_return "";
    }

    /**
     * @brief 读取握手前的数据
     * @param pre_read_data 之前 peek 到的数据，需要重新通过 websocket 握手消费
     * @return std::string 对于 Server 模式，返回请求的目标路径；对于 Client 模式，返回空串。
     * @note 这个函数是在 Server 模式下使用的，用于处理 Client 发送的握手数据。
     */
    template <TransportConcept Transport>
    auto obscura<Transport>::handshake_preread(std::string_view pre_read_data)
        -> net::awaitable<std::string>
    {
        if (role_ != role::server)
        {
            co_return "";
        }

        wsocket_.set_option(websocket::stream_base::timeout::suggested(static_cast<beast::role_type>(role_)));

        std::string target_path;
        // 1. 预解析获取 target (因为 Beast async_accept(buffer) 重载不暴露 req 对象)
        {
            beast::http::request_parser<beast::http::empty_body> parser;
            beast::error_code ec;
            parser.eager(true); // 仅解析头部

            const auto buf = net::buffer(pre_read_data.data(), pre_read_data.size());
            parser.put(buf, ec);

            // 只要解析开始了，尝试提取 target（即使不完整，如果第一行完整即可）
            // 注意：如果数据太少可能还没解析出 target，这种情况下 target_path 为空
            if (!ec && parser.is_header_done())
            {
                target_path = std::string(parser.get().target());
            }
        }

        // 2. 使用 buffer 进行握手
        // 仅传入 buffer 和 token，Beast 会内部处理请求对象
        co_await wsocket_.async_accept(net::buffer(pre_read_data.data(), pre_read_data.size()),net::use_awaitable);

        co_return target_path;
    }

    /**
     * @brief 读取数据
     * @param buffer 外部缓冲区
     * @return std::size_t 读取到的字节数
     */
    template <TransportConcept Transport>
    auto obscura<Transport>::async_read(beast::flat_buffer &buffer)
        -> net::awaitable<std::size_t>
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
    template <TransportConcept Transport>
    auto obscura<Transport>::async_write(std::string_view data)
        -> net::awaitable<void>
    {
        co_await wsocket_.async_write(net::buffer(data), net::use_awaitable);
    }
} // namespace ngx::transport
