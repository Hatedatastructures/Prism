/**
 * @file Native.hpp
 * @brief Preview 原生 ngtcp2 QUIC 客户端、服务端与网关入口
 * @details 以真实 UDP socket 承载 ngtcp2 和 BoringSSL TLS 1.3，
 *          将双向流与 QUIC DATAGRAM 暴露为 Preview 提供者。
 *          每个实例只绑定一个执行器，所有 ngtcp2 调用在该执行器串行进行。
 * @note 该接口不依赖 src/prism 或 include/prism。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include <openssl/ssl.h>

#include <preview/Protocols/Quic/DatagramAdapter.hpp>
#include <preview/Protocols/Quic/StreamAdapter.hpp>

namespace Preview::Quic
{

    namespace net = boost::asio;

    /**
     * @struct ServerOptions
     * @brief 原生 QUIC 服务端连接参数
     * @details Socket 必须已经绑定；服务端在收到第一个 Initial 包后
     *          从包头提取连接 ID 并完成连接初始化。
     */
    struct ServerOptions
    {
        net::any_io_executor Executor{}; ///< 所有 QUIC 操作使用的执行器
        std::shared_ptr<net::ip::udp::socket> Socket{}; ///< 已绑定 UDP socket
        SSL_CTX *TlsContext{nullptr}; ///< TLS 1.3 服务端上下文
    };

    /**
     * @struct ClientOptions
     * @brief 原生 QUIC 客户端连接参数
     */
    struct ClientOptions
    {
        net::any_io_executor Executor{}; ///< 所有 QUIC 操作使用的执行器
        std::shared_ptr<net::ip::udp::socket> Socket{}; ///< 已绑定 UDP socket
        net::ip::udp::endpoint Peer{}; ///< 服务端 UDP 端点
        SSL_CTX *TlsContext{nullptr}; ///< TLS 1.3 客户端上下文
        std::string ServerName{}; ///< TLS SNI
    };

    namespace Detail
    {
        class NativeConnection;
    }

    /**
     * @class Client
     * @brief 单连接原生 QUIC 客户端
     */
    class Client final : public std::enable_shared_from_this<Client>
    {
    public:
        explicit Client(ClientOptions Options);
        ~Client() noexcept;

        Client(const Client &) = delete;
        auto operator=(const Client &) -> Client & = delete;

        /** @brief 启动 UDP 接收循环并发送 QUIC Initial */
        void Start();

        /** @brief 等待 QUIC 握手完成，关闭前返回 false */
        [[nodiscard]] auto WaitHandshake() -> net::awaitable<bool>;

        /** @brief 打开一个本端发起的双向 QUIC 流 */
        [[nodiscard]] auto OpenBidirectionalStream() -> net::awaitable<SharedStreamProvider>;

        /** @brief 获取该连接的数据报提供者 */
        [[nodiscard]] auto Datagram() const -> SharedDatagramProvider;

        /** @brief 取消 socket、流和挂起操作并释放 QUIC 状态 */
        void Close();

    private:
        std::shared_ptr<Detail::NativeConnection> Connection_;
    };

    /**
     * @class Server
     * @brief 单连接原生 QUIC 服务端
     */
    class Server final : public std::enable_shared_from_this<Server>
    {
    public:
        explicit Server(ServerOptions Options);
        ~Server() noexcept;

        Server(const Server &) = delete;
        auto operator=(const Server &) -> Server & = delete;

        /** @brief 启动 UDP 接收循环并等待客户端 Initial */
        void Start();

        /** @brief 等待 QUIC 握手完成，关闭前返回 false */
        [[nodiscard]] auto WaitHandshake() -> net::awaitable<bool>;

        /** @brief 接收下一个对端发起的双向 QUIC 流 */
        [[nodiscard]] auto AcceptBidirectionalStream() -> net::awaitable<SharedStreamProvider>;

        /** @brief 获取该连接的数据报提供者 */
        [[nodiscard]] auto Datagram() const -> SharedDatagramProvider;

        /** @brief 取消 socket、流和挂起操作并释放 QUIC 状态 */
        void Close();

    private:
        std::shared_ptr<Detail::NativeConnection> Connection_;
    };

    /**
     * @class Gateway
     * @brief 原生 QUIC 单连接网关门面
     * @details Gateway 保留服务端连接入口，并把接受流/数据报能力暴露给
     *          上层协议。多连接监听与 CID 路由由更高层负责。
     */
    class Gateway final
    {
    public:
        explicit Gateway(ServerOptions Options);
        ~Gateway() noexcept = default;

        Gateway(const Gateway &) = delete;
        auto operator=(const Gateway &) -> Gateway & = delete;

        void Start();
        [[nodiscard]] auto WaitHandshake() -> net::awaitable<bool>;
        [[nodiscard]] auto AcceptBidirectionalStream() -> net::awaitable<SharedStreamProvider>;
        [[nodiscard]] auto Datagram() const -> SharedDatagramProvider;
        void Close();

        /** @brief 获取门面持有的单连接服务端 */
        [[nodiscard]] auto Connection() const noexcept -> std::shared_ptr<Server>
        {
            return Server_;
        }

    private:
        std::shared_ptr<Server> Server_;
    };

} // namespace Preview::Quic
