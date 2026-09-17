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
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>

#include <openssl/ssl.h>

#include <Preview/Protocols/Quic/DatagramAdapter.hpp>
#include <Preview/Protocols/Quic/StreamAdapter.hpp>

namespace Preview::Quic
{

    namespace Net = boost::asio;

    class Server;

    /// 随机源回调；返回 1 表示成功，其他值表示随机源失败。
    using RandomSource = std::function<int(std::uint8_t *, int)>;

    /**
     * @struct NativeConnectionHealth
     * @brief 原生 QUIC 连接的分阶段就绪状态。
     * @details SocketReady/ReceiveLoopReady 只表示入口已建立；只有
     * HandshakeReady 只表示 QUIC 握手完成；上层协议完成 ALPN/协议绑定后
     * 还必须显式标记 ProtocolReady。BoundedFailure 表示该实例因执行器
     * 不亲和或共享 socket 超出单连接能力而被明确拒绝。
     */
    struct NativeConnectionHealth final
    {
        bool SocketReady{false};
        bool ReceiveLoopReady{false};
        bool HandshakeReady{false};
        bool ProtocolReady{false};
        bool Closed{false};
        bool BoundedFailure{false};

        [[nodiscard]] auto Healthy() const noexcept -> bool
        {
            return SocketReady && ReceiveLoopReady && HandshakeReady && ProtocolReady &&
                   !Closed && !BoundedFailure;
        }
    };

    /**
     * @struct ServerOptions
     * @brief 原生 QUIC 服务端连接参数
     * @details Socket 必须已经绑定；服务端在收到第一个 Initial 包后
     *          从包头提取连接 ID 并完成连接初始化。
     */
    struct ServerOptions
    {
        using EstablishedHandler = std::function<void(std::string)>;
        using StartedHandler = std::function<void(std::shared_ptr<Server>)>;
        using StreamHandler = std::function<void(SharedStreamProvider)>;
        using UnidirectionalHandler = std::function<void(SharedStreamProvider)>;
        using DatagramHandler = std::function<void(SharedDatagramProvider)>;
        using ClosedHandler = std::function<void()>;
        using KeyingMaterialExporter = std::function<bool(
            std::span<std::uint8_t>, std::span<const std::uint8_t>, std::string_view)>;
        using ExporterHandler = std::function<void(KeyingMaterialExporter)>;

        Net::any_io_executor Executor{}; ///< 所有 QUIC 操作使用的执行器
        std::shared_ptr<Net::ip::udp::socket> Socket{}; ///< 已绑定 UDP socket
        SSL_CTX *TlsContext{nullptr}; ///< TLS 1.3 服务端上下文
        RandomSource Random{}; ///< 可注入的随机源；缺省使用 BoringSSL RAND_bytes
        bool ExternalReceive{false}; ///< 由上层 CID owner 注入数据报，不启动内部 receive loop
        std::string ExpectedAlpn{}; ///< 非空时 negotiated ALPN 必须精确匹配
        std::string ExpectedServerName{}; ///< 非空时 TLS SNI 必须精确匹配
        std::size_t MaxStreams{64}; ///< 入站流上限，由上层协议工厂执行
        std::size_t MaxDatagrams{64}; ///< 数据报上限，由上层协议工厂执行
        EstablishedHandler OnEstablished{};
        StartedHandler OnStarted{};
        StreamHandler OnStream{};
        UnidirectionalHandler OnUnidirectional{};
        DatagramHandler OnDatagram{};
        ClosedHandler OnClosed{};
        ExporterHandler OnExporter{};
    };

    /**
     * @struct ClientOptions
     * @brief 原生 QUIC 客户端连接参数
     */
    struct ClientOptions
    {
        Net::any_io_executor Executor{}; ///< 所有 QUIC 操作使用的执行器
        std::shared_ptr<Net::ip::udp::socket> Socket{}; ///< 已绑定 UDP socket
        Net::ip::udp::endpoint Peer{}; ///< 服务端 UDP 端点
        SSL_CTX *TlsContext{nullptr}; ///< TLS 1.3 客户端上下文
        std::string ServerName{}; ///< TLS SNI
        RandomSource Random{}; ///< 可注入的随机源；缺省使用 BoringSSL RAND_bytes
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
        explicit Client(const ClientOptions &Options);
        ~Client() noexcept;

        Client(const Client &) = delete;
        auto operator=(const Client &) -> Client & = delete;

        /** @brief 启动 UDP 接收循环并发送 QUIC Initial */
        auto Start() -> void;

        /** @brief 等待 QUIC 握手完成，关闭前返回 false */
        [[nodiscard]] auto WaitHandshake() -> Net::awaitable<bool>;

        /** @brief 在所属执行器上登记上层协议已完成绑定 */
        [[nodiscard]] auto MarkProtocolReady() -> Net::awaitable<bool>;

        /** @brief 打开一个本端发起的双向 QUIC 流 */
        [[nodiscard]] auto OpenBidirectionalStream() -> Net::awaitable<SharedStreamProvider>;

        /** @brief 打开一个本端发起的单向 QUIC 流 */
        [[nodiscard]] auto OpenUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>;

        /** @brief 接收一个服务端发起的单向 QUIC 流 */
        [[nodiscard]] auto AcceptUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>;

        /** @brief 从已完成的 TLS 会话导出密钥材料 */
        [[nodiscard]] auto ExportKeyingMaterial(
            std::span<std::uint8_t> Output,
            std::span<const std::uint8_t> Label,
            std::string_view Context) const -> bool;

        /** @brief 获取该连接的数据报提供者 */
        [[nodiscard]] auto Datagram() const -> SharedDatagramProvider;

        /** @brief 取消 socket、流和挂起操作并释放 QUIC 状态 */
        auto Close() -> void;

        /** @brief 获取连接的分阶段就绪状态 */
        [[nodiscard]] auto Health() const noexcept -> NativeConnectionHealth;

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
        explicit Server(const ServerOptions &Options);
        ~Server() noexcept;

        Server(const Server &) = delete;
        auto operator=(const Server &) -> Server & = delete;

        /** @brief 启动 UDP 接收循环并等待客户端 Initial */
        auto Start() -> void;

        /**
         * @brief 向 external-receive server 注入一个已由 CID owner 路由的数据报。
         * @note 调用方必须在 ServerOptions::Executor 上串行调用。
         */
        [[nodiscard]] auto ReceivePacket(
            std::span<const std::byte> Data,
            const Net::ip::udp::endpoint &Peer) -> bool;

        /** @brief 等待 QUIC 握手完成，关闭前返回 false */
        [[nodiscard]] auto WaitHandshake() -> Net::awaitable<bool>;

        /** @brief 在所属执行器上登记上层协议已完成绑定 */
        [[nodiscard]] auto MarkProtocolReady() -> Net::awaitable<bool>;

        /** @brief 接收下一个对端发起的双向 QUIC 流 */
        [[nodiscard]] auto AcceptBidirectionalStream() -> Net::awaitable<SharedStreamProvider>;

        /** @brief 打开一个服务端发起的单向 QUIC 流 */
        [[nodiscard]] auto OpenUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>;

        /** @brief 接收一个客户端发起的单向 QUIC 流 */
        [[nodiscard]] auto AcceptUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>;

        /** @brief 从已完成的 TLS 会话导出密钥材料 */
        [[nodiscard]] auto ExportKeyingMaterial(
            std::span<std::uint8_t> Output,
            std::span<const std::uint8_t> Label,
            std::string_view Context) const -> bool;

        /** @brief 获取该连接的数据报提供者 */
        [[nodiscard]] auto Datagram() const -> SharedDatagramProvider;

        /** @brief 取消 socket、流和挂起操作并释放 QUIC 状态 */
        auto Close() -> void;

        /** @brief 获取连接的分阶段就绪状态 */
        [[nodiscard]] auto Health() const noexcept -> NativeConnectionHealth;

    private:
        std::shared_ptr<Detail::NativeConnection> Connection_;
        ServerOptions::StartedHandler OnStarted_;
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

        auto Start() -> void;
        [[nodiscard]] auto WaitHandshake() -> Net::awaitable<bool>;
        [[nodiscard]] auto MarkProtocolReady() -> Net::awaitable<bool>;
        [[nodiscard]] auto AcceptBidirectionalStream() -> Net::awaitable<SharedStreamProvider>;
        [[nodiscard]] auto OpenUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>;
        [[nodiscard]] auto AcceptUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>;
        [[nodiscard]] auto ExportKeyingMaterial(
            std::span<std::uint8_t> Output,
            std::span<const std::uint8_t> Label,
            std::string_view Context) const -> bool;
        [[nodiscard]] auto Datagram() const -> SharedDatagramProvider;
        auto Close() -> void;

        /** @brief 获取门面持有的单连接就绪状态 */
        [[nodiscard]] auto Health() const noexcept -> NativeConnectionHealth;

        /** @brief 获取门面持有的单连接服务端 */
        [[nodiscard]] auto Connection() const noexcept -> std::shared_ptr<Server>
        {
            return Server_;
        }

    private:
        std::shared_ptr<Server> Server_;
    };

} // namespace Preview::Quic
