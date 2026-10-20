/**
 * @file Native.hpp
 * @brief Prism 原生 ngtcp2 QUIC 客户端、服务端与网关入口
 * @details 以真实 UDP socket 承载 ngtcp2 和 BoringSSL TLS 1.3，
 *          将双向流与 QUIC DATAGRAM 暴露为 Prism 提供者。
 *          每个实例只绑定一个执行器，所有 ngtcp2 调用在该执行器串行进行。
 * @note 该接口不依赖退役的旧版产品目录。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl/context.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>


#include <Prism/Protocols/Quic/DatagramAdapter.hpp>
#include <Prism/Protocols/Quic/StreamAdapter.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Contract/Services/Quic.hpp>
#include <expected>

namespace Prism::Quic
{

    namespace Net = boost::asio;

    class Server;

    /// 随机源回调；返回 1 表示成功，其他值表示随机源失败。
    using RandomSource = std::function<int(std::uint8_t *, int)>;

    enum class ServerLifecycleStage : std::uint8_t
    {
        PacketReceived,
        InitialRejected,
        ServerInitialized,
        ServerInitializationFailed,
        TlsInitialized,
        TlsInitializationFailed,
        PacketAccepted,
        PacketRejected,
        TlsHandshakeComplete,
        AlpnRejected,
        ServerNameRejected,
        Established,
        Closed,
    };

    struct ServerLifecycleEvent final
    {
        ServerLifecycleStage Stage{ServerLifecycleStage::PacketReceived};
        std::int64_t Code{0};
    };

    using ServerLifecycleHandler = std::function<void(ServerLifecycleEvent)>;

    [[nodiscard]] constexpr auto ServerLifecycleStageName(
        const ServerLifecycleStage Stage) noexcept -> std::string_view
    {
        switch (Stage)
        {
        case ServerLifecycleStage::PacketReceived:
            return "PacketReceived";
        case ServerLifecycleStage::InitialRejected:
            return "InitialRejected";
        case ServerLifecycleStage::ServerInitialized:
            return "ServerInitialized";
        case ServerLifecycleStage::ServerInitializationFailed:
            return "ServerInitializationFailed";
        case ServerLifecycleStage::TlsInitialized:
            return "TlsInitialized";
        case ServerLifecycleStage::TlsInitializationFailed:
            return "TlsInitializationFailed";
        case ServerLifecycleStage::PacketAccepted:
            return "PacketAccepted";
        case ServerLifecycleStage::PacketRejected:
            return "PacketRejected";
        case ServerLifecycleStage::TlsHandshakeComplete:
            return "TlsHandshakeComplete";
        case ServerLifecycleStage::AlpnRejected:
            return "AlpnRejected";
        case ServerLifecycleStage::ServerNameRejected:
            return "ServerNameRejected";
        case ServerLifecycleStage::Established:
            return "Established";
        case ServerLifecycleStage::Closed:
            return "Closed";
        }
        return "Unknown";
    }

    /**
     * @struct NativeConnectionHealth
     * @brief 原生 QUIC 连接的分阶段就绪状态。
     * @details SocketReady/ReceiveLoopReady 只表示入口已建立；只有
     * HandshakeReady 只表示 QUIC 握手完成；上层协议完成 ALPN/协议绑定后
     * 还必须显式标记 ProtocolReady。BoundedFailure 表示该实例因执行器
     * 不亲和或共享 socket 超出单连接能力而被明确拒绝。DroppedDatagrams
     * 为 Native 暂存队列拒绝的数据报累计数。
     */
    struct NativeConnectionHealth final
    {
        bool SocketReady{false};
        bool ReceiveLoopReady{false};
        bool HandshakeReady{false};
        bool ProtocolReady{false};
        bool Closed{false};
        bool BoundedFailure{false};
        std::uint64_t DroppedDatagrams{0};

        [[nodiscard]] auto Healthy() const noexcept -> bool
        {
            return SocketReady && ReceiveLoopReady && HandshakeReady && ProtocolReady &&
                   !Closed && !BoundedFailure;
        }
    };

    /**
     * @struct ServerOptions
     * @brief 原生 QUIC 服务端连接参数
     * @details Socket 必须已经绑定，Boundary 仍是共享入口 socket 的最终关闭者。
     *          TlsContext 与 Generation 复制 owning 句柄；所有服务端句柄保留原材料和
     *          已注册的独立 executor context，外部 executor 由调用者保活至最后句柄释放。
     *          服务端在首个 Initial 包后完成初始化；取消、半关闭与 Drain 在 Executor 上执行。
     */
    struct ServerOptions
    {
        /** @brief 同步入站事件接口；成功表示调用方已登记 owner，失败会中止当前 native callback。
         * @details stream 在回调前已由 NativeConnection::Streams_ 保有，datagram state 由 Datagram_ 保有；
         *          调用方必须先预约，再构造适配器。拒绝时实物仍留在原 Native owner，最终关闭由 Server 负责。
         */
        using EstablishedHandler = std::function<std::expected<void, Prism::Fault::Failure>(std::string)>;
        using StartedHandler = std::function<void(std::shared_ptr<Server>)>;
        using StreamHandler = std::function<std::expected<void, Prism::Fault::Failure>(SharedStreamProvider)>;
        using UnidirectionalHandler = std::function<std::expected<void, Prism::Fault::Failure>(SharedStreamProvider)>;
        using DatagramHandler = std::function<std::expected<void, Prism::Fault::Failure>(SharedDatagramProvider)>;
        using ClosedHandler = std::function<void()>;
        using KeyingMaterialExporter = std::function<bool(
            std::span<std::uint8_t>, std::span<const std::uint8_t>, std::string_view)>;
        using ExporterHandler = std::function<std::expected<void, Prism::Fault::Failure>(KeyingMaterialExporter)>;

        Net::any_io_executor Executor{}; ///< 所有 QUIC 操作使用的执行器
        std::shared_ptr<Net::ip::udp::socket> Socket{}; ///< listener 拥有的已绑定 UDP socket
        std::shared_ptr<Net::ssl::context> TlsContext{}; ///< 唯一 owning TLS 1.3 服务端上下文
        std::shared_ptr<Prism::Contract::QuicDatagramSender> Sender{}; ///< Boundary 所有的 QUIC UDP 发包端口
        RandomSource Random{}; ///< 可注入的随机源；缺省使用 BoringSSL RAND_bytes
        bool ExternalReceive{false}; ///< 由上层 CID owner 注入数据报，不启动内部 receive loop
        std::string ExpectedAlpn{}; ///< 非空时 negotiated ALPN 必须精确匹配
        std::string ExpectedServerName{}; ///< 非空时 TLS SNI 必须精确匹配
        std::size_t MaxStreams{64}; ///< 每条连接同时打开的对端双向流上限；native close 回执后归还额度
        std::size_t MaxDatagrams{64}; ///< Native inbox 数据报上限；配置验证拒绝 0
        EstablishedHandler OnEstablished{};
        StartedHandler OnStarted{};
        StreamHandler OnStream{};
        UnidirectionalHandler OnUnidirectional{};
        DatagramHandler OnDatagram{};
        ClosedHandler OnClosed{};
        ExporterHandler OnExporter{};
        ServerLifecycleHandler OnLifecycle{};
        Prism::Foundation::GenerationPin Generation{}; ///< 该连接的原配置代次材料
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
        std::shared_ptr<Net::ssl::context> TlsContext{}; ///< 唯一 owning TLS 1.3 客户端上下文
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

        /**
         * @brief 打开本端发起的双向流。
         * @return owning provider；关闭为 Canceled，握手未就绪为 Blocked，ngtcp2 失败保留原类别和值。
         * @note StreamProvider 持有本连接的单流 owner；最终流关闭由 QUIC connection owner 完成。
         */
        [[nodiscard]] auto OpenBidirectionalStream()
            -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>;

        /**
         * @brief 打开本端发起的单向流。
         * @return owning provider；关闭为 Canceled，握手未就绪为 Blocked，ngtcp2 失败保留原类别和值。
         * @note StreamProvider 持有本连接的单流 owner；最终流关闭由 QUIC connection owner 完成。
         */
        [[nodiscard]] auto OpenUnidirectionalStream()
            -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>;

        /**
         * @brief 接收服务端发起的单向流。
         * @return owning provider；本端关闭为 Canceled，真实 channel 或 native 错误保留其失败原因。
         * @note 成功将队列中的单流 owner 移交给调用者；connection owner 负责最终关闭。
         */
        [[nodiscard]] auto AcceptUnidirectionalStream()
            -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>;

        /** @brief 从已完成的 TLS 会话导出密钥材料 */
        [[nodiscard]] auto ExportKeyingMaterial(
            std::span<std::uint8_t> Output,
            std::span<const std::uint8_t> Label,
            std::string_view Context) const -> bool;

        /** @brief 获取该连接的数据报提供者 */
        [[nodiscard]] auto Datagram() const -> SharedDatagramProvider;

        /** @brief 取消 socket、流和挂起操作并释放 QUIC 状态 */
        auto Close() -> void;

        /** @brief 请求关闭并等待连接真实退栈。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 读取 Native 连接及任务的纯物理退休回执。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

        /** @brief 获取连接的分阶段就绪状态 */
        [[nodiscard]] auto Health() const noexcept -> NativeConnectionHealth;

    private:
        [[nodiscard]] static auto DrainConnection(
            std::shared_ptr<Detail::NativeConnection> Connection)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        std::shared_ptr<Detail::NativeConnection> Connection_;
    };

    /**
     * @class Server
     * @brief 单连接原生 QUIC 服务端，所有共享句柄保活原 Io/PMR、TLS 和 generation。
     * @details Drain 等待真实 I/O 完成；完成后的 Close 和析构不再向 executor 投递。
     *          字段按材料先构造、连接先析构的顺序持有，无 Runtime 或 Worker 强引用。
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

        /**
         * @brief 接收下一个对端发起的双向流。
         * @return owning provider；本端关闭为 Canceled，真实 channel 或 native 错误保留其失败原因。
         * @note 成功将队列中的单流 owner 移交给调用者；connection owner 负责最终关闭。
         */
        [[nodiscard]] auto AcceptBidirectionalStream()
            -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>;

        /**
         * @brief 打开服务端发起的单向流。
         * @return owning provider；关闭为 Canceled，握手未就绪为 Blocked，ngtcp2 失败保留原类别和值。
         * @note StreamProvider 持有本连接的单流 owner；最终流关闭由 QUIC connection owner 完成。
         */
        [[nodiscard]] auto OpenUnidirectionalStream()
            -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>;

        /**
         * @brief 接收客户端发起的单向流。
         * @return owning provider；本端关闭为 Canceled，真实 channel 或 native 错误保留其失败原因。
         * @note 成功将队列中的单流 owner 移交给调用者；connection owner 负责最终关闭。
         */
        [[nodiscard]] auto AcceptUnidirectionalStream()
            -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>;

        /** @brief 从已完成的 TLS 会话导出密钥材料 */
        [[nodiscard]] auto ExportKeyingMaterial(
            std::span<std::uint8_t> Output,
            std::span<const std::uint8_t> Label,
            std::string_view Context) const -> bool;

        /** @brief 获取该连接的数据报提供者 */
        [[nodiscard]] auto Datagram() const -> SharedDatagramProvider;

        /** @brief 取消 socket、流和挂起操作并释放 QUIC 状态 */
        auto Close() -> void;

        /** @brief 请求关闭并 await native pump/receive completion，必须驱动原 executor；共享入口 socket 不归本连接。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 读取 Native owner 的纯物理退休回执。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

        /** @brief 获取连接的分阶段就绪状态 */
        [[nodiscard]] auto Health() const noexcept -> NativeConnectionHealth;

    private:
        std::shared_ptr<Prism::Executor::ContextOwner> Context_;
        Prism::Foundation::GenerationPin Generation_;
        std::shared_ptr<Net::ssl::context> TlsContext_;
        std::shared_ptr<Detail::NativeConnection> Connection_;
        ServerOptions::StartedHandler OnStarted_;
        [[nodiscard]] static auto DrainOwned(std::shared_ptr<Server> Owner)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
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
        [[nodiscard]] auto AcceptBidirectionalStream()
            -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>;
        [[nodiscard]] auto OpenUnidirectionalStream()
            -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>;
        [[nodiscard]] auto AcceptUnidirectionalStream()
            -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>;
        [[nodiscard]] auto ExportKeyingMaterial(
            std::span<std::uint8_t> Output,
            std::span<const std::uint8_t> Label,
            std::string_view Context) const -> bool;
        [[nodiscard]] auto Datagram() const -> SharedDatagramProvider;
        auto Close() -> void;

        /** @brief 请求关闭并等待 Native 连接真实退栈。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 读取 Native 连接及任务的纯物理退休回执。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

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

} // namespace Prism::Quic

// 公共 QUIC 门面、provider 和 Native connection 契约聚合。
#include <Prism/Protocols/Quic/Detail/NativeConnection.hpp>
