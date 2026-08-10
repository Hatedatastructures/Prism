/**
 * @file server.hpp
 * @brief QUIC 服务端/客户端连接封装
 * @details 基于 ngtcp2 + BoringSSL 的 QUIC 封装：
 *          1. UDP socket 数据报 → ngtcp2_conn_read_pkt
 *          2. BoringSSL TLS-over-QUIC 桥接（SSL_QUIC_METHOD）
 *          3. 双向流 + datagram 暴露给上层协议
 */

#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/diagnose/context.hpp>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <openssl/ssl.h>

#include <atomic>
#include <deque>
#include <functional>
#include <memory>
#include <unordered_map>

namespace psm::quic
{

    namespace net = boost::asio;

    class server;
    class client;

    /**
     * @class stream
     * @brief QUIC 双向流传输装饰器
     * @details 继承 transmission，读写经 ngtcp2 流收发。
     */
    class stream final : public psm::transport::transmission
    {
    public:
        stream(net::any_io_executor executor, std::shared_ptr<server> owner,
               std::int64_t stream_id, memory::resource_pointer mr);

        [[nodiscard]] auto executor() const -> executor_type override;

        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        void close() override;
        void cancel() override;

        [[nodiscard]] auto next_layer() noexcept -> psm::transport::transmission * override
        {
            return nullptr;
        }

        [[nodiscard]] auto next_layer() const noexcept -> const psm::transport::transmission * override
        {
            return nullptr;
        }

        /// 投递流数据（由 server 帧处理调用）
        void push(std::span<const std::byte> data);

        /// 通知流关闭
        void notify_fin();

        [[nodiscard]] auto id() const noexcept -> std::int64_t
        {
            return stream_id_;
        }

        /// 是否为客户端发起的单向流（QUIC 流 ID 规则：id%4==2）
        [[nodiscard]] auto is_uni() const noexcept -> bool
        {
            return (stream_id_ & 2) != 0;
        }

    private:
        net::any_io_executor executor_;
        std::shared_ptr<server> owner_;
        std::int64_t stream_id_{0};
        memory::resource_pointer mr_;
        using channel_type = net::experimental::concurrent_channel<
            void(boost::system::error_code, memory::vector<std::byte>)>;
        channel_type channel_;                 ///< 数据通道（事件驱动读）
        memory::vector<std::byte> recv_buf_;   ///< 已收明文
        std::size_t recv_offset_{0};
        bool fin_{false};
        bool closed_{false};
    };

    using shared_stream = std::shared_ptr<stream>;

    /**
     * @struct server_options
     * @brief QUIC 服务端构造参数
     */
    struct server_options
    {
        net::any_io_executor executor;              ///< 执行器
        net::ip::udp::endpoint peer;                ///< 对端端点
        std::shared_ptr<net::ip::udp::socket> udp;  ///< UDP socket（已绑定）
        SSL_CTX *ssl_ctx{nullptr};                  ///< TLS 上下文（服务端）
        memory::resource_pointer mr{};              ///< 内存资源
        std::shared_ptr<diagnose::context> prefix;  ///< 日志前缀
    };

    /**
     * @class server
     * @brief QUIC 服务端连接
     * @details 管理单条 QUIC 连接：握手、流、datagram。
     *          首包（Initial）到达后自动建立连接。
     */
    class server : public std::enable_shared_from_this<server>
    {
    public:
        explicit server(server_options opts);
        ~server() noexcept;

        server(const server &) = delete;
        server &operator=(const server &) = delete;

        void start();
        void close();

        auto handle_datagram(const net::ip::udp::endpoint &from, std::span<const std::byte> data)
            -> net::awaitable<void>;

        /// 泵送握手期间累积的 QUIC 包（外部驱动握手用）
        [[nodiscard]] auto flush_handshake() -> net::awaitable<void>;

        auto write_stream_data(std::int64_t stream_id, std::span<const std::byte> data)
            -> net::awaitable<fault::code>;

        auto write_datagram(std::span<const std::byte> data)
            -> net::awaitable<fault::code>;

        /// 打开单向流（服务器主动开流，HTTP/3 控制流/QPACK 流用；失败返回 -1）
        [[nodiscard]] auto open_uni_stream() -> std::int64_t;

        [[nodiscard]] auto get_stream(std::int64_t stream_id) const -> shared_stream;

        /// 首条双向流建立回调
        std::function<void(shared_stream)> on_stream{nullptr};

        /// datagram 接收回调
        std::function<void(memory::vector<std::byte>)> on_datagram{nullptr};

        /// 握手完成回调
        std::function<void()> on_handshake_complete{nullptr};

        [[nodiscard]] auto is_handshake_complete() const noexcept -> bool
        {
            return handshake_complete_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto native_conn() const noexcept -> ngtcp2_conn *
        {
            return conn_;
        }

        [[nodiscard]] auto native_ssl() const noexcept -> SSL *
        {
            return ssl_;
        }

        [[nodiscard]] auto peer_endpoint() const noexcept -> const net::ip::udp::endpoint &
        {
            return peer_;
        }

        /// 流回调（ngtcp2 内部使用）
        void on_stream_data(std::int64_t stream_id, std::span<const std::byte> data);
        void on_stream_open(std::int64_t stream_id);
        void on_stream_close(std::int64_t stream_id);
        void on_datagram_data(std::span<const std::byte> data);
        void on_handshake_done();

    private:
        auto setup_tls() -> bool;
        auto setup_ngtcp2(const ngtcp2_cid &original_dcid, const ngtcp2_cid &peer_scid) -> bool;
        auto send_udp(std::span<const std::byte> data) -> net::awaitable<void>;

        server_options opts_;
        ngtcp2_conn *conn_{nullptr};
        SSL *ssl_{nullptr};
        std::atomic<bool> handshake_complete_{false};
        bool closed_{false};
        std::unique_ptr<ngtcp2_cid> scid_;  ///< 服务端连接 ID
        std::unordered_map<std::int64_t, shared_stream> streams_;
        memory::resource_pointer mr_;
        net::ip::udp::endpoint peer_;
    };

    using shared_server = std::shared_ptr<server>;

    /// 创建 QUIC 服务端
    [[nodiscard]] inline auto make_server(server_options opts) -> shared_server
    {
        return std::make_shared<server>(std::move(opts));
    }

    /**
     * @struct client_options
     * @brief QUIC 客户端构造参数
     */
    struct client_options
    {
        net::any_io_executor executor;              ///< 执行器
        net::ip::udp::endpoint peer;                ///< 服务端端点
        std::shared_ptr<net::ip::udp::socket> udp;  ///< UDP socket（已绑定）
        SSL_CTX *ssl_ctx{nullptr};                  ///< TLS 上下文（客户端）
        std::string host;                           ///< SNI 主机名
        memory::resource_pointer mr{};              ///< 内存资源
        std::shared_ptr<diagnose::context> prefix;  ///< 日志前缀
    };

    /**
     * @class client
     * @brief QUIC 客户端连接（测试/联调用）
     * @details 驱动握手并暴露双向流读写。
     */
    class client : public std::enable_shared_from_this<client>
    {
    public:
        explicit client(client_options opts);
        ~client() noexcept;

        client(const client &) = delete;
        client &operator=(const client &) = delete;

        void start();
        void close();

        [[nodiscard]] auto is_handshake_complete() const noexcept -> bool
        {
            return handshake_complete_.load(std::memory_order_acquire);
        }

        /// 握手完成回调
        std::function<void()> on_handshake_complete{nullptr};

        /// 流数据接收回调（stream_id + data）
        std::function<void(int64_t, std::span<const std::byte>)> on_stream_data{nullptr};

        /// 打开双向流（返回流 ID）
        [[nodiscard]] auto open_stream() -> std::int64_t;

        /// 打开单向流（返回流 ID，失败返回 -1）
        [[nodiscard]] auto open_uni_stream() -> std::int64_t;

        [[nodiscard]] auto native_ssl() const noexcept -> SSL *
        {
            return ssl_;
        }

        /// 发送流数据
        [[nodiscard]] auto write_stream_data(std::int64_t stream_id, std::span<const std::byte> data)
            -> net::awaitable<fault::code>;

        /// 发送 datagram
        [[nodiscard]] auto write_datagram(std::span<const std::byte> data)
            -> net::awaitable<fault::code>;

        /// 处理一个 UDP 数据报
        auto handle_datagram(const net::ip::udp::endpoint &from, std::span<const std::byte> data)
            -> net::awaitable<void>;

        /// 泵送握手期间累积的 QUIC 包（外部驱动握手用）
        [[nodiscard]] auto flush_handshake() -> net::awaitable<void>;

        /// 握手完成通知（ngtcp2 回调使用）
        void on_handshake_done();

    private:
        auto setup_ngtcp2() -> bool;
        auto setup_tls() -> bool;
        auto send_udp(std::span<const std::byte> data) -> net::awaitable<void>;

        client_options opts_;
        ngtcp2_conn *conn_{nullptr};
        SSL *ssl_{nullptr};
        std::atomic<bool> handshake_complete_{false};
        bool closed_{false};
        std::unique_ptr<ngtcp2_cid> dcid_;
        std::unique_ptr<ngtcp2_cid> scid_;
    };

    using shared_client = std::shared_ptr<client>;

    /// 创建 QUIC 客户端
    [[nodiscard]] inline auto make_client(client_options opts) -> shared_client
    {
        return std::make_shared<client>(std::move(opts));
    }

} // namespace psm::quic
