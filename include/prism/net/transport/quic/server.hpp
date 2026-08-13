/**
 * @file server.hpp
 * @brief QUIC 服务端/客户端连接封装
 * @details 基于 ngtcp2 + BoringSSL 的 QUIC 封装：
 *          1. UDP socket 数据报 → ngtcp2_conn_read_pkt
 *          2. BoringSSL TLS-over-QUIC 桥接（SSL_QUIC_METHOD）
 *          3. 双向流 + datagram 暴露给上层协议
 */

#pragma once

#include <prism/diagnose/context.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <openssl/ssl.h>

#include <atomic>
#include <deque>
#include <functional>
#include <memory>
#include <unordered_map>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

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
        /**
         * @brief 构造 QUIC 双向流装饰器
         * @param executor 执行器
         * @param owner 所属的 QUIC 服务端连接
         * @param stream_id 流 ID
         * @param mr 内存资源指针
         */
        stream(net::any_io_executor executor, std::shared_ptr<server> owner, std::int64_t stream_id,
               memory::resource_pointer mr);

        /**
         * @brief 获取关联的执行器
         * @return 执行器
         */
        [[nodiscard]] auto executor() const -> executor_type override;

        /**
         * @brief 异步读取数据
         * @details 从接收通道取出已收明文，无数据时挂起等待。
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 异步操作，完成后返回读取的字节数
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 异步写入数据
         * @details 将数据发送到 QUIC 流，由 server 负责实际发包。
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 异步操作，完成后返回写入的字节数
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 关闭传输层
         */
        void close() override;

        /**
         * @brief 取消所有未完成的异步操作
         */
        void cancel() override;

        /**
         * @brief 获取内层传输
         * @return nullptr stream 是叶子节点，没有内层
         */
        [[nodiscard]] auto next_layer() noexcept -> psm::transport::transmission * override
        {
            return nullptr;
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return nullptr stream 是叶子节点，没有内层
         */
        [[nodiscard]] auto next_layer() const noexcept -> const psm::transport::transmission * override
        {
            return nullptr;
        }

        /**
         * @brief 投递流数据（由 server 帧处理调用）
         * @param data 待投递的流数据
         */
        void push(std::span<const std::byte> data);

        /**
         * @brief 通知流关闭
         */
        void notify_fin();

        /**
         * @brief 获取流 ID
         * @return 流 ID
         */
        [[nodiscard]] auto id() const noexcept -> std::int64_t
        {
            return stream_id_;
        }

        /**
         * @brief 是否为客户端发起的单向流（QUIC 流 ID 规则：id%4==2）
         * @return 单向流返回 true，否则返回 false
         */
        [[nodiscard]] auto is_uni() const noexcept -> bool
        {
            return (stream_id_ & 2) != 0;
        }

    private:
        net::any_io_executor executor_;          // 执行器
        std::shared_ptr<server> owner_;          // 所属 QUIC 服务端连接
        std::int64_t stream_id_{0};              // 流 ID
        memory::resource_pointer mr_;            // 内存资源
        using channel_type =
            net::experimental::concurrent_channel<void(boost::system::error_code, memory::vector<std::byte>)>;
        channel_type channel_;               ///< 数据通道（事件驱动读）
        memory::vector<std::byte> recv_buf_; ///< 已收明文
        std::size_t recv_offset_{0};         // 已读明文偏移
        bool fin_{false};                    // 对端是否已发送 FIN
        bool closed_{false};                 // 流是否已关闭
    };

    using shared_stream = std::shared_ptr<stream>;

    /**
     * @struct server_options
     * @brief QUIC 服务端构造参数
     */
    struct server_options
    {
        net::any_io_executor executor;             ///< 执行器
        net::ip::udp::endpoint peer;               ///< 对端端点
        std::shared_ptr<net::ip::udp::socket> udp; ///< UDP socket（已绑定）
        SSL_CTX *ssl_ctx{nullptr};                 ///< TLS 上下文（服务端）
        memory::resource_pointer mr{};             ///< 内存资源
        std::shared_ptr<diagnose::context> prefix; ///< 日志前缀
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
        /**
         * @brief 构造 QUIC 服务端连接
         * @param opts 服务端构造参数
         */
        explicit server(server_options opts);

        /**
         * @brief 析构 QUIC 服务端连接
         */
        ~server() noexcept;

        server(const server &) = delete;
        server &operator=(const server &) = delete;

        /**
         * @brief 启动连接处理
         * @details 注册回调并等待首包（Initial）建立连接。
         */
        void start();

        /**
         * @brief 关闭连接
         */
        void close();

        /**
         * @brief 处理一个 UDP 数据报
         * @details 将收到的数据报交给 ngtcp2 解析，触发连接推进。
         * @param from 数据报来源端点
         * @param data 数据报内容
         * @return 协程对象，处理完成后结束
         */
        auto handle_datagram(const net::ip::udp::endpoint &from, std::span<const std::byte> data)
            -> net::awaitable<void>;

        /**
         * @brief 泵送握手期间累积的 QUIC 包（外部驱动握手用）
         * @return 协程对象，泵送完成后结束
         */
        [[nodiscard]] auto flush_handshake() -> net::awaitable<void>;

        /**
         * @brief 向指定流写入数据
         * @param stream_id 目标流 ID
         * @param data 待发送数据
         * @return 结果码
         */
        auto write_stream_data(std::int64_t stream_id, std::span<const std::byte> data)
            -> net::awaitable<fault::code>;

        /**
         * @brief 发送 datagram
         * @param data 待发送数据
         * @return 结果码
         */
        auto write_datagram(std::span<const std::byte> data) -> net::awaitable<fault::code>;

        /**
         * @brief 打开单向流（服务器主动开流，HTTP/3 控制流/QPACK 流用；失败返回 -1）
         * @return 新流 ID，失败返回 -1
         */
        [[nodiscard]] auto open_uni_stream() -> std::int64_t;

        /**
         * @brief 按 ID 获取流
         * @param stream_id 流 ID
         * @return 流的共享指针，未找到返回空
         */
        [[nodiscard]] auto get_stream(std::int64_t stream_id) const -> shared_stream;

        /// 首条双向流建立回调
        std::function<void(shared_stream)> on_stream{nullptr};

        /// datagram 接收回调
        std::function<void(memory::vector<std::byte>)> on_datagram{nullptr};

        /// 握手完成回调
        std::function<void()> on_handshake_complete{nullptr};

        /**
         * @brief 握手是否已完成
         * @return 完成返回 true，否则返回 false
         */
        [[nodiscard]] auto is_handshake_complete() const noexcept -> bool
        {
            return handshake_complete_.load(std::memory_order_acquire);
        }

        /**
         * @brief 获取底层 ngtcp2 连接指针
         * @return ngtcp2_conn 指针
         */
        [[nodiscard]] auto native_conn() const noexcept -> ngtcp2_conn *
        {
            return conn_;
        }

        /**
         * @brief 获取底层 SSL 对象指针
         * @return SSL 指针
         */
        [[nodiscard]] auto native_ssl() const noexcept -> SSL *
        {
            return ssl_;
        }

        /**
         * @brief 获取对端端点
         * @return 对端 UDP 端点
         */
        [[nodiscard]] auto peer_endpoint() const noexcept -> const net::ip::udp::endpoint &
        {
            return peer_;
        }

        /**
         * @brief 流回调（ngtcp2 内部使用）
         * @param stream_id 流 ID
         * @param data 流数据
         */
        void on_stream_data(std::int64_t stream_id, std::span<const std::byte> data);

        /**
         * @brief 流打开回调（ngtcp2 内部使用）
         * @param stream_id 新打开的流 ID
         */
        void on_stream_open(std::int64_t stream_id);

        /**
         * @brief 流关闭回调（ngtcp2 内部使用）
         * @param stream_id 已关闭的流 ID
         */
        void on_stream_close(std::int64_t stream_id);

        /**
         * @brief datagram 接收回调（ngtcp2 内部使用）
         * @param data 收到的 datagram 数据
         */
        void on_datagram_data(std::span<const std::byte> data);

        /**
         * @brief 握手完成回调（ngtcp2 内部使用）
         */
        void on_handshake_done();

    private:
        /**
         * @brief 初始化 TLS 上下文
         * @return 初始化成功返回 true
         */
        auto setup_tls() -> bool;

        /**
         * @brief 初始化 ngtcp2 连接
         * @param original_dcid 原始目标连接 ID
         * @param peer_scid 对端源连接 ID
         * @return 初始化成功返回 true
         */
        auto setup_ngtcp2(const ngtcp2_cid &original_dcid, const ngtcp2_cid &peer_scid) -> bool;

        /**
         * @brief 发送 UDP 数据报
         * @param data 待发送数据
         * @return 协程对象，发送完成后结束
         */
        auto send_udp(std::span<const std::byte> data) -> net::awaitable<void>;

        server_options opts_;                       // 服务端构造参数
        ngtcp2_conn *conn_{nullptr};                // ngtcp2 连接指针
        SSL *ssl_{nullptr};                         // TLS 对象指针
        std::atomic<bool> handshake_complete_{false}; // 握手完成标志
        bool closed_{false};                        // 连接关闭标志
        std::unique_ptr<ngtcp2_cid> scid_; ///< 服务端连接 ID
        std::unordered_map<std::int64_t, shared_stream> streams_; // 流表（流 ID → 流对象）
        memory::resource_pointer mr_;               // 内存资源
        net::ip::udp::endpoint peer_;               // 对端端点
    };

    using shared_server = std::shared_ptr<server>;

    /**
     * @brief 创建 QUIC 服务端
     * @param opts 服务端构造参数
     * @return 服务端连接共享指针
     */
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
        net::any_io_executor executor;             ///< 执行器
        net::ip::udp::endpoint peer;               ///< 服务端端点
        std::shared_ptr<net::ip::udp::socket> udp; ///< UDP socket（已绑定）
        SSL_CTX *ssl_ctx{nullptr};                 ///< TLS 上下文（客户端）
        std::string host;                          ///< SNI 主机名
        memory::resource_pointer mr{};             ///< 内存资源
        std::shared_ptr<diagnose::context> prefix; ///< 日志前缀
    };

    /**
     * @class client
     * @brief QUIC 客户端连接（测试/联调用）
     * @details 驱动握手并暴露双向流读写。
     */
    class client : public std::enable_shared_from_this<client>
    {
    public:
        /**
         * @brief 构造 QUIC 客户端连接
         * @param opts 客户端构造参数
         */
        explicit client(client_options opts);

        /**
         * @brief 析构 QUIC 客户端连接
         */
        ~client() noexcept;

        client(const client &) = delete;
        client &operator=(const client &) = delete;

        /**
         * @brief 启动连接并驱动握手
         */
        void start();

        /**
         * @brief 关闭连接
         */
        void close();

        /**
         * @brief 握手是否已完成
         * @return 完成返回 true，否则返回 false
         */
        [[nodiscard]] auto is_handshake_complete() const noexcept -> bool
        {
            return handshake_complete_.load(std::memory_order_acquire);
        }

        /// 握手完成回调
        std::function<void()> on_handshake_complete{nullptr};

        /// 流数据接收回调（stream_id + data）
        std::function<void(int64_t, std::span<const std::byte>)> on_stream_data{nullptr};

        /**
         * @brief 打开双向流（返回流 ID）
         * @return 新流 ID
         */
        [[nodiscard]] auto open_stream() -> std::int64_t;

        /**
         * @brief 打开单向流（返回流 ID，失败返回 -1）
         * @return 新流 ID，失败返回 -1
         */
        [[nodiscard]] auto open_uni_stream() -> std::int64_t;

        /**
         * @brief 获取底层 SSL 对象指针
         * @return SSL 指针
         */
        [[nodiscard]] auto native_ssl() const noexcept -> SSL *
        {
            return ssl_;
        }

        /**
         * @brief 发送流数据
         * @param stream_id 目标流 ID
         * @param data 待发送数据
         * @return 发送结果码
         */
        [[nodiscard]] auto write_stream_data(std::int64_t stream_id, std::span<const std::byte> data)
            -> net::awaitable<fault::code>;

        /**
         * @brief 发送 datagram
         * @param data 待发送数据
         * @return 发送结果码
         */
        [[nodiscard]] auto write_datagram(std::span<const std::byte> data) -> net::awaitable<fault::code>;

        /**
         * @brief 处理一个 UDP 数据报
         * @param from 数据报来源端点
         * @param data 数据报内容
         * @return 协程对象，处理完成后结束
         */
        auto handle_datagram(const net::ip::udp::endpoint &from, std::span<const std::byte> data)
            -> net::awaitable<void>;

        /**
         * @brief 泵送握手期间累积的 QUIC 包（外部驱动握手用）
         * @return 协程对象，泵送完成后结束
         */
        [[nodiscard]] auto flush_handshake() -> net::awaitable<void>;

        /**
         * @brief 握手完成通知（ngtcp2 回调使用）
         */
        void on_handshake_done();

    private:
        /**
         * @brief 初始化 ngtcp2 连接
         * @return 初始化成功返回 true
         */
        auto setup_ngtcp2() -> bool;

        /**
         * @brief 初始化 TLS 上下文
         * @return 初始化成功返回 true
         */
        auto setup_tls() -> bool;

        /**
         * @brief 发送 UDP 数据报
         * @param data 待发送数据
         * @return 协程对象，发送完成后结束
         */
        auto send_udp(std::span<const std::byte> data) -> net::awaitable<void>;

        client_options opts_;                       // 客户端构造参数
        ngtcp2_conn *conn_{nullptr};                // ngtcp2 连接指针
        SSL *ssl_{nullptr};                         // TLS 对象指针
        std::atomic<bool> handshake_complete_{false}; // 握手完成标志
        bool closed_{false};                        // 连接关闭标志
        std::unique_ptr<ngtcp2_cid> dcid_;          // 目标连接 ID
        std::unique_ptr<ngtcp2_cid> scid_;          // 源连接 ID
    };

    using shared_client = std::shared_ptr<client>;

    /**
     * @brief 创建 QUIC 客户端
     * @param opts 客户端构造参数
     * @return 客户端连接共享指针
     */
    [[nodiscard]] inline auto make_client(client_options opts) -> shared_client
    {
        return std::make_shared<client>(std::move(opts));
    }

} // namespace psm::quic
