/**
 * @file craft.hpp
 * @brief h2mux 多路复用会话服务端（HTTP/2 CONNECT stream 多路复用）
 * @details h2mux::craft 继承 multiplex::core，利用 nghttp2 库实现 HTTP/2
 * 原生 stream 多路复用。每个 HTTP/2 CONNECT 请求创建一个独立的 stream，
 * 对应一个 duct（TCP）或 parcel（UDP）。流量控制由 HTTP/2 标准流控管理，
 * 无需应用层窗口机制。地址解析通过 address_resolver 回调注入，
 * 支持 sing-mux（StreamRequest flags）和 TrustTunnel（:authority 头）两种模式。
 * @note 通过 core 的虚函数接口发送帧，duct/parcel 无需感知具体协议
 */
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <memory>

#include <boost/asio/experimental/concurrent_channel.hpp>
#include <nghttp2/nghttp2.h>

#include <prism/multiplex/core.hpp>
#include <prism/multiplex/config.hpp>
#include <prism/multiplex/h2mux/config.hpp>
#include <prism/memory/container.hpp>

namespace psm::multiplex::h2mux
{
    namespace net = boost::asio;

    /**
     * @enum stream_type
     * @brief HTTP/2 stream 类型
     * @details 从 CONNECT 请求的地址或 StreamRequest flags 中提取，
     * 决定创建 duct、parcel 还是执行健康检查。
     */
    enum class stream_type : std::uint8_t
    {
        /** @brief TCP 流，创建 duct 双向转发 */
        tcp,
        /** @brief UDP 数据报，创建 parcel 中继 */
        udp,
        /** @brief ICMP 代理（后续迭代） */
        icmp,
        /** @brief 健康检查，回复 200 后关闭 */
        check
    }; // enum stream_type

    /**
     * @struct h2_stream_info
     * @brief address_resolver 返回的流地址信息
     * @details 由 address_resolver 回调填充，包含连接目标的所有信息。
     * valid=false 表示地址信息不完整（如 sing-mux 模式需要等待 DATA 帧）。
     */
    struct h2_stream_info
    {
        memory::string host;              // 目标主机
        std::uint16_t port = 0;           // 目标端口
        stream_type type = stream_type::tcp; // 流类型
        bool valid = false;               // 地址信息是否完整可用
    }; // struct h2_stream_info

    /**
     * @struct h2_headers
     * @brief 从 HTTP/2 HEADERS 帧收集的请求头
     * @details 在 on_header 回调中逐步填充，传递给 address_resolver。
     */
    struct h2_headers
    {
        int32_t stream_id{0};           // HTTP/2 stream ID
        memory::string authority;       // :authority 头（CONNECT 目标）
        memory::string host;            // Host 头（用于类型判断）
        memory::string user_agent;      // User-Agent 头
        memory::string proxy_auth;      // Proxy-Authorization 头
    }; // struct h2_headers

    /**
     * @brief 地址解析回调类型
     * @param stream_id HTTP/2 stream ID
     * @param headers 从 HEADERS 帧收集的请求头
     * @return h2_stream_info 解析结果，valid=false 表示需要等待 DATA 帧
     * @details 由外部注入，根据使用场景不同有两种实现：
     * - sing-mux resolver: authority 为 localhost/空，忽略 HEADERS，等待 StreamRequest
     * - TrustTunnel resolver: 从 authority 解析 host:port，从 Host 判断流类型
     */
    using address_resolver = std::function<h2_stream_info(
        int32_t stream_id, const h2_headers &headers)>;

    /**
     * @struct h2_pending_entry
     * @brief 正在等待地址解析和连接的 HTTP/2 stream 条目
     * @details HEADERS(CONNECT) 帧创建后由 address_resolver 尝试解析。
     * 如果 resolver 返回 valid=false（sing-mux 模式），则等待首个 DATA 帧
     * 携带的 StreamRequest 数据。connecting 标志防止重复 activate_stream。
     */
    struct h2_pending_entry
    {
        h2_headers headers;             // 收集的 HTTP/2 请求头
        h2_stream_info info;            // resolver 返回的地址信息
        bool connecting = false;        // 是否已发起连接
    }; // struct h2_pending_entry

    /**
     * @struct outbound_data
     * @brief 出站数据项，用于 send_loop 串行化写入
     * @details 携带 stream_id 和待发送的 payload，由 send_loop
     * 通过 nghttp2_submit_data 编码为 HTTP/2 DATA 帧后写入 transport。
     */
    struct outbound_data
    {
        std::uint32_t stream_id = 0;                  // 目标 stream
        memory::vector<std::byte> payload;             // 待发送数据
        bool is_fin = false;                           // 是否为 FIN（RST_STREAM）

        outbound_data() = default;
        explicit outbound_data(memory::resource_pointer mr) : payload(mr) {}
    }; // struct outbound_data

    /**
     * @class craft
     * @brief h2mux 多路复用会话服务端
     * @details 继承 core，利用 nghttp2 实现 HTTP/2 服务端帧编解码。
     * nghttp2 的同步回调在 frame_loop 的 nghttp2_session_mem_recv 中执行，
     * 通过 concurrent_channel 将数据传递到 duct/parcel。
     * 生命周期由 core::start() 启动，通过 co_spawn 运行 run() 协程。
     * 不走 sing-mux bootstrap 协商，由 scheme 或 bootstrap 直接创建。
     */
    class craft final : public core
    {
    public:
        /**
         * @brief 构造 h2mux 会话
         * @param transport 已建立的传输层连接（TLS + ALPN h2）
         * @param router 路由器引用，用于解析地址并连接目标
         * @param cfg 多路复用配置参数（含 h2mux 子配置）
         * @param resolver 地址解析回调，决定如何从 CONNECT 请求提取目标地址
         * @param mr PMR 内存资源，为空时使用默认资源
         */
        craft(transport::shared_transmission transport, connect::router &router,
              const multiplex::config &cfg, address_resolver resolver,
              memory::resource_pointer mr = {});

        ~craft() override;

        /**
         * @brief 发送 HTTP/2 DATA 帧到客户端
         * @param stream_id 目标流标识符
         * @param payload 要发送的数据（所有权转移）
         * @details 通过 concurrent_channel 投递到 send_loop 串行化发送
         */
        auto send_data(std::uint32_t stream_id, memory::vector<std::byte> payload) const
            -> net::awaitable<void> override;

        /**
         * @brief 发送 RST_STREAM 关闭指定流
         * @param stream_id 目标流标识符
         * @details 通过 co_spawn 异步发送，不阻塞调用者
         */
        void send_fin(std::uint32_t stream_id) override;

        /**
         * @brief 获取 transport executor
         * @return net::any_io_executor transport 的执行器
         */
        [[nodiscard]] net::any_io_executor executor() const override;

        /**
         * @brief 等待第一个 CONNECT 请求
         * @return 第一个有效的 CONNECT 请求头，或 nullopt（连接关闭）
         * @details 供 TrustTunnel scheme 验证 auth 后再交给 craft 管理
         */
        auto wait_first_connect()
            -> net::awaitable<std::optional<h2_headers>>;

        /**
         * @brief 回复 CONNECT 请求
         * @param stream_id HTTP/2 stream ID
         * @param status HTTP 状态码（200 或 407）
         * @return 0 成功，非 0 失败
         */
        auto respond_connect(int32_t stream_id, std::uint32_t status)
            -> int;

        /**
         * @brief 发送 nghttp2 缓冲区中的待输出数据
         */
        auto send_pending()
            -> net::awaitable<void>;

        /**
         * @brief 激活指定 stream（解析地址、连接目标、创建 duct/parcel）
         * @param stream_id 流标识符
         */
        auto activate_stream(std::uint32_t stream_id)
            -> net::awaitable<void>;

    private:
        auto run()
            -> net::awaitable<void> override;

        auto init_nghttp2()
            -> int;

        auto frame_loop()
            -> net::awaitable<void>;

        /**
         * @brief 处理完整的 CONNECT 请求
         * @details 由 on_frame_recv 回调触发，调用 address_resolver 解析地址，
         * 成功则 spawn activate_stream，失败则 RST_STREAM
         */
        auto handle_connect(int32_t stream_id)
            -> void;

        // nghttp2 回调（静态函数，通过 user_data 获取 this）
        static auto on_begin_headers(nghttp2_session *, const nghttp2_frame *, void *) -> int;
        static auto on_header(nghttp2_session *, const nghttp2_frame *,
                              const uint8_t *, size_t, const uint8_t *, size_t,
                              uint8_t, void *) -> int;
        static auto on_frame_recv(nghttp2_session *, const nghttp2_frame *, void *) -> int;
        static auto on_data(nghttp2_session *, uint8_t, int32_t,
                            const uint8_t *, size_t, void *) -> int;
        static auto on_stream_close(nghttp2_session *, int32_t, uint32_t, void *) -> int;

        /**
         * @brief 发送循环协程
         * @details 从 send_channel_ 取出 outbound_data，
         * 通过 nghttp2_submit_data 编码为 HTTP/2 DATA 帧后写入 transport
         */
        auto send_loop()
            -> net::awaitable<void>;

        nghttp2_session *session_{nullptr};
        address_resolver resolver_;

        // 独立的 h2 pending 映射（不使用 core 的 pending_）
        memory::unordered_map<std::uint32_t, h2_pending_entry> h2_pending_;

        // 发送通道，串行化多流写入
        using send_channel_type = net::experimental::concurrent_channel<void(boost::system::error_code, outbound_data)>;
        mutable send_channel_type send_channel_;

        // 第一个 CONNECT 的通知机制
        bool first_connect_resolved_{false};
        h2_headers first_connect_;
        net::steady_timer first_connect_waiter_;

        bool closed_{false};
    }; // class craft

} // namespace psm::multiplex::h2mux
