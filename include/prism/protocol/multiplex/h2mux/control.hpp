/**
 * @file control.hpp
 * @brief h2mux 多路复用协议会话控制（HTTP/2 CONNECT stream 多路复用）
 * @details 定义 multiplex::h2mux::control，HTTP/2 CONNECT 多路复用会话实现。
 *          继承 multiplex::multiplexer，利用 nghttp2 库承载 HTTP/2 帧
 *          编解码（帧格式由标准库管理，无需自定义 codec），是这条
 *          mux 连接上的"中心调度控制"：
 *          - frame_loop 将传输层字节流喂给 nghttp2_session_mem_recv，
 *            nghttp2 回调（on_begin_headers/on_header/on_frame_recv/
 *            on_data/on_stream_close）在同步上下文中驱动流生命周期
 *          - 每个 CONNECT 请求创建一个独立 stream：address_resolver
 *            回调解析目标（支持 sing-mux StreamRequest 与 TrustTunnel
 *            :authority 两种模式），激活后创建 stream/datagram
 *          - 发送路径复用基类发送通道：write_frame 经
 *            nghttp2_submit_data/submit_rst_stream + send_pending 编码
 *          - 流量控制由 HTTP/2 标准流控管理，无应用层窗口
 *          特殊功能：wait_first_connect 供 TrustTunnel 验证 auth，
 *          健康检查流（stream_type::check）回复 200 后关闭。
 *          相当于 HTTP/2 CONNECT 代理在服务端的"翻译官 + 调度器"。
 * @note 线程安全：单个实例非线程安全，应在 transport executor 上串行使用
 * @note 生命周期：由 multiplexer::start() 启动，经 shared_from_this 保活
 */
#pragma once

#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/multiplex/datagram.hpp>
#include <prism/protocol/multiplex/h2mux/config.hpp>
#include <prism/protocol/multiplex/multiplexer.hpp>

#include <cstdint>
#include <functional>
#include <memory>

#include <nghttp2/nghttp2.h>

namespace psm::outbound
{

    class proxy;

}

namespace psm::multiplex::h2mux
{

    namespace net = boost::asio;

    /**
     * @enum stream_type
     * @brief HTTP/2 stream 类型
     * @details 从 CONNECT 请求的地址或 StreamRequest flags 中提取，
     *          决定创建 stream、datagram 还是执行健康检查。
     */
    enum class stream_type : std::uint8_t
    {
        tcp,  ///< TCP 流，创建 stream 双向转发
        udp,  ///< UDP 数据报，创建 datagram 中继
        icmp, ///< ICMP 代理（后续迭代）
        check ///< 健康检查，回复 200 后关闭
    };

    /**
     * @struct stream_info
     * @brief address_resolver 返回的流地址信息
     * @details valid=false 表示地址信息不完整（如 sing-mux 模式需要等待 DATA 帧）。
     */
    struct stream_info
    {
        memory::string host;                 ///< 目标主机
        std::uint16_t port = 0;              ///< 目标端口
        stream_type type = stream_type::tcp; ///< 流类型
        bool valid = false;                  ///< 地址信息是否完整可用
    };

    /**
     * @struct h2_headers
     * @brief 从 HTTP/2 HEADERS 帧收集的请求头
     * @details 在 on_header 回调中逐步填充，传递给 address_resolver。
     */
    struct h2_headers
    {
        std::int32_t stream_id{0}; ///< HTTP/2 stream ID
        memory::string method;     ///< :method 头（CONNECT 校验用）
        memory::string authority;  ///< :authority 头（CONNECT 目标）
        memory::string host;       ///< Host 头（用于类型判断）
        memory::string user_agent; ///< User-Agent 头
        memory::string proxy_auth; ///< Proxy-Authorization 头
    };

    /**
     * @brief 地址解析回调类型
     * @param stream_id HTTP/2 stream ID
     * @param headers 从 HEADERS 帧收集的请求头
     * @return stream_info 解析结果，valid=false 表示需要等待 DATA 帧
     * @details 由外部注入，两种实现：
     *          - sing-mux resolver：等待 StreamRequest
     *          - TrustTunnel resolver：从 authority 解析目标
     */
    using address_resolver = std::function<stream_info(std::int32_t stream_id, const h2_headers &headers)>;

    /**
     * @struct h2_pending_entry
     * @brief 等待地址解析和连接的 HTTP/2 stream 条目
     * @details HEADERS(CONNECT) 帧创建后由 address_resolver 尝试解析；
     *          valid=false（sing-mux 模式）时等待首个 DATA 帧的
     *          StreamRequest 数据。connecting 防重复激活。
     */
    struct h2_pending_entry
    {
        h2_headers headers;                     ///< 收集的 HTTP/2 请求头
        stream_info info;                       ///< resolver 返回的地址信息
        bool connecting = false;                ///< 是否已发起连接
        memory::vector<std::byte> buffer;       ///< StreamRequest 累积缓冲
        memory::vector<std::byte> pending_data; ///< 解析后的剩余数据（转发给流）
    };

    /**
     * @class control
     * @brief h2mux 多路复用协议会话控制
     * @details 利用 nghttp2 实现 HTTP/2 服务端帧编解码（nghttp2 回调在
     *          frame_loop 的 mem_recv 同步上下文中执行），数据经基类
     *          发送通道串行化后由 write_frame 经 nghttp2_submit_data
     *          编码为 DATA 帧。不走 sing-mux bootstrap 协商，
     *          由 scheme 或 bootstrap 直接创建。
     */
    class control final : public multiplexer
    {
    public:
        /**
         * @brief 构造 h2mux 会话
         * @param opts 基类构造参数（传输层、出站代理、配置、内存资源）
         * @param resolver 地址解析回调（决定如何从 CONNECT 提取目标地址）
         * @param sing_streams 是否 sing-mux 流（激活后前置 StreamResponse 状态字节）
         */
        explicit control(multiplexer_options opts, address_resolver resolver, bool sing_streams = false);

        ~control() noexcept override;

        /**
         * @brief 等待第一个 CONNECT 请求
         * @return 第一个有效的 CONNECT 请求头，或 nullopt（连接关闭）
         * @details 供 TrustTunnel scheme 验证 auth 后再交给 control 管理。
         */
        [[nodiscard]] auto wait_first_connect() -> net::awaitable<std::optional<h2_headers>>;

        /**
         * @brief 回复 CONNECT 请求
         * @param stream_id HTTP/2 stream ID
         * @param status HTTP 状态码（200 或 407）
         * @return 0 成功，非 0 失败
         */
        [[nodiscard]] auto respond_connect(std::int32_t stream_id, std::uint32_t status) -> std::int32_t;

        /**
         * @brief 发送 nghttp2 缓冲区中的待输出数据
         * @details TrustTunnel 在认证接管后手动刷新输出缓冲。
         */
        [[nodiscard]] auto send_pending() -> net::awaitable<void>;

        /**
         * @brief 激活指定 stream（解析地址、连接目标、创建 stream/datagram）
         * @param stream_id 流标识符
         * @details TrustTunnel 认证通过后手动激活首个 CONNECT 流。
         */
        [[nodiscard]] auto activate_stream(std::uint32_t stream_id) -> net::awaitable<void>;

    protected:
        /**
         * @brief 协议主循环
         * @details 初始化 nghttp2 会话，发送 SETTINGS，进入 frame_loop。
         */
        auto run() -> net::awaitable<void> override;

        /**
         * @brief 编码并写入一个逻辑帧
         * @param frame 逻辑帧（所有权转移）
         * @details data 帧经 nghttp2_submit_data 编码为 HTTP/2 DATA 帧；
         *          fin 帧经 nghttp2_submit_rst_stream 关闭流；
         *          然后 send_pending 把 nghttp2 输出缓冲写入传输层。
         */
        auto write_frame(outbound_frame frame) -> net::awaitable<void> override;

    private:
        /**
         * @brief 初始化 nghttp2 服务端会话与回调
         * @return 0 成功，非 0 失败
         */
        [[nodiscard]] auto init_nghttp2() -> std::int32_t;

        /**
         * @brief 帧循环主协程
         * @details 读取传输层字节流喂给 nghttp2_session_mem_recv，
         *          回调在同步上下文中驱动流生命周期。
         */
        auto frame_loop() -> net::awaitable<void>;

        /**
         * @brief 处理完整的 CONNECT 请求
         * @details 由 on_frame_recv 回调触发，调用 address_resolver 解析地址，
         *          成功则 spawn activate_stream。
         */
        void handle_connect(std::int32_t stream_id);

        /**
         * @brief 尝试激活 stream（解析地址并 spawn activate_stream）
         * @param stream_id 流标识符
         * @details 供 handle_connect 与 on_data（sing-mux StreamRequest
         *          解析完成后）共用，connecting 防重复激活。
         */
        void spawn_activate(std::uint32_t stream_id);

        /**
         * @brief 处理单个 datagram 流的重组与发送
         * @details h2mux UDP 数据报为 length-prefixed 格式，目标地址在
         *          激活时确定（CONNECT 目标），此处累积跨帧数据并解析。
         */
        auto process_udp(std::uint32_t stream_id, memory::vector<std::byte> payload) -> net::awaitable<void>;

        /**
         * @brief 构造 datagram 端点解析回调
         */
        [[nodiscard]] auto make_resolve() const -> resolve_fn;

        /**
         * @brief 构造 datagram 响应回传回调
         */
        [[nodiscard]] auto make_emit(std::uint32_t stream_id) -> emit_fn;

        // nghttp2 回调（静态函数，通过 user_data 获取 this）
        static auto on_begin_headers(nghttp2_session *, const nghttp2_frame *, void *) -> int;
        static auto on_header(nghttp2_session *, const nghttp2_frame *, const uint8_t *, size_t,
                              const uint8_t *, size_t, uint8_t, void *) -> int;
        static auto on_frame_recv(nghttp2_session *, const nghttp2_frame *, void *) -> int;
        static auto on_data(nghttp2_session *, uint8_t, int32_t, const uint8_t *, size_t, void *) -> int;
        static auto on_stream_close(nghttp2_session *, int32_t, uint32_t, void *) -> int;

        /**
         * @struct udp_entry
         * @brief UDP 流重组缓冲（length-prefixed 格式）
         */
        struct udp_entry
        {
            memory::vector<std::byte> buffer; ///< 累积的未解析数据
            bool processing = false;          ///< 处理循环运行标志
            memory::string dest_host;         ///< 固定目标主机（CONNECT 时确定）
            std::uint16_t dest_port = 0;      ///< 固定目标端口

            explicit udp_entry(memory::resource_pointer mr) : buffer(mr), dest_host(mr)
            {
            }
        };

        /**
         * @struct data_source
         * @brief nghttp2 DATA 数据源（生命周期绑定会话映射，防延迟读取悬垂）
         */
        struct data_source
        {
            std::shared_ptr<memory::vector<std::byte>> buf;
            std::size_t offset{0};
        };

        nghttp2_session *session_{nullptr}; ///< nghttp2 会话
        address_resolver resolver_;         ///< 地址解析回调
        bool sing_streams_{false};          ///< sing-mux 流模式（激活前置状态字节）
        std::function<net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>(std::string_view,
                                                                                     std::string_view)>
            router_fn_; ///< UDP 路由回调

        memory::unordered_map<std::uint32_t, h2_pending_entry> h2_pending_; ///< 等待解析的 HTTP/2 stream
        memory::unordered_map<std::uint32_t, udp_entry> udp_bufs_;          ///< UDP 重组缓冲表
        memory::unordered_map<std::uint32_t, std::unique_ptr<data_source>>
            pending_data_; ///< DATA 数据源（随流存活）

        // 第一个 CONNECT 的通知机制（TrustTunnel auth 验证用）
        bool connect_resolved_{false};     ///< 首个 CONNECT 是否已到达
        h2_headers first_connect_;         ///< 首个 CONNECT 的请求头
        net::steady_timer connect_waiter_; ///< 首个 CONNECT 等待定时器
    };

    /**
     * @brief 创建 h2mux 会话共享指针
     * @param opts 基类构造参数
     * @param init 构造参数（出站代理、配置、地址解析回调）
     * @return control 的共享指针
     */
    [[nodiscard]] inline auto make_control(multiplexer_options opts, address_resolver resolver)
        -> std::shared_ptr<control>
    {
        return std::make_shared<control>(std::move(opts), std::move(resolver));
    }

} // namespace psm::multiplex::h2mux
