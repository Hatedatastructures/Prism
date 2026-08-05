/**
 * @file control.hpp
 * @brief yamux 多路复用协议会话控制（中心调度控制）
 * @details 定义 multiplex::yamux::control，yamux 协议的会话实现。
 *          继承 multiplex::multiplexer，负责 yamux 协议的帧循环、
 *          帧分发、窗口流控与流激活，是这条 mux 连接上的
 *          "中心调度控制"：
 *          - frame_loop 读取 12 字节大端帧头 → codec 解析 → 按消息
 *            类型分发（Data 按标志再分发 / WindowUpdate / Ping / GoAway）
 *          - 窗口流控：send() 扣减发送窗口，不足时等待 WindowUpdate
 *            唤醒；接收侧累计消费量达阈值时回发 WindowUpdate
 *          - 流激活：解析地址（sing-mux 格式）后创建 stream/datagram
 *          协议特有的窗口表、pending 超时、Ping 心跳全部隔离在本类，
 *          基类与 stream/datagram 不感知 yamux 细节。
 *          相当于 yamux 协议在服务端的"翻译官 + 调度器 + 流量计"。
 * @note 线程安全：单个实例非线程安全，应在 transport executor 上串行使用
 * @note 生命周期：由 multiplexer::start() 启动，经 shared_from_this 保活
 */
#pragma once

#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/multiplex/datagram.hpp>
#include <prism/protocol/multiplex/multiplexer.hpp>
#include <prism/protocol/multiplex/yamux/codec.hpp>
#include <prism/protocol/multiplex/yamux/frame.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <cstdint>
#include <memory>


namespace psm::multiplex::yamux
{

    namespace net = boost::asio;

    /**
     * @struct stream_window
     * @brief 流窗口状态，用于流量控制
     * @details 跟踪单个流的发送和接收窗口。send_window 由 send() 扣减、
     *          WindowUpdate 帧增加；recv_consumed 累计接收消费量，达
     *          阈值时回发 WindowUpdate。window_signal 在窗口不足时
     *          挂起发送方，WindowUpdate 到达时 cancel 唤醒。
     */
    struct stream_window
    {
        std::atomic<std::uint32_t> send_window{default_window}; // 发送窗口（对端允许发送的数据量）
        std::atomic<std::uint32_t> recv_consumed{0};           // 已消费的接收数据量（阈值触发 WindowUpdate）
        std::shared_ptr<net::steady_timer> window_signal;      // 窗口更新信号定时器

        explicit stream_window(const net::any_io_executor &ex)
            : window_signal(std::make_shared<net::steady_timer>(ex))
        {
            window_signal->expires_at(net::steady_timer::time_point::max());
        }
    };

    /**
     * @class control
     * @brief yamux 多路复用协议会话控制
     * @details 实现 yamux 协议（兼容 Hashicorp/yamux + sing-mux 协商）：
     *          - 12 字节大端帧头编解码（经 yamux_codec）
     *          - 窗口流控（send_window 扣减/等待，recv WindowUpdate 回发）
     *          - Ping 心跳与 GoAway 会话终止
     *          - pending 流打开超时保护
     * @note send() 覆写基类以施加发送窗口流控，其余 egress 行为沿用基类
     */
    class control final : public multiplexer
    {
    public:
        /**
         * @brief 构造 yamux 会话
         * @param opts 基类构造参数（传输层、出站代理、配置、内存资源）
         */
        explicit control(multiplexer_options opts);

        ~control() noexcept override;

        /**
         * @brief 回传流数据（覆写：施加发送窗口流控）
         * @details 扣减流发送窗口，窗口不足时等待 WindowUpdate 唤醒；
         *          窗口足够后投递数据帧到发送通道。
         */
        auto send(std::uint32_t stream_id, memory::vector<std::byte> payload)
            -> net::awaitable<void> override;

        /**
         * @brief 关闭会话（幂等）
         * @details 先取消 pending 超时定时器与窗口信号，再执行基类清理。
         */
        void close() override;

        /**
         * @brief 从注册表移除流并清理窗口状态
         */
        void drop(std::uint32_t stream_id) override;

    protected:
        /**
         * @brief 协议主循环
         * @details 启动 Ping 心跳（配置开启时），然后执行 frame_loop。
         */
        auto run()
            -> net::awaitable<void> override;

        /**
         * @brief 编码并写入一个逻辑帧
         * @details data/fin 经 yamux_codec 编码为 Data 帧字节写入传输层；
         *          control 帧（WindowUpdate/Ping/GoAway/RST）的字节已由
         *          调用方预编码，直接写入。写失败时关闭整个会话。
         */
        auto write_frame(outbound_frame frame)
            -> net::awaitable<void> override;

    private:
        /**
         * @struct udp_entry
         * @brief UDP 流重组缓冲（同 smux：sing-mux 格式数据报重组）
         */
        struct udp_entry
        {
            memory::vector<std::byte> buffer; ///< 累积的未解析数据
            bool processing = false;          ///< 处理循环运行标志
            memory::string dest_host;         ///< length_prefixed 模式固定目标主机
            std::uint16_t dest_port = 0;      ///< length_prefixed 模式固定目标端口
            addr_mode mode{addr_mode::length_prefixed}; ///< 地址编码模式

            explicit udp_entry(memory::resource_pointer mr) : buffer(mr), dest_host(mr) {}
        };

        /**
         * @brief 帧循环主协程
         * @details 读取 12 字节帧头 + Data 帧载荷，按消息类型分发。
         */
        auto frame_loop()
            -> net::awaitable<void>;

        /**
         * @brief 处理 Data 帧
         * @details 按标志分发：SYN → handle_syn，RST → handle_rst，
         *          FIN → handle_fin，无标志 → dispatch_data。
         */
        auto handle_data(const frame_header &hdr, memory::vector<std::byte> payload)
            -> net::awaitable<void>;

        /**
         * @brief 处理 Data(SYN) 帧，创建流并回复 ACK
         * @details sing-mux 兼容模式：允许 Data 帧携带 SYN 标志和地址数据。
         */
        auto handle_syn(std::uint32_t stream_id, memory::vector<std::byte> payload)
            -> net::awaitable<void>;

        /**
         * @brief 处理 RST 标志（强制重置流）
         */
        void handle_rst(std::uint32_t stream_id);

        /**
         * @brief 处理 FIN 标志（半关闭流）
         */
        void handle_fin(std::uint32_t stream_id);

        /**
         * @brief 分发纯数据帧到 pending/stream/datagram
         * @details pending 流累积地址数据并尝试激活；stream 投递数据
         *          （co_spawn 防慢 target 阻塞帧循环）；datagram 流进入
         *          重组缓冲；未知流回发 RST。
         */
        auto dispatch_data(std::uint32_t stream_id, memory::vector<std::byte> payload)
            -> net::awaitable<void>;

        /**
         * @brief 尝试激活 pending 流（缓冲 ≥ 7 字节且未连接时）
         */
        void try_activate_pending(std::uint32_t stream_id);

        /**
         * @brief 处理 WindowUpdate 帧
         * @details 按标志分发：RST 重置流、FIN 半关闭、SYN 打开新流、
         *          SYN+ACK 确认流、普通帧增加 send_window 并唤醒发送方。
         */
        auto handle_winupd(const frame_header &hdr)
            -> net::awaitable<void>;

        /**
         * @brief 处理 Ping 帧
         * @details SYN 为心跳请求，回复 ACK 携带相同 ID；ACK 忽略。
         */
        auto handle_ping(const frame_header &hdr)
            -> net::awaitable<void>;

        /**
         * @brief 处理 GoAway 帧，关闭整个会话
         */
        auto handle_goaway(const frame_header &hdr)
            -> net::awaitable<void>;

        /**
         * @brief 从 pending 解析地址、连接目标、创建 stream/datagram
         */
        auto activate_stream(std::uint32_t stream_id)
            -> net::awaitable<void>;

        /**
         * @brief 发送地址解析错误状态并关闭流
         */
        auto send_addr_err(std::uint32_t stream_id)
            -> net::awaitable<void>;

        /**
         * @brief 激活 UDP 流，创建 datagram
         */
        auto activate_udp(activate_opts opts)
            -> net::awaitable<void>;

        /**
         * @brief 激活 TCP 流，连接目标并创建 stream
         */
        auto activate_tcp(activate_opts opts)
            -> net::awaitable<void>;

        /**
         * @brief 处理单个 datagram 流的重组与发送
         */
        auto process_udp(std::uint32_t stream_id, memory::vector<std::byte> payload)
            -> net::awaitable<void>;

        /**
         * @brief 为 pending 流设置打开超时定时器
         */
        void start_pending(std::uint32_t stream_id);

        /**
         * @brief pending 流超时处理协程
         */
        auto pending_timeout(std::uint32_t stream_id, std::shared_ptr<net::steady_timer> timer)
            -> net::awaitable<void>;

        /**
         * @brief 获取或创建流窗口
         */
        [[nodiscard]] auto ensure_window(std::uint32_t stream_id) -> stream_window *;

        /**
         * @brief 获取流窗口（不创建）
         */
        [[nodiscard]] auto get_window(std::uint32_t stream_id) const -> stream_window *;

        /**
         * @brief 检查并更新接收窗口，必要时发送 WindowUpdate
         */
        auto update_recv_win(std::uint32_t stream_id, std::uint32_t consumed)
            -> net::awaitable<void>;

        /**
         * @brief 投递协议控制帧（预编码帧头，经发送通道串行化）
         * @param type 消息类型
         * @param f 标志位
         * @param stream_id 流标识符
         * @param length 长度字段（增量/ID/原因码）
         */
        auto push_control(message_type type, flags f, std::uint32_t stream_id, std::uint32_t length)
            -> net::awaitable<void>;

        /**
         * @brief 主动 Ping 心跳循环
         */
        auto ping_loop()
            -> net::awaitable<void>;

        /**
         * @brief 构造 datagram 端点解析回调
         */
        [[nodiscard]] auto make_resolve() const
            -> resolve_fn;

        /**
         * @brief 构造 datagram 响应回传回调
         */
        [[nodiscard]] auto make_emit(std::uint32_t stream_id, addr_mode mode)
            -> emit_fn;

        yamux_codec codec_; ///< yamux 帧编解码策略
        std::function<net::awaitable<std::pair<fault::code,
                                               net::ip::udp::endpoint>>(std::string_view, std::string_view)> router_fn_; ///< UDP 路由回调
        memory::unordered_map<std::uint32_t, std::unique_ptr<stream_window>> windows_;            ///< 流窗口映射
        memory::unordered_map<std::uint32_t, std::shared_ptr<net::steady_timer>> pending_timers_; ///< pending 流超时定时器
        memory::unordered_map<std::uint32_t, udp_entry> udp_bufs_; ///< UDP 重组缓冲表
        std::atomic<std::uint32_t> ping_id_{0};                    ///< Ping 标识符计数器
    };

    /**
     * @brief 创建 yamux 会话共享指针
     * @param opts 基类构造参数
     * @return control 的共享指针
     */
    [[nodiscard]] inline auto make_control(multiplexer_options opts)
        -> std::shared_ptr<control>
    {
        return std::make_shared<control>(std::move(opts));
    }

} // namespace psm::multiplex::yamux
