/**
 * @file craft.hpp
 * @brief yamux 多路复用会话服务端（兼容 Hashicorp/yamux + sing-mux 协商）
 * @details yamux::craft 继承 multiplex::core，实现 yamux 协议服务端逻辑。
 * 与 smux 相比，yamux 提供完整的流量控制（256KB 初始窗口）、标志位系统、心跳机制。
 * 帧格式为 12 字节大端帧头，而非 smux 的 8 字节小端帧头。
 *
 * 流打开流程（sing-mux 协商后）：
 * 1. 客户端发送 WindowUpdate(SYN) → 服务端创建 pending，回复 WindowUpdate(ACK)
 * 2. 客户端发送 Data(none) 携带目标地址 → 服务端解析地址，连接目标
 * 3. 服务端发送 Data(none) 携带 0x00 成功状态 → 创建 duct/parcel
 *
 * 消息类型处理：
 * - Data: 根据 flags 处理 SYN/数据/FIN/RST，dispatch_data 非阻塞分发
 * - WindowUpdate: 流创建（SYN）、确认（ACK）、窗口更新（普通）
 * - Ping: SYN 为请求，回复 ACK
 * - GoAway: 关闭整个会话
 *
 * 发送路径与 smux 相同架构：
 * duct::target_read_loop() → send_data() → push_frame() → channel_ → send_loop() → transport
 * header 与 payload 分离传递，scatter-gather 写入，零拷贝。
 *
 * @note 通过 core 的虚函数接口发送帧，duct/parcel 无需感知具体协议
 */
#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <unordered_map>

#include <boost/asio/experimental/concurrent_channel.hpp>

#include <prism/multiplex/core.hpp>
#include <prism/multiplex/config.hpp>
#include <prism/multiplex/yamux/frame.hpp>
#include <prism/memory/container.hpp>

namespace psm::multiplex::yamux
{
    namespace net = boost::asio;

    /**
     * @struct outbound_frame
     * @brief 出站帧结构，header 与 payload 分离传递
     * @details header 为 12 字节编码后的帧头，payload 持有实际数据。
     * 两者分离传递至 send_loop，由 send_loop 分别写入 transport，
     * 消除将 header+payload 拼接到单一 buffer 的 memcpy 开销。
     */
    struct outbound_frame
    {
        std::array<std::byte, frame_header_size> header{}; // 编码后的帧头（12 字节）
        memory::vector<std::byte> payload;                 // 帧载荷数据（所有权转移）

        outbound_frame() = default;
        explicit outbound_frame(memory::resource_pointer mr) : payload(mr) {}
    }; // struct outbound_frame

    /**
     * @struct stream_window
     * @brief 流窗口状态，用于流量控制
     * @details 跟踪单个流的发送和接收窗口，使用原子变量确保线程安全。
     * duct::target_read_loop 和 frame_loop 可能并发访问 send_window，
     * dispatch_data 和 update_recv_window 可能并发访问 recv_consumed。
     */
    struct stream_window
    {
        std::atomic<std::uint32_t> send_window{initial_stream_window}; // 发送窗口（对端允许发送的数据量）
        std::atomic<std::uint32_t> recv_window{initial_stream_window}; // 接收窗口（本地允许接收的数据量）
        std::atomic<std::uint32_t> recv_consumed{0};                   // 已消费的接收数据量（阈值触发 WindowUpdate）
    }; // struct stream_window

    /**
     * @class craft
     * @brief yamux 多路复用会话服务端
     * @details 继承 core，实现 yamux 协议服务端逻辑，包括帧读写、窗口管理、
     * 心跳和流生命周期管理。生命周期由 core::start() 启动，通过 co_spawn 运行 run() 协程。
     * 与 smux 相比，增加了窗口管理（send_window/recv_window）、Ping 心跳、12 字节大端帧头。
     */
    class craft final : public core
    {
    public:
        /**
         * @brief 构造 yamux 会话
         * @param transport 已建立的传输层连接（通常是 Trojan 隧道）
         * @param router 路由器引用，用于解析地址并连接目标
         * @param cfg 多路复用配置参数（含 yamux 子配置）
         * @param mr PMR 内存资源，为空时使用默认资源
         */
        craft(channel::transport::shared_transmission transport, resolve::router &router,
              const multiplex::config &cfg, memory::resource_pointer mr = {});

        ~craft() override;

        /**
         * @brief 发送 Data 帧到客户端
         * @param stream_id 目标流标识符
         * @param payload 要发送的数据（所有权转移，零拷贝传递至发送通道）
         * @details 将 payload 编码为 outbound_frame（header 与 payload 分离），
         * 推入 channel_ 发送通道。不执行 memcpy，payload 直接 move。
         * @note 方法定义在 craft.cpp 中
         */
        auto send_data(std::uint32_t stream_id, memory::vector<std::byte> payload) const
            -> net::awaitable<void> override;

        /**
         * @brief 发送 FIN 帧到客户端
         * @param stream_id 目标流标识符
         * @details 通过 co_spawn 异步发送，不阻塞调用者（通常是 duct 的 target_read_loop）。
         * @note 方法定义在 craft.cpp 中
         */
        void send_fin(std::uint32_t stream_id) override;

        /**
         * @brief 获取 transport executor
         * @return net::any_io_executor transport 的执行器
         * @note 用于 duct/parcel 协程调度和 co_spawn
         */
        [[nodiscard]] net::any_io_executor executor() const override;

    private:
        /**
         * @brief 协议主循环（由 core::start() 通过 co_spawn 启动）
         * @details 启动 send_loop 后进入 frame_loop，frame_loop 退出后取消 channel_。
         */
        auto run() -> net::awaitable<void> override;

        /**
         * @brief 帧循环主协程
         * @details 循环读取帧头（12 字节）+ 载荷（Data 帧才有），按消息类型分发：
         * - Data: handle_data 根据 flags 分发
         * - WindowUpdate: handle_window_update 处理流创建或窗口更新
         * - Ping: handle_ping 回复 ACK
         * - GoAway: handle_go_away 关闭会话
         * 读取失败或无效帧时退出循环。
         */
        auto frame_loop() -> net::awaitable<void>;

        /**
         * @brief 处理 Data 帧
         * @param hdr 帧头
         * @param payload 帧载荷（所有权转移）
         * @details 根据 flags 分发：SYN → handle_syn，RST → handle_rst，
         * FIN → handle_fin，无标志 → dispatch_data。
         */
        auto handle_data(const frame_header &hdr, memory::vector<std::byte> payload)
            -> net::awaitable<void>;

        /**
         * @brief 处理 Data(SYN) 帧，创建流并回复 ACK
         * @param stream_id 流标识符
         * @param payload 帧载荷（可能携带地址数据）
         * @details 检查 max_streams 限制，创建 pending_entry，回复 WindowUpdate(ACK)，
         * payload 非空时累积到 buffer 并尝试激活。这是 sing-mux 兼容模式，
         * 允许在 Data 帧中携带 SYN 标志和地址数据。
         */
        auto handle_syn(std::uint32_t stream_id, memory::vector<std::byte> payload)
            -> net::awaitable<void>;

        /**
         * @brief 处理 RST 标志（强制重置流）
         * @param stream_id 要重置的流标识符
         * @details 清除 pending、调用 duct/parcel 的关闭方法、移除窗口状态。
         */
        void handle_rst(std::uint32_t stream_id);

        /**
         * @brief 处理 FIN 标志（半关闭流）
         * @param stream_id 要半关闭的流标识符
         * @details 按顺序检查：pending（直接移除）→ duct（on_mux_fin）→ parcel（close）。
         */
        void handle_fin(std::uint32_t stream_id);

        /**
         * @brief 分发纯数据帧到 pending/duct/parcel
         * @param stream_id 流标识符
         * @param payload 帧载荷（所有权转移）
         * @details 三路分发逻辑：
         * 1. pending 流：累积数据，尝试激活，更新接收窗口
         * 2. 已连接 duct：co_spawn(detached) 调用 on_mux_data，不阻塞帧循环
         * 3. 活跃 parcel：co_spawn(detached) 调用 on_mux_data
         * 流不存在时发送 WindowUpdate(RST)。
         */
        auto dispatch_data(std::uint32_t stream_id, memory::vector<std::byte> payload)
            -> net::awaitable<void>;

        /**
         * @brief 尝试激活 pending 流
         * @param stream_id 流标识符
         * @param entry pending 条目引用
         * @details 当 buffer >= 7 字节且未连接时，通过 co_spawn 启动 activate_stream。
         * connecting 标志防止重复激活。
         */
        void try_activate_pending(std::uint32_t stream_id, pending_entry &entry);

        /**
         * @brief 处理 WindowUpdate 帧
         * @param hdr 帧头（length 字段为窗口增量）
         * @details 处理多种情况：
         * - stream_id == 0：会话级窗口更新，忽略
         * - RST 标志：重置流
         * - FIN 标志：半关闭流
         * - SYN（无 ACK）：客户端打开新流，回复 ACK
         * - SYN+ACK：确认服务端发起的流（本实现不支持服务端发起）
         * - 普通：增加 send_window
         */
        auto handle_window_update(const frame_header &hdr) -> net::awaitable<void>;

        /**
         * @brief 处理 Ping 帧
         * @param hdr 帧头（length 字段为 ping ID）
         * @details SYN 标志为请求，回复 Ping(ACK) 并携带相同 ID；
         * ACK 标志为响应，忽略。
         */
        auto handle_ping(const frame_header &hdr) const -> net::awaitable<void>;

        /**
         * @brief 处理 GoAway 帧
         * @param hdr 帧头（length 字段为终止原因码）
         * @details 收到 GoAway 后调用 close() 关闭整个会话。
         */
        auto handle_go_away(const frame_header &hdr) -> net::awaitable<void>;

        /**
         * @brief 从 pending 解析地址、连接目标、创建 duct/parcel
         * @param stream_id 流标识符
         * @details 解析 SOCKS5 格式目标地址（复用 smux::parse_mux_address），区分 TCP/UDP：
         * - UDP: 发送 0x00 成功状态 → 创建 parcel → 转发剩余数据
         * - TCP: 通过 router 连接目标 → 发送 0x00 成功状态 → 创建 duct → 转发剩余数据
         * 地址解析失败时发送 0x01 错误状态并 FIN。
         */
        auto activate_stream(std::uint32_t stream_id) -> net::awaitable<void>;

        // --- 窗口管理 ---

        /**
         * @brief 获取或创建流窗口
         * @param stream_id 流标识符
         * @return 流窗口指针，永不返回 nullptr
         */
        stream_window *get_or_create_window(std::uint32_t stream_id);

        /**
         * @brief 检查并更新接收窗口，必要时发送 WindowUpdate
         * @param stream_id 流标识符
         * @param consumed 本次消费的数据量
         * @details 累积 recv_consumed，当达到 initial_stream_window/2 阈值时，
         * 发送 WindowUpdate(none) 帧，将 delta 设为累积消费量。
         */
        auto update_recv_window(std::uint32_t stream_id, std::uint32_t consumed)
            -> net::awaitable<void>;

        // --- 发送 ---

        /**
         * @brief 将帧推送到发送通道
         * @param type 消息类型
         * @param f 标志位
         * @param stream_id 流标识符
         * @param length Length 字段值
         * @param payload 帧载荷（所有权转移，Data 帧有效）
         * @details 编码帧头为 12 字节数组，与 payload 组装为 outbound_frame，
         * 通过 channel_ 发送通道传递给 send_loop。header 与 payload 分离，零拷贝。
         */
        auto push_frame(message_type type, flags f, std::uint32_t stream_id,
                        std::uint32_t length, memory::vector<std::byte> payload) const
            -> net::awaitable<void>;

        /**
         * @brief 发送循环协程，scatter-gather 写入 transport
         * @details 从 channel_ 取出 outbound_frame，先写 12 字节帧头，再写 payload。
         * 写入失败时调用 close() 关闭整个会话。channel_ 取消时退出。
         */
        auto send_loop() -> net::awaitable<void>;

        /// 发送通道类型
        using channel_type = net::experimental::concurrent_channel<void(boost::system::error_code, outbound_frame)>;
        mutable channel_type channel_; // 有界发送通道，串行化多流写入，容量为 max_streams

        memory::unordered_map<std::uint32_t, std::unique_ptr<stream_window>> windows_; // 流窗口映射
        memory::vector<std::byte> recv_buffer_;                                        // 帧头读取缓冲（12 字节）
    }; // class craft

} // namespace psm::multiplex::yamux
