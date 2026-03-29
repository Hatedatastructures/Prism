/**
 * @file multiplexer.hpp
 * @brief smux 多路复用会话服务端（兼容 Mihomo/xtaci/smux v1）
 * @details 定义 multiplexer 和 pipe 类。multiplexer 负责帧循环、
 * 地址解析、连接目标（pending 阶段），pipe 是纯粹的双向管道，
 * 只负责目标服务器与 mux 之间的数据转发。
 * 数据流：SYN 帧 → multiplexer 创建 pending_entry → PSH 帧累积数据 →
 * 数据足够时解析地址并发起连接 → 连接成功创建 pipe →
 * 后续 PSH 帧由帧循环直接 co_await 写入 target，天然反压。
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

#include <boost/asio.hpp>

#include <forward-engine/channel/smux/config.hpp>
#include <forward-engine/channel/smux/frame.hpp>
#include <forward-engine/channel/transport/transmission.hpp>
#include <forward-engine/memory/container.hpp>

// 前向声明
namespace ngx::resolve
{
    class router;
}

namespace ngx::channel::smux
{
    namespace net = boost::asio;

    class pipe;
    class datagram_pipe;

    /**
     * @class multiplexer
     * @brief smux 多路复用会话服务端
     * @details 管理帧循环和流生命周期。SYN 创建 pending_entry，
     * PSH 累积地址数据后发起连接，连接成功创建 pipe。
     * 发送操作通过 strand 串行化，确保帧不会被交错写入。
     * 生命周期通过 shared_from_this 保活，帧循环异常或结束时自动关闭。
     * @note close() 使用 std::move 取出 pipes_ 避免 iterator invalidation。
     */
    class multiplexer : public std::enable_shared_from_this<multiplexer>
    {
        friend class pipe;
        friend class datagram_pipe;

    public:
        /**
         * @brief 构造 multiplexer
         * @param transport 已建立的传输层连接（通常是 Trojan 隧道）
         * @param router 路由器引用，用于解析地址并连接目标
         * @param cfg smux 配置参数
         * @param sing_mux 是否为 sing-mux 模式（协议协商 + StreamResponse）
         * @param mr 内存资源，为空时使用默认资源
         */
        multiplexer(transport::shared_transmission transport, resolve::router &router, const config &cfg,
                    bool sing_mux = false, memory::resource_pointer mr = {});

        /**
         * @brief 析构函数
         * @details 自动调用 close() 释放所有资源。
         */
        ~multiplexer();

        /**
         * @brief 启动 mux 会话（帧循环）
         * @details 通过 co_spawn 在 transport executor 上启动帧循环协程，
         * 异常或正常退出时自动调用 close()。
         */
        void start();

        /**
         * @brief 关闭会话
         * @details 原子地标记非活跃，取消并关闭 transport，
         * 清空 pending_，std::move 取出 pipes_ 后逐一 close。
         * 幂等操作，多次调用无副作用。
         */
        void close();

        /**
         * @brief 发送 PSH 帧到客户端
         * @param stream_id 目标流标识符
         * @param payload 要发送的数据
         * @return 协程等待对象
         * @note 通过 strand 串行化，可从任意 executor 安全调用。
         */
        auto send_data(std::uint32_t stream_id, std::span<const std::byte> payload) const
            -> net::awaitable<void>;

        /**
         * @brief 发送 FIN 帧到客户端
         * @param stream_id 目标流标识符
         * @note 通过 co_spawn 异步发送，不阻塞调用者。
         */
        void send_fin(std::uint32_t stream_id);

        /**
         * @brief 检查会话是否活跃
         * @return true 表示会话正在运行
         */
        [[nodiscard]] bool is_active() const noexcept
        {
            return active_.load(std::memory_order_acquire);
        }

        /**
         * @brief 从活跃管道映射中移除指定管道
         * @param stream_id 要移除的流标识符
         */
        void remove_pipe(std::uint32_t stream_id);

        /**
         * @brief 从活跃 UDP 管道映射中移除指定管道
         * @param stream_id 要移除的流标识符
         */
        void remove_datagram_pipe(std::uint32_t stream_id);

    private:
        /**
         * @brief 运行入口，根据模式决定是否先协商协议
         * @details sing_mux 模式下先执行协议协商，再进入帧循环。
         * 非 sing_mux 模式直接进入帧循环。
         * @return 协程等待对象
         */
        auto run() -> net::awaitable<void>;

        /**
         * @brief sing-mux 协议协商
         * @details 读取 sing-mux 协议头：[Version 1B][Protocol 1B]，
         * Version > 0 时额外读取 [PaddingLen 2B big-endian][Padding N bytes]。
         * @return 错误码，成功时为空
         */
        auto negotiate_protocol() const -> net::awaitable<std::error_code>;

        /**
         * @brief 帧循环主协程
         * @details 循环读取帧头 + 负载，按命令类型分发到对应 handler。
         * transport 关闭或读取错误时退出循环。
         * @return 协程等待对象
         */
        auto frame_loop() -> net::awaitable<void>;

        /**
         * @brief 处理 SYN 帧，创建 pending_entry
         * @param stream_id 客户端分配的流标识符
         * @return 协程等待对象
         */
        auto handle_syn(std::uint32_t stream_id) -> net::awaitable<void>;

        /**
         * @brief 处理 PSH 帧
         * @details 三路分发：pending 中累积数据并在数据足够时发起连接；
         * connecting 状态忽略（连接协程独立运行）；active 流直接
         * co_await 写 target，帧循环天然反压。
         * @param stream_id 流标识符
         * @param payload 帧负载数据
         * @return 协程等待对象
         */
        auto handle_data(std::uint32_t stream_id, std::span<const std::byte> payload)
            -> net::awaitable<void>;

        /**
         * @brief 处理 FIN 帧
         * @details pending 中直接移除；active 流通知 on_mux_fin 半关闭。
         * @param stream_id 流标识符
         */
        void handle_fin(std::uint32_t stream_id);

        /**
         * @brief 从 pending 解析地址、连接目标、创建 pipe
         * @details 解析 SOCKS5 风格地址，通过 router 连接目标，
         * 成功后创建 pipe 并转发地址之后的剩余数据。
         * 失败时发送 FIN 帧通知客户端。
         * @param stream_id 流标识符
         * @return 协程等待对象
         */
        auto connect_pipe(std::uint32_t stream_id) -> net::awaitable<void>;

        /**
         * @brief 发送帧到客户端（通过 strand 串行化）
         * @param hdr 帧头
         * @param payload 负载数据
         * @return 协程等待对象
         */
        auto send_frame(const frame_header &hdr, std::span<const std::byte> payload) const
            -> net::awaitable<void>;

        transport::shared_transmission transport_; // 底层传输连接
        resolve::router &router_;                  // 路由器引用
        const config &config_;                     // smux 配置
        bool sing_mux_;                             // sing-mux 模式标志
        memory::unsynchronized_pool own_pool_;     // multiplexer 自有的内存池（预留）
        memory::resource_pointer mr_;              // PMR 内存资源（构造时由外部传入或使用默认资源）
        std::atomic<bool> active_{false};          // 会话活跃标志

        /**
         * @struct pending_entry
         * @brief 正在等待地址解析和连接的流条目
         * @details 累积首个 PSH 帧及后续 PSH 帧的数据，
         * 数据足够时由 connect_stream 消费。
         */
        struct pending_entry
        {
            memory::vector<std::byte> buffer; // 累积的地址+数据
            bool connecting = false;          // 是否已发起连接

            explicit pending_entry(memory::resource_pointer mr) : buffer(mr) {}
        };
        memory::unordered_map<std::uint32_t, pending_entry> pending_; // 待连接流

        /// 已连接的活跃管道
        memory::unordered_map<std::uint32_t, std::shared_ptr<pipe>> pipes_;

        /// 活跃的 UDP 管道
        memory::unordered_map<std::uint32_t, std::shared_ptr<datagram_pipe>> udp_pipes_;
        memory::vector<std::byte> recv_buffer_; // 帧头读取缓冲

        // 发送串行化 strand
        net::strand<net::any_io_executor> send_strand_;
    }; // class multiplexer

    /**
     * @class pipe
     * @brief smux 服务端管道（纯双向管道）
     * @details 构造时已持有已连接的 target，不存在空管道阶段。
     * 上行方向（target → mux）由独立协程循环读取并发送；
     * 下行方向（mux → target）由帧循环直接 co_await 写入，
     * 不经过额外缓冲，天然反压。
     * 生命周期通过 shared_from_this 保活，uplink 异常或 FIN 时自动关闭。
     */
    class pipe : public std::enable_shared_from_this<pipe>
    {
    public:
        /**
         * @brief 构造 pipe
         * @param stream_id 流标识符
         * @param mux 所属 multiplexer 引用
         * @param target 已连接的目标传输层
         * @param mr PMR 内存资源
         */
        pipe(std::uint32_t stream_id, std::shared_ptr<multiplexer> mux, transport::shared_transmission target,
             memory::resource_pointer mr);

        /**
         * @brief 析构函数
         * @details 自动调用 close() 释放资源。
         */
        ~pipe();

        /**
         * @brief 启动上行循环（target → mux）
         * @details 通过 co_spawn 在 target executor 上启动 uplink_loop，
         * 异常或正常退出时自动调用 close()。
         */
        void start();

        /**
         * @brief 接收 mux 数据并写入 target
         * @details 直接 co_await 写入目标，由帧循环同步等待，
         * 写不快时天然反压，不经过额外缓冲。
         * @param data 来自 mux PSH 帧的数据
         * @return 协程等待对象
         */
        auto on_mux_data(std::span<const std::byte> data) -> net::awaitable<void>;

        /**
         * @brief 处理 mux 端 FIN
         * @details 标记 mux_closed_，关闭 target 写端。
         * 若 target 也已关闭则立即 close()。
         */
        void on_mux_fin();

        /**
         * @brief 关闭管道
         * @details 关闭 target 传输层，从 multiplexer 移除自身。
         * 幂等操作，多次调用无副作用。
         */
        void close();

        /**
         * @brief 获取流标识符
         * @return 流 ID
         */
        [[nodiscard]] std::uint32_t stream_id() const noexcept
        {
            return stream_id_;
        }

    private:
        /**
         * @brief 上行循环：从 target 读取数据发送到 mux
         * @details 循环 co_await async_read_some 读取 target 数据，
         * 通过 multiplexer::send_data 发送 PSH 帧到客户端。
         * target EOF 或错误时退出，发送 FIN 通知客户端。
         * @return 协程等待对象
         */
        auto uplink_loop()
            -> net::awaitable<void>;

        std::uint32_t stream_id_;                        // 流标识符
        std::shared_ptr<multiplexer> mux_;               // 所属 multiplexer（shared_ptr 保活）
        memory::resource_pointer mr_;            // PMR 内存资源
        transport::shared_transmission target_;  // 目标传输层
        bool closed_ = false;                    // 关闭标志
        memory::vector<std::byte> recv_buffer_;  // 上行读缓冲
        std::atomic<bool> mux_closed_{false};    // mux 端已关闭
        std::atomic<bool> target_closed_{false}; // target 端已关闭
    }; // class pipe

    /**
     * @class datagram_pipe
     * @brief smux UDP 数据报管道
     * @details 处理 smux 中的 UDP 流。每个 PSH 帧承载一个 SOCKS5 UDP relay
     * 格式数据报，可发往不同目标。上行方向通过 idle_timer 管理生命周期，
     * 超时自动关闭。串行处理数据报，由 frame_loop co_await 调用。
     */
    class datagram_pipe : public std::enable_shared_from_this<datagram_pipe>
    {
    public:
        /**
         * @brief 构造 datagram_pipe
         * @param stream_id 流标识符
         * @param mux 所属 multiplexer
         * @param cfg smux 配置参数
         * @param router 路由器引用，用于 DNS 解析
         * @param mr PMR 内存资源
         */
        datagram_pipe(std::uint32_t stream_id, std::shared_ptr<multiplexer> mux,
                       const config &cfg, resolve::router &router,
                       memory::resource_pointer mr);

        /**
         * @brief 析构函数
         * @details 自动调用 close() 释放资源。
         */
        ~datagram_pipe();

        /**
         * @brief 启动空闲超时监控
         * @details 通过 co_spawn 启动 uplink_loop 协程，管理 UDP 管道
         * 生命周期。异常或空闲超时时自动调用 close()。
         */
        void start();

        /**
         * @brief 接收 mux 数据报并转发到目标
         * @param data SOCKS5 UDP relay 格式数据
         * @return 协程等待对象
         */
        auto on_mux_data(std::span<const std::byte> data) -> net::awaitable<void>;

        /**
         * @brief 关闭管道
         * @details 幂等操作，关闭 UDP socket，取消 timer，从 multiplexer 移除。
         */
        void close();

        /**
         * @brief 获取流标识符
         * @return 流 ID
         */
        [[nodiscard]] std::uint32_t stream_id() const noexcept
        {
            return stream_id_;
        }

    private:
        /**
         * @brief 空闲超时监控循环
         */
        auto uplink_loop() -> net::awaitable<void>;

        /**
         * @brief 中继单个 UDP 数据报
         * @param udp_packet SOCKS5 UDP relay 格式数据报
         */
        auto relay_datagram(std::span<const std::byte> udp_packet) -> net::awaitable<void>;

        /**
         * @brief 重置空闲计时器
         */
        void touch_idle_timer();

        std::uint32_t stream_id_;
        std::shared_ptr<multiplexer> mux_;
        resolve::router &router_;
        const config &config_;
        memory::resource_pointer mr_;
        bool closed_ = false;

        net::steady_timer idle_timer_;
        std::optional<net::ip::udp::socket> egress_socket_;
        net::ip::udp::endpoint::protocol_type socket_protocol_{net::ip::udp::v4()};
        memory::vector<std::byte> recv_buffer_;
    }; // class datagram_pipe

} // namespace ngx::channel::smux
