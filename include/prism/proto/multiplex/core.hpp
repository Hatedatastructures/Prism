/**
 * @file core.hpp
 * @brief 多路复用核心抽象基类声明
 * @details 声明 multiplex::core，提供所有多路复用协议共享的
 * 会话生命周期管理、流状态跟踪和发送串行化。协议特定的帧格式、
 * 解析和协商由子类实现（如 smux::craft）。core 管理三种流状态：
 * pending（SYN 后等待地址数据）、duct（TCP 流双向转发）、
 * parcel（UDP 数据报中继）。duct 和 parcel 通过 core 的虚函数
 * 接口与具体协议交互，无需感知底层帧格式。
 * @note 设计原则：core 是协议无关的抽象层，所有帧编解码委托给子类
 * @note 线程安全：单个实例非线程安全，应在 transport executor 上串行使用
 * @note 方法实现位于 core.cpp 中
 */
#pragma once

#include <prism/foundation/memory/container.hpp>
#include <prism/proto/multiplex/config.hpp>
#include <prism/proto/protocol/types.hpp>
#include <prism/trace/context.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <cstdint>
#include <memory>


// 前向声明
namespace psm::outbound
{

    class proxy;

}

namespace psm::stats::traffic
{

    class traffic_state;
}

namespace psm::multiplex
{

    namespace net = boost::asio;

    class duct;
    class parcel;

    /**
     * @struct core_options
     * @brief core 构造参数聚合
     * @details 将 core 构造函数的传输层连接、出站代理、配置和内存资源
     * 聚合为单一结构体，将构造函数参数降至 1 个。
     */
    struct core_options
    {
        transport::shared_transmission transport; ///< 已建立的传输层连接（通常是 TLS 隧道）
        outbound::proxy *outbound{nullptr};       ///< 出站代理接口（非拥有，worker 生命周期）
        const config &cfg;                        ///< 多路复用配置参数
        memory::resource_pointer mr = {};         ///< PMR 内存资源，为空时使用默认资源
    };

    /**
     * @class core
     * @brief 多路复用核心抽象基类
     * @details 管理流生命周期和发送串行化。SYN 创建 pending_entry，
     * 协议子类解析地址后连接目标，创建 duct/parcel 进行双向转发。
     * 继承 std::enable_shared_from_this，支持协程上下文中安全的共享指针管理。
     * duct 和 parcel 声明为 friend，可直接访问 pending_/ducts_/parcels_。
     * 流状态转换：SYN 帧创建 pending_entry 累积地址数据，
     * 地址完整后 activate_stream() 连接目标创建 duct（TCP）或 parcel（UDP），
     * FIN 帧半关闭或完全关闭对应流。
     * @note 发送操作通过子类的串行化机制确保帧不会被交错写入
     * @note close() 是幂等操作，多次调用无副作用
     * @warning 子类必须实现 send_data、send_fin、executor 和 run 四个纯虚函数
     */
    class core : public std::enable_shared_from_this<core>
    {
        friend class duct;
        friend class parcel;

    public:
        /**
         * @brief 构造 core
         * @param opts 构造参数聚合，包含传输层连接、路由器、配置和内存资源
         * @details 初始化传输层和配置，会话处于未启动状态。
         * 调用 start() 后才会进入协议主循环。
         * @note 方法定义在 core.cpp 中
         */
        explicit core(core_options opts);

        virtual ~core() noexcept;

        /**
         * @brief 启动 mux 会话
         * @details 通过 co_spawn 在 transport executor 上启动 run() 协程，
         * 异常或正常退出时自动调用 close()。
         * @note 方法定义在 core.cpp 中
         */
        void start();

        /**
         * @brief 关闭会话（幂等）
         * @details 原子地标记非活跃，取消并关闭 transport，
         * 清空 pending_，std::move 取出 ducts_ 后逐一 close。
         * 多次调用无副作用。
         * @note 方法定义在 core.cpp 中
         */
        virtual void close();

        /**
         * @brief 设置流量统计状态和归属协议
         * @param t per-worker 流量统计指针
         * @param p 外层协议类型（trojan/vless），mux 子流流量归属到外层协议
         */
        void set_traffic(stats::traffic::traffic_state *t, protocol::protocol_type p) noexcept
        {
            traffic_ = t;
            proto_ = p;
        }

        /**
         * @brief 设置会话日志前缀
         * @param p 调用方的 trace_context shared_ptr
         * @details mux craft 的 detached 协程通过 shared_ptr 捕获 prefix_，
         * prefix_ 用 shared_ptr 管理防悬垂。prefix_ 用 shared_ptr
         * 管理，prefix_restore_handler 持有副本保活，避免 IOCP 回调时悬垂。
         */
        void set_prefix(std::shared_ptr<trace::trace_context> p) noexcept
        {
            prefix_ = std::move(p);
        }

        /**
         * @brief 累加子流（duct/parcel）上报的流量字节数
         * @param up 上行字节数
         * @param down 下行字节数
         */
        void accumulate_traffic(std::uint64_t up, std::uint64_t down) noexcept
        {
            if (up) mux_uplink_.fetch_add(up, std::memory_order_relaxed);
            if (down) mux_downlink_.fetch_add(down, std::memory_order_relaxed);
        }

        /**
         * @brief 检查会话是否活跃
         * @details 通过原子变量读取 active_ 标志，使用 acquire 内存序保证可见性
         * @return bool true 表示会话正在运行
         */
        [[nodiscard]] auto is_active() const noexcept -> bool
        {
            return active_.load(std::memory_order_acquire);
        }

        /**
         * @brief 发送数据帧到客户端
         * @param stream_id 目标流标识符
         * @param payload 要发送的数据（所有权转移，零拷贝传递）
         * @details 将 payload 编码为协议数据帧并发送。payload 通过 move 传递，
         * 不执行额外拷贝。由 duct::target_readloop 和 parcel::relay_datagram 调用。
         */
        virtual auto send_data(std::uint32_t stream_id, memory::vector<std::byte> payload) const
            -> net::awaitable<void> = 0;

        /**
         * @brief 发送 FIN 帧到客户端
         * @param stream_id 目标流标识符
         * @details 异步发送半关闭帧，不阻塞调用者。由 duct::target_readloop
         * 在 target EOF 后调用，或由 activate_stream 在连接失败时调用。
         */
        virtual void send_fin(std::uint32_t stream_id) = 0;

        /**
         * @brief 获取当前 executor
         * @return net::any_io_executor 用于 duct/parcel 协程调度
         */
        [[nodiscard]] virtual auto executor() const -> net::any_io_executor = 0;

    protected:
        /**
         * @brief 从活跃管道映射中移除指定 TCP 管道
         * @param stream_id 要移除的流标识符
         * @details 由 duct::close() 调用，子类可 override 清理协议特定资源（如 yamux 窗口）
         * @note 方法定义在 core.cpp 中
         */
        virtual void remove_duct(std::uint32_t stream_id);

        /**
         * @brief 从活跃管道映射中移除指定 UDP 管道
         * @param stream_id 要移除的流标识符
         * @details 由 parcel::close() 调用，子类可 override 清理协议特定资源（如 yamux 窗口）
         * @note 方法定义在 core.cpp 中
         */
        virtual void remove_parcel(std::uint32_t stream_id);

        /**
         * @brief 协议主循环（纯虚，由子类实现）
         * @details 实现协议特定的帧读取、解析和分发逻辑。
         * 由 start() 通过 co_spawn 启动，退出时自动 close()。
         */
        virtual auto run()
            -> net::awaitable<void> = 0;

        /**
         * @brief run 协程完成回调
         */
        void on_exception(const std::exception_ptr &ep);

        transport::shared_transmission transport_; // 底层传输连接
        outbound::proxy *outbound_{nullptr};                     // 出站代理接口（非拥有，worker 生命周期）
        const config &config_;                              // mux 配置
        memory::resource_pointer mr_;                       // PMR 内存资源
        std::atomic<bool> active_{false};                   // 会话活跃标志
        stats::traffic::traffic_state *traffic_{nullptr};   // per-worker 流量统计指针
        protocol::protocol_type proto_{protocol::protocol_type::unknown}; // 归属的外层协议类型
        std::shared_ptr<trace::trace_context> prefix_;    // 会话日志前缀（shared_ptr 管理，防 IOCP 回调悬垂）
        std::atomic<std::uint64_t> mux_uplink_{0};          // 子流累加上行字节
        std::atomic<std::uint64_t> mux_downlink_{0};        // 子流累加下行字节

        /**
         * @struct pending_entry
         * @brief 正在等待地址解析和连接的流条目
         * @details SYN 帧创建后累积后续 PSH 帧的数据。
         * 当累积数据足够时（>= 7 字节），解析 SOCKS5 格式地址并发起连接。
         * connecting 标志防止重复发起 activate_stream。
         */
        struct pending_entry
        {
            memory::vector<std::byte> buffer; // 累积的地址+数据
            bool connecting = false;          // 是否已发起连接

            explicit pending_entry(memory::resource_pointer mr) : buffer(mr) {}
        };

        memory::unordered_map<std::uint32_t, pending_entry> pending_;           // 待连接流
        memory::unordered_map<std::uint32_t, std::shared_ptr<duct>> ducts_;     // 已连接的活跃 TCP 管道
        memory::unordered_map<std::uint32_t, std::shared_ptr<parcel>> parcels_; // 活跃的 UDP 管道
    }; // class core

} // namespace psm::multiplex
