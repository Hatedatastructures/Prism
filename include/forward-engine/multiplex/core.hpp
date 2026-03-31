/**
 * @file core.hpp
 * @brief 多路复用核心抽象基类
 * @details 定义 multiplex::core，提供所有多路复用协议共享的
 * 会话生命周期管理、流状态跟踪和发送串行化。协议特定的帧格式、
 * 解析和协商由子类实现（如 smux::craft）。
 *
 * @section architecture 架构
 *
 * core 管理三种流状态：
 * - **pending**: SYN 后等待地址数据（首 PSH 帧）
 * - **duct**: TCP 流双向转发
 * - **parcel**: UDP 数据报中继
 *
 * duct 和 parcel 通过 core 的虚函数接口
 * （send_data / send_fin / executor）与具体协议交互，
 * 无需感知底层帧格式。
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <span>

#include <boost/asio.hpp>

#include <forward-engine/multiplex/config.hpp>
#include <forward-engine/channel/transport/transmission.hpp>
#include <forward-engine/memory/container.hpp>

// 前向声明
namespace ngx::resolve
{
    class router;
}

namespace ngx::multiplex
{
    namespace net = boost::asio;

    class duct;
    class parcel;

    /**
     * @class core
     * @brief 多路复用核心抽象基类
     * @details 管理流生命周期和发送串行化。
     * SYN 创建 pending_entry，协议子类解析地址后连接目标，
     * 创建 duct/parcel 进行双向转发。
     * 发送操作通过 strand 串行化，确保帧不会被交错写入。
     */
    class core : public std::enable_shared_from_this<core>
    {
        friend class duct;
        friend class parcel;

    public:
        /**
         * @brief 构造 core
         * @param transport 已建立的传输层连接
         * @param router 路由器引用，用于解析地址并连接目标
         * @param cfg 多路复用配置参数
         * @param mr 内存资源，为空时使用默认资源
         */
        core(channel::transport::shared_transmission transport, resolve::router &router,
             const config &cfg, memory::resource_pointer mr = {});

        virtual ~core();

        /**
         * @brief 启动 mux 会话
         * @details 通过 co_spawn 在 transport executor 上启动 run() 协程，
         * 异常或正常退出时自动调用 close()。
         */
        void start();

        /**
         * @brief 关闭会话
         * @details 原子地标记非活跃，取消并关闭 transport，
         * 清空 pending_，std::move 取出 ducts_ 后逐一 close。
         * 幂等操作，多次调用无副作用。
         */
        void close();

        /**
         * @brief 检查会话是否活跃
         * @return true 表示会话正在运行
         */
        [[nodiscard]] bool is_active() const noexcept
        {
            return active_.load(std::memory_order_acquire);
        }

        // --- duct/parcel 通过这些虚函数发送帧 ---

        /**
         * @brief 发送数据帧到客户端
         * @param stream_id 目标流标识符
         * @param payload 要发送的数据
         * @return 协程等待对象
         */
        virtual auto send_data(std::uint32_t stream_id, std::span<const std::byte> payload) const
            -> net::awaitable<void> = 0;

        /**
         * @brief 发送 FIN 帧到客户端
         * @param stream_id 目标流标识符
         */
        virtual void send_fin(std::uint32_t stream_id) = 0;

        /**
         * @brief 获取当前 executor
         * @return executor 用于 duct/parcel 协程调度
         */
        [[nodiscard]] virtual net::any_io_executor executor() const = 0;

    protected:
        /**
         * @brief 协议主循环（纯虚，由子类实现）
         * @details 实现协议特定的帧读取、解析和分发逻辑。
         * @return 协程等待对象
         */
        virtual auto run() -> net::awaitable<void> = 0;

        /**
         * @brief 从活跃管道映射中移除指定管道
         * @param stream_id 要移除的流标识符
         */
        void remove_duct(std::uint32_t stream_id);

        /**
         * @brief 从活跃 UDP 管道映射中移除指定管道
         * @param stream_id 要移除的流标识符
         */
        void remove_parcel(std::uint32_t stream_id);

        channel::transport::shared_transmission transport_; ///< 底层传输连接
        resolve::router &router_;                           ///< 路由器引用
        const config &config_;                              ///< mux 配置
        memory::resource_pointer mr_;                       ///< PMR 内存资源
        std::atomic<bool> active_{false};                   ///< 会话活跃标志

        /**
         * @struct pending_entry
         * @brief 正在等待地址解析和连接的流条目
         * @details 累积首个 PSH 帧及后续 PSH 帧的数据。
         */
        struct pending_entry
        {
            memory::vector<std::byte> buffer; ///< 累积的地址+数据
            bool connecting = false;          ///< 是否已发起连接

            explicit pending_entry(memory::resource_pointer mr) : buffer(mr) {}
        };

        memory::unordered_map<std::uint32_t, pending_entry> pending_;           ///< 待连接流
        memory::unordered_map<std::uint32_t, std::shared_ptr<duct>> ducts_;     ///< 已连接的活跃 TCP 管道
        memory::unordered_map<std::uint32_t, std::shared_ptr<parcel>> parcels_; ///< 活跃的 UDP 管道

        net::strand<net::any_io_executor> send_strand_; ///< 发送串行化 strand
    }; // class core

} // namespace ngx::multiplex