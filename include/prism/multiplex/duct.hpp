/**
 * @file duct.hpp
 * @brief 多路复用 TCP 流管道
 * @details multiplex::duct 是协议无关的双向 TCP 转发管道。
 * 构造时已持有已连接的 target，不存在空管道阶段。
 * 上行方向（target → mux）由独立协程循环读取并发送；
 * 下行方向（mux → target）由帧循环直接 co_await 写入，
 * 不经过额外缓冲，天然反压。
 *
 * @note 通过 core 的虚函数接口发送帧，不依赖具体协议。
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <span>

#include <boost/asio.hpp>

#include <prism/channel/transport/transmission.hpp>
#include <prism/memory/container.hpp>

namespace psm::multiplex
{
    class core;

    namespace net = boost::asio;

    /**
     * @class duct
     * @brief 多路复用 TCP 流管道
     * @details 双向转发：uplink_loop 独立协程读 target → mux；
     * on_mux_data 由帧循环 co_await 写 target。天然反压。
     * 生命周期通过 shared_from_this 保活。
     */
    class duct : public std::enable_shared_from_this<duct>
    {
    public:
        /**
         * @brief 构造 duct
         * @param stream_id 流标识符
         * @param owner 所属 core 引用
         * @param target 已连接的目标传输层
         * @param mr PMR 内存资源
         */
        duct(std::uint32_t stream_id, std::shared_ptr<core> owner,
             channel::transport::shared_transmission target, memory::resource_pointer mr);

        ~duct();

        /**
         * @brief 启动上行循环（target → mux）
         */
        void start();

        /**
         * @brief 接收 mux 数据并写入 target
         * @param data 来自 mux 数据帧的数据
         * @return 协程等待对象
         */
        auto on_mux_data(std::span<const std::byte> data) -> net::awaitable<void>;

        /**
         * @brief 处理 mux 端 FIN
         */
        void on_mux_fin();

        /**
         * @brief 关闭管道（幂等）
         */
        void close();

        /**
         * @brief 获取流标识符
         */
        [[nodiscard]] std::uint32_t stream_id() const noexcept
        {
            return id_;
        }

    private:
        /**
         * @brief 上行循环：从 target 读取数据发送到 mux
         */
        auto uplink_loop() -> net::awaitable<void>;

        std::uint32_t id_;                               // 流标识符
        std::shared_ptr<core> owner_;                    // 所属 core
        memory::resource_pointer mr_;                    // PMR 内存资源
        channel::transport::shared_transmission target_; // 目标传输层
        bool closed_ = false;                            // 关闭标志
        memory::vector<std::byte> recv_buffer_;          // 上行读缓冲
        std::atomic<bool> mux_closed_{false};            // mux 端已关闭
        std::atomic<bool> target_closed_{false};         // target 端已关闭
    }; // class duct

} // namespace psm::multiplex