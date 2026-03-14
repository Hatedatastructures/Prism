/**
 * @file listener.hpp
 * @brief 前端代理连接监听器
 * @details 该模块实现了前端代理的连接监听组件，负责绑定监听地址、接受
 * 入站连接并分发给负载均衡器。监听器采用 Boost.Asio 协程模式实现异步
 * 接受循环，支持反压机制：当负载均衡器报告全局过载时，监听器将延迟
 * 接受新连接，避免系统过载恶化。每个新连接根据客户端端点计算亲和性
 * 值，确保同一客户端的连接倾向于分发至同一工作线程。
 */

#pragma once

#include <chrono>

#include <boost/asio.hpp>

#include <forward-engine/agent/config.hpp>
#include <forward-engine/agent/front/balancer.hpp>

namespace ngx::agent::front
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    /**
     * @class listener
     * @brief 前端代理连接监听器
     * @details 该类负责监听指定端口并接受入站 TCP 连接，将接受的连接
     * 通过负载均衡器分发给后端工作线程。监听器运行在独立的 io_context
     * 中，与工作线程隔离以避免相互影响。接受循环采用协程实现，当检测
     * 到全局反压信号时，会主动延迟接受操作，为系统恢复预留缓冲时间。
     * @note 该类不可复制，且必须在构造后调用 listen() 方法启动监听。
     * @warning 监听器的生命周期必须长于其引用的负载均衡器。
     */
    class listener
    {
    public:
        /**
         * @brief 构造监听器
         * @param cfg 代理配置，包含监听地址、端口等参数
         * @param dispatcher 负载均衡器引用，用于分发连接
         * @details 根据配置初始化 io_context 和 acceptor，设置套接字
         * 缓冲区大小与反压延迟参数。此时尚未开始监听，需调用 listen()
         * 方法启动接受循环。配置中的监听地址必须有效，否则启动时将抛出
         * 异常。
         */
        explicit listener(const agent::config &cfg, balancer &dispatcher);

        /**
         * @brief 启动监听
         * @details 打开 acceptor 并绑定至配置的监听地址，启动异步接受
         * 循环协程。该方法将阻塞运行 io_context，处理所有接受事件。通常
         * 在主线程或专用线程中调用。若绑定地址失败或端口被占用，将抛出
         * std::system_error 异常。
         * @throws std::system_error 绑定地址失败时抛出
         */
        void listen();

    private:
        /**
         * @brief 计算连接亲和性值
         * @param endpoint 客户端端点
         * @return 亲和性哈希值
         * @details 根据客户端 IP 地址和端口计算哈希值，用于负载均衡器的
         * 一致性选择。相同客户端的连接将产生相近的亲和性值，倾向于分发
         * 至同一工作线程，有利于连接亲和性与会话保持。
         */
        [[nodiscard]] static auto make_affinity(const tcp::endpoint &endpoint) noexcept -> std::uint64_t;

        /**
         * @brief 异步接受循环协程
         * @return 协程对象
         * @details 持续接受入站连接，根据客户端端点计算亲和性值，调用
         * 负载均衡器选择目标工作线程并分发连接。当负载均衡器返回反压
         * 标志时，协程将暂停指定的延迟时间后再继续接受，实现反压扩散
         * 的平滑处理。
         */
        auto accept_loop() -> net::awaitable<void>;

        net::io_context ioc_;                           // 独立的 IO 上下文
        tcp::acceptor acceptor_;                        // TCP 接受器
        balancer &dispatcher_;                          // 负载均衡器引用
        std::uint32_t buffer_size_;                     // 套接字缓冲区大小
        std::chrono::milliseconds backpressure_delay_;  // 反压延迟时间
    };
} // namespace ngx::agent::front
