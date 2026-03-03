/**
 * @file listener.hpp
 * @brief 单入口监听器
 * @details 负责：
 * - 唯一端口监听；
 * - 接收新连接；
 * - 调用 `distribute` 选择目标 `worker` 并投递。
 *
 * 该类不处理协议与会话，只做接入面调度。
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <forward-engine/agent/config.hpp>
#include <forward-engine/agent/distribute.hpp>
#include <boost/asio.hpp>

namespace ngx::agent
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    /**
     * @class listener
     * @brief 接入监听线程容器
     * @details 监听线程封闭运行，避免多线程监听同端口在 Windows 下的不稳定行为。
     */
    class listener
    {
    public:
        /**
         * @brief 构造监听器
         * @param cfg 代理配置
         * @param dispatcher 接入分流器引用
         */
        explicit listener(const config &cfg, distribute &dispatcher);

        /**
         * @brief 启动监听事件循环
         */
        void listen();

    private:
        /**
         * @brief 生成连接亲和值
         * @param endpoint 远端地址
         * @return `std::uint64_t` 亲和键
         */
        [[nodiscard]] static auto make_affinity(const tcp::endpoint &endpoint) noexcept 
            -> std::uint64_t;

        /**
         * @brief 接收循环协程
         * @return `net::awaitable<void>` 协程任务
         */
        auto accept_loop() -> net::awaitable<void>;

        net::io_context ioc_;                          ///< 监听线程 `io_context`
        tcp::acceptor acceptor_;                       ///< TCP 接收器
        distribute &dispatcher_;                       ///< 分流器引用
        std::uint32_t buffer_size_;                    ///< 连接缓冲区大小
        std::chrono::milliseconds backpressure_delay_; ///< 背压等待时长
    };
}
