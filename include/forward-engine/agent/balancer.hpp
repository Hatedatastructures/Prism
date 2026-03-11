/**
 * @file distribute.hpp
 * @brief 接入分流策略器
 * @details 提供监听线程到工作线程的无锁分流能力，核心目标是：
 * - 粘性分配：默认按亲和哈希落到固定 `worker`，提升会话与连接局部性；
 * - 过载兜底：当主目标超载时，采用 two-choices 进行降载重选；
 * - 防抖控制：通过双阈值滞回减少频繁切换；
 * - 全局背压：所有 `worker` 高压时向监听层输出背压信号。
 *
 * 该模块只做“选择”与“投递”，不持有业务会话状态。
 */
#pragma once

#include <cstddef>
#include <functional>
#include <forward-engine/memory/container.hpp>
#include <boost/asio.hpp>

namespace ngx::agent
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    /**
     * @struct worker_load_snapshot
     * @brief `worker` 负载快照
     * @details 用于分流决策的轻量只读快照。
     */
    struct worker_load_snapshot
    {
        std::uint32_t active_sessions{0};   ///< 活跃会话数
        std::uint32_t pending_handoffs{0};  ///< 等待投递处理的 socket 数
        std::uint64_t event_loop_lag_us{0}; ///< 事件循环延迟（微秒）
    };

    /**
     * @struct distribute_config
     * @brief 分流策略参数
     * @details 所有阈值均面向运行时调优，默认值偏向稳态吞吐。
     */
    struct distribute_config
    {
        double enter_overload{0.90};                ///< 进入超载阈值
        double exit_overload{0.80};                 ///< 退出超载阈值
        double global_backpressure_threshold{0.95}; ///< 全局背压阈值
        double weight_session{0.60};                ///< 会话负载权重
        double weight_pending{0.10};                ///< 投递队列权重
        double weight_lag{0.30};                    ///< 事件循环延迟权重
        std::uint32_t session_capacity{1024};       ///< 会话容量基准
        std::uint32_t pending_capacity{256};        ///< 投递容量基准
        std::uint64_t lag_capacity_us{5000};        ///< 延迟容量基准（微秒）
    };

    /**
     * @class balancer
     * @brief 无锁接入分流器
     * @details
     * - 输入：亲和键 + `worker` 快照；
     * - 输出：目标 `worker` 索引、是否触发溢出、是否建议背压；
     * - 执行模型：由监听线程单线程调用，不需要互斥锁。
     */
    class balancer
    {
    public:
        /**
         * @struct worker_binding
         * @brief `worker` 绑定描述
         * @details 包含一个投递函数和一个快照函数。
         */
        struct worker_binding
        {
            std::function<void(tcp::socket)> dispatch;      ///< 将 socket 投递到目标 `worker`
            std::function<worker_load_snapshot()> snapshot; ///< 获取目标 `worker` 当前负载快照
        };

        /**
         * @struct select_result
         * @brief 分流选择结果
         */
        struct select_result
        {
            std::size_t worker_index{0}; ///< 目标 `worker` 索引
            bool overflowed{false};      ///< 是否发生超载重选
            bool backpressure{false};    ///< 是否建议监听层触发背压
        };

        /**
         * @brief 构造分流器
         * @param bindings `worker` 绑定集合
         * @param config 分流策略参数
         * @param mr 内存资源
         */
        explicit balancer(memory::vector<worker_binding> bindings, const distribute_config &config = {},
                            memory::resource_pointer mr = memory::current_resource());

        /**
         * @brief 基于亲和键选择目标 `worker`
         * @param affinity_value 亲和值（通常由远端地址/端口混合得到）
         * @return `select_result` 选择结果
         */
        [[nodiscard]] auto select(std::uint64_t affinity_value) noexcept 
            -> select_result;

        /**
         * @brief 将 socket 投递到目标 `worker`
         * @param worker_index 目标索引
         * @param socket 已建立连接
         */
        void dispatch(std::size_t worker_index, tcp::socket socket) const;

        /**
         * @brief 获取可用 `worker` 数量
         * @return `std::size_t` 绑定数量
         */
        [[nodiscard]] auto size() const noexcept -> std::size_t;

    private:
        /**
         * @brief 哈希混洗函数
         * @param value 输入值
         * @return `std::uint64_t` 混洗后哈希
         */
        [[nodiscard]] static auto mix_hash(std::uint64_t value) noexcept -> std::uint64_t;

        /**
         * @brief 计算综合负载分数
         * @param snapshot `worker` 负载快照
         * @return `double` 归一化分数
         */
        [[nodiscard]] auto score(const worker_load_snapshot &snapshot) const noexcept -> double;

        /**
         * @brief 刷新单个 `worker` 的滞回状态
         * @param worker_index 目标索引
         * @param load_score 当前负载分数
         */
        void refresh_state(std::size_t worker_index, double load_score) noexcept;

        memory::vector<worker_binding> bindings_;     ///< `worker` 绑定集合
        memory::vector<std::uint8_t> overload_state_; ///< 超载状态位（0 正常 / 1 超载）
        distribute_config config_;                    ///< 分流参数
        memory::resource_pointer mr_;                 ///< 内存资源
    };
}
