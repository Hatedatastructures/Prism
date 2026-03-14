/**
 * @file balancer.hpp
 * @brief 前端代理负载均衡器
 * @details 该模块实现了基于加权评分的工作线程选择算法，支持过载检测
 * 与全局反压机制。负载均衡器通过收集各工作线程的实时负载快照，计算
 * 综合评分后选择最优目标进行连接分发。评分公式综合考虑活跃会话数、
 * 待处理移交数和事件循环延迟三个维度，权重可配置。当所有工作线程均
 * 进入过载状态时，系统将触发全局反压，暂停接受新连接。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

#include <boost/asio.hpp>

#include <forward-engine/memory/container.hpp>

/**
 * @namespace ngx::agent::front
 * @brief 前端代理模块
 * @details 该命名空间包含前端代理的核心组件，负责监听入站连接、执行
 * 负载均衡、将连接分发给后端工作线程。主要组件包括监听器和负载均衡器，
 * 两者协作完成高性能的连接接入与分发流程。
 */
namespace ngx::agent::front
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    /**
     * @struct worker_load_snapshot
     * @brief 工作线程负载快照
     * @details 该结构体记录某一时刻工作线程的负载状态，用于负载均衡器
     * 计算评分。快照数据由工作线程定期上报，反映当前的会话负载、待处理
     * 任务队列深度以及事件循环的响应延迟。这三个指标共同决定工作线程的
     * 综合负载评分。
     */
    struct worker_load_snapshot
    {
        std::uint32_t active_sessions{0};   // 当前活跃的会话数量
        std::uint32_t pending_handoffs{0};  // 等待处理的移交任务数
        std::uint64_t event_loop_lag_us{0}; // 事件循环延迟，单位微秒
    };

    /**
     * @struct distribute_config
     * @brief 分发策略配置参数
     * @details 该结构体定义了负载均衡器的各项阈值与权重参数。过载检测
     * 采用滞后机制避免抖动，进入过载阈值高于退出阈值。权重参数用于调整
     * 各负载指标在评分计算中的比重，三者之和应等于 1.0。容量参数用于
     * 将绝对负载值归一化为相对比例。
     */
    struct distribute_config
    {
        double enter_overload{0.90};                // 进入过载状态的负载阈值
        double exit_overload{0.80};                 // 退出过载状态的负载阈值
        double global_backpressure_threshold{0.95}; // 全局反压触发阈值
        double weight_session{0.60};                // 会话数权重
        double weight_pending{0.10};                // 待处理数权重
        double weight_lag{0.30};                    // 延迟权重
        std::uint32_t session_capacity{1024};       // 会话容量基准值
        std::uint32_t pending_capacity{256};        // 待处理容量基准值
        std::uint64_t lag_capacity_us{5000};        // 延迟容量基准值，单位微秒
    };

    /**
     * @class balancer
     * @brief 工作线程负载均衡器
     * @details 该类实现了基于加权评分的工作线程选择算法，维护所有工作
     * 线程的绑定信息与过载状态。选择算法首先根据亲和性值计算候选工作
     * 线程，然后获取其实时负载快照并计算评分，选择评分最低的健康工作
     * 线程进行分发。当检测到全局过载时，返回结果将标记反压标志，通知
     * 上层暂停接受新连接。
     * @note 该类不是线程安全的，调用方需确保在同一线程上下文中操作。
     * @warning 分发函数可能抛出异常，调用方需妥善处理。
     */
    class balancer
    {
    public:
        /**
         * @struct worker_binding
         * @brief 工作线程绑定信息
         * @details 该结构体封装了工作线程的分发函数与负载快照获取函数。
         * 分发函数负责将套接字移交至目标工作线程的事件循环，快照函数
         * 返回该工作线程当前的负载状态。两个函数均由工作线程注册时提供。
         */
        struct worker_binding
        {
            std::function<void(tcp::socket)> dispatch;      // 连接分发函数
            std::function<worker_load_snapshot()> snapshot; // 负载快照获取函数
        };

        /**
         * @struct select_result
         * @brief 工作线程选择结果
         * @details 该结构体封装了选择算法的返回信息，包含选中的工作线程
         * 索引以及系统状态标志。overflowed 标志表示选中线程已过载但仍需
         * 分发，backpressure 标志表示系统整体过载应触发反压机制。
         */
        struct select_result
        {
            std::size_t worker_index{0}; // 选中的工作线程索引
            bool overflowed{false};      // 是否已过载
            bool backpressure{false};    // 是否触发全局反压
        };

        /**
         * @brief 构造负载均衡器
         * @param bindings 工作线程绑定信息列表
         * @param config 分发策略配置参数
         * @param mr 内存资源指针，用于分配内部容器
         * @details 初始化负载均衡器，拷贝绑定信息与配置参数，初始化所有
         * 工作线程的过载状态为正常。绑定信息列表不能为空，否则后续选择
         * 操作将产生未定义行为。
         */
        explicit balancer(memory::vector<worker_binding> bindings, const distribute_config &config = {},
                          memory::resource_pointer mr = memory::current_resource());

        /**
         * @brief 选择最优工作线程
         * @param affinity_value 亲和性哈希值，用于一致性选择
         * @return 选择结果，包含工作线程索引与状态标志
         * @details 根据亲和性值计算候选工作线程集合，获取各候选线程的
         * 实时负载快照并计算评分，选择评分最低且未过载的线程。若所有
         * 线程均过载，则选择评分最低的过载线程并设置相应标志。该函数
         * 不抛出异常，可安全在热路径中调用。
         */
        [[nodiscard]] auto select(std::uint64_t affinity_value) noexcept -> select_result;

        /**
         * @brief 分发连接至指定工作线程
         * @param worker_index 目标工作线程索引
         * @param socket 待分发的套接字
         * @details 调用目标工作线程的分发函数，将套接字移交至其事件循环。
         * 索引必须有效，否则将触发断言失败。分发后套接字的所有权转移至
         * 目标工作线程，调用方不应再访问该套接字。
         */
        void dispatch(std::size_t worker_index, tcp::socket socket) const;

        /**
         * @brief 获取工作线程数量
         * @return 工作线程数量
         */
        [[nodiscard]] auto size() const noexcept -> std::size_t;

    private:
        /**
         * @brief 混合哈希值
         * @param value 输入哈希值
         * @return 混合后的哈希值
         * @details 使用 MurmurHash3 混合函数对输入值进行混淆，提高哈希
         * 分布的随机性，减少亲和性选择时的聚集效应。
         */
        [[nodiscard]] static auto mix_hash(std::uint64_t value) noexcept -> std::uint64_t;

        /**
         * @brief 计算负载评分
         * @param snapshot 负载快照
         * @return 综合负载评分，值越低表示负载越轻
         * @details 根据配置的权重参数，计算会话数、待处理数和延迟三个
         * 维度的加权评分。评分值在 0.0 到 1.0 之间，表示相对负载水平。
         */
        [[nodiscard]] auto score(const worker_load_snapshot &snapshot) const noexcept -> double;

        /**
         * @brief 刷新工作线程过载状态
         * @param worker_index 工作线程索引
         * @param load_score 当前负载评分
         * @details 根据负载评分与配置的阈值，更新工作线程的过载状态。
         * 采用滞后机制避免状态抖动，评分高于进入阈值时标记过载，低于
         * 退出阈值时清除过载标记。
         */
        void refresh_state(std::size_t worker_index, double load_score) noexcept;

        memory::vector<worker_binding> bindings_;     // 工作线程绑定列表
        memory::vector<std::uint8_t> overload_state_; // 过载状态标记
        distribute_config config_;                    // 分发配置参数
        memory::resource_pointer mr_;                 // 内存资源指针
    };
} // namespace ngx::agent::front
