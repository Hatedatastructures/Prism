/**
 * @file WorkerBridge.hpp
 * @brief Preview 到 production worker/metrics 的隔离桥接契约
 * @details 本头文件只定义类型擦除后的最小接口，不包含 production 头文件，
 *          因而普通 Preview target 不会反向链接 PrismStaticLibrary 或
 *          TestSupport。production TU 通过 ProductionAccess 持有真实类型，
 *          并把 worker::alive/stop 与 worker::load_snapshot 适配到回调。
 *
 * Task A 接口要求：worker 提供 alive() const noexcept -> bool 与 stop() -> void；
 * metrics 提供 snapshot()，结果包含 active_sessions、pending_handoffs、lag_us、
 * active_tasks、spawned_total、cancelled_total 与 alive 字段。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <utility>

namespace psm::resource
{

    struct worker;

} // namespace psm::resource

namespace psm::runtime::worker
{

    class worker;

} // namespace psm::runtime::worker

namespace psm::preview
{

    /**
     * @struct WorkerMetricsSnapshot
     * @brief Preview 可消费的 worker 负载值语义快照
     */
    struct WorkerMetricsSnapshot
    {
        std::uint32_t ActiveSessions{0};
        std::uint32_t PendingHandoffs{0};
        std::uint64_t LagUs{0};
        std::size_t ActiveTasks{0};
        std::size_t SpawnedTotal{0};
        std::size_t CancelledTotal{0};
        bool Alive{false};
    };

    /**
     * @class WorkerBridge
     * @brief 拥有 production worker 和 metrics 的 Preview 适配对象
     * @details FromProduction 通过 shared_ptr 捕获 owner；返回值脱离调用方
     *          局部变量后仍能读取 worker 与 metrics，不暴露 production 类型。
     */
    class WorkerBridge final
    {
    public:
        using AliveFn = std::function<bool()>;
        using StopFn = std::function<void()>;
        using MetricsFn = std::function<WorkerMetricsSnapshot()>;

        /**
         * @struct ProductionAccess
         * @brief 真实 production worker/launcher 的类型化所有权入口
         * @details 生产适配 TU 应将 psm::resource::worker 或
         *          psm::runtime::worker::worker 的公开 API 绑定到三个回调：
         *          alive/stop/load_snapshot。Preview 侧不需要链接 production。
         */
        struct ProductionAccess
        {
            std::shared_ptr<psm::resource::worker> ResourceWorker{};
            std::shared_ptr<psm::runtime::worker::worker> Launcher{};
            AliveFn Alive{};
            StopFn Stop{};
            MetricsFn Metrics{};
        };

        WorkerBridge() = default;

        /**
         * @brief 从真实 production worker/launcher 所有权构造桥接
         * @param Access 类型化 production 所有权和公开 API 适配回调
         * @return 值语义桥接对象
         */
        [[nodiscard]] static auto FromProduction(ProductionAccess Access) -> WorkerBridge
        {
            WorkerBridge Result;
            Result.WorkerOwner_ = std::move(Access.ResourceWorker);
            Result.LauncherOwner_ = std::move(Access.Launcher);
            Result.Alive_ = std::move(Access.Alive);
            Result.Stop_ = std::move(Access.Stop);
            Result.Metrics_ = std::move(Access.Metrics);
            return Result;
        }

        /**
         * @brief 从具有 Task A 最小接口的 production 类型构造桥接
         * @tparam Worker production worker 类型
         * @tparam Metrics production metrics 类型
         * @param WorkerOwner worker 共享所有权
         * @param MetricsOwner metrics 共享所有权
         * @return 值语义桥接对象
         */
        template <typename Worker, typename Metrics>
        [[nodiscard]] static auto FromProduction(std::shared_ptr<Worker> WorkerOwner,
                                                 std::shared_ptr<Metrics> MetricsOwner) -> WorkerBridge
        {
            WorkerBridge Result;
            Result.WorkerOwner_ = WorkerOwner;
            Result.MetricsOwner_ = MetricsOwner;
            Result.Alive_ = [WorkerOwner]() noexcept
            {
                return WorkerOwner && WorkerOwner->alive();
            };
            Result.Stop_ = [WorkerOwner]()
            {
                if (WorkerOwner)
                {
                    WorkerOwner->stop();
                }
            };
            Result.Metrics_ = [MetricsOwner]
            {
                WorkerMetricsSnapshot ResultSnapshot;
                if (!MetricsOwner)
                {
                    return ResultSnapshot;
                }
                const auto Snapshot = MetricsOwner->snapshot();
                ResultSnapshot.ActiveSessions = Snapshot.active_sessions;
                ResultSnapshot.PendingHandoffs = Snapshot.pending_handoffs;
                ResultSnapshot.LagUs = Snapshot.lag_us;
                ResultSnapshot.ActiveTasks = Snapshot.active_tasks;
                ResultSnapshot.SpawnedTotal = Snapshot.spawned_total;
                ResultSnapshot.CancelledTotal = Snapshot.cancelled_total;
                ResultSnapshot.Alive = Snapshot.alive;
                return ResultSnapshot;
            };
            return Result;
        }

        /**
         * @brief worker 是否存活
         */
        [[nodiscard]] auto IsAlive() const noexcept -> bool
        {
            return Alive_ && Alive_();
        }

        /**
         * @brief 请求 worker 停止
         */
        auto Stop() -> void
        {
            if (Stop_)
            {
                Stop_();
            }
        }

        /**
         * @brief 读取值语义 metrics 快照
         */
        [[nodiscard]] auto Metrics() const -> WorkerMetricsSnapshot
        {
            return Metrics_ ? Metrics_() : WorkerMetricsSnapshot{};
        }

    private:
        std::shared_ptr<void> WorkerOwner_{};
        std::shared_ptr<void> LauncherOwner_{};
        std::shared_ptr<void> MetricsOwner_{};
        AliveFn Alive_{};
        StopFn Stop_{};
        MetricsFn Metrics_{};
    };

} // namespace psm::preview
