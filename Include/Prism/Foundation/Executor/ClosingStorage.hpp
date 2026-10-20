/**
 * @file ClosingStorage.hpp
 * @brief 进程级失败关闭实物存储；所有槽位在接入前构造。
 * @details 本类型只保存所有权，不建立任务队列。回收仍由实物的原 ExecutorReclaimer
 *          执行；无法投递的实物及其执行上下文保存至可回收或进程终态。
 */
#pragma once
#include <atomic>
#include <cstddef>
#include <memory>
#include <utility>
namespace Prism::Executor
{
    class ClosingStorage;
    /** @brief 原 executor 不可投递后的进程停止通知；接收者只能 weak 联系应用 owner。 */
    class ClosingFailureObserver
    {
    public:
        virtual ~ClosingFailureObserver() = default;
        virtual auto OnDispatchUnavailable() noexcept -> void = 0;
    };
    /** @brief 预构造的关闭实物槽位；具体 owner 实现原 executor 回收，反向联系必须为 weak。 */
    class ClosingResource
    {
    public:
        virtual ~ClosingResource() = default;
        /** @brief 仅请求原 executor 回收；失败保存实物，不执行线程外关闭。 */
        virtual auto RequestRetirement() -> void = 0;
        /** @brief 已释放载体且实际 I/O 已退栈时才为 true；没有半关闭语义。 */
        [[nodiscard]] virtual auto IsRetired() const noexcept -> bool = 0;
        [[nodiscard]] virtual auto IsDispatchUnavailable() const noexcept -> bool = 0;
    private:
        friend class ClosingStorage;
        std::atomic<std::shared_ptr<ClosingResource>> Next_;
        std::atomic<bool> Registered_{false};
    };
    class ClosingStorage final
    {
    public:
        /** @brief 唯一进程终态存储；进程结束由操作系统接管不可投递实物，禁止线程外析构。 */
        [[nodiscard]] static auto ProcessStorage() -> std::shared_ptr<ClosingStorage>;
        /** @brief 接管预构造槽位，无新分配、无容量丢弃；可在任意线程调用。 */
        auto Retain(std::shared_ptr<ClosingResource> Resource) noexcept -> void;
        /** @brief 冷路径登记进程关闭观察者；弱反向联系不保留 Application/服务/绑定。 */
        auto Observe(std::weak_ptr<ClosingFailureObserver> Observer) noexcept -> void;
        /** @brief 不可投递后进程停止新 admission，直到进程终态；已有实物绝不因容量限制丢弃。 */
        [[nodiscard]] auto IsSealed() const noexcept -> bool { return Sealed_.load(); }
        /** @brief 请求已有实物使用唯一原 reclaimer 回收；不等待、取消或启动新的调度器。 */
        auto Retry() -> void;
        /** @brief 移除已真正退休的空槽位；载体与在途 I/O 必须已由原 executor 释放。 */
        auto Collect() noexcept -> void;
        /** @brief 未收集槽位数；可包含已退休等待收集的槽，绝不漏算仍在保留的实物。 */
        [[nodiscard]] auto Pending() const noexcept -> std::size_t { return Retained_.load(); }
    private:
        /** @brief 单次遍历预约；竞争者直接返回，不阻塞或忙等 executor。 */
        struct TraversalLease final
        {
            std::atomic_flag& Flag;
            ~TraversalLease();
        };
        std::atomic_flag Traversing_ = ATOMIC_FLAG_INIT;
        std::atomic<std::size_t> Retained_{0};
        std::atomic<std::shared_ptr<ClosingResource>> Head_;
        std::atomic<std::weak_ptr<ClosingFailureObserver>> Observer_;
        std::atomic<bool> Sealed_{false};
    };
}
