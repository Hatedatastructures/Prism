/** @file CancellationDomain.hpp @brief 绑定单一 executor 的侵入式取消树。 */
#pragma once

#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/cancellation_signal.hpp>

#include <atomic>
#include <memory>

namespace Prism::Lifecycle
{
    namespace Net = boost::asio;

    /** @brief 在绑定 executor 收到一次取消通知；取消观察者不拥有任务或资源。 */
    class CancellationObserver
    {
    public:
        virtual ~CancellationObserver() = default;
        /** @brief signal 在绑定 executor 发出时调用；hook 只请求 task 行为，不关闭资源。 */
        virtual auto OnCancellation() -> void = 0;
    };

    /**
     * @brief 绑定单一 executor 的层级取消状态与信号 owner。
     * @details 请求状态可跨线程读取；树链接、观察者 hook 和 cancellation signal 在绑定 executor
     *          处理。子域拥有独立节点，父仅保留节点到 Detach。Cancel 只请求取消，不执行 I/O、
     *          半关闭、drain 或最终资源关闭；实际 task/resource owner 必须继续保活并等待退休。
     *          本类持有 Reclaimer，但不延长外部 io_context 的生命周期。
     */
    class CancellationDomain final
    {
        struct State;
        explicit CancellationDomain(std::shared_ptr<State> Value);

    public:
        /**
         * @brief 为 executor 建立取消域；未提供 Reclaimer 时创建绑定该 executor 的交付 owner。
         * @param Executor 取消 hook 与信号所属的原 executor。
         * @param Reclaimer 可共享的交付 owner；空值时由本域创建。
         * @note 调用者仍负责保持 executor/context 存活到所有任务与资源真实退栈。
         */
        explicit CancellationDomain(Net::any_io_executor Executor,
            std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer = {});
        ~CancellationDomain();
        CancellationDomain(const CancellationDomain&) = delete;
        auto operator=(const CancellationDomain&) -> CancellationDomain& = delete;

        /**
         * @brief 创建并接管独立子节点；链接在绑定 executor 执行，取消可先于链接发布。
         * @return 子域 shared owner；链接交付失败时子域报告 DispatchBlocked，不抛 typed Failure。
         * @note 调用方拥有返回的子域；析构只 Detach，不代替任务取消或资源关闭。
         */
        [[nodiscard]] auto CreateChild() -> std::shared_ptr<CancellationDomain>;
        /**
         * @brief 标记本节点脱离父树；父域下次在绑定 executor 遍历时移除。
         * @details 可重复，既有投递仍保活节点至原 executor 处理；不发取消信号、不执行半关闭或最终关闭。
         */
        auto Detach() noexcept -> void;
        /**
         * @brief 跨线程记录并投递取消；signal 与 observer hook 只在绑定 executor 执行。
         * @return true 表示本次已尝试投递 Emit，投递失败时仍为 true 且 IsDispatchBlocked 为 true；
         *         false 仅表示请求已记录且取消已实际发出。true 不代表 hook 已运行或资源已退休。
         * @note 取消只唤醒操作；owner 仍须处理 drain 与最终关闭。
         */
        [[nodiscard]] auto Cancel() -> bool;
        /**
         * @brief 安装任务取消观察者的 weak 引用。
         * @param Observer 非 owning 观察者；TaskSubmission 必须保活实现至取消 hook 解绑。
         * @note 替换观察者不发信号；收到取消通知的 hook 在绑定 executor 执行。
         */
        auto Observe(std::weak_ptr<CancellationObserver> Observer) noexcept -> void;
        /** @brief 只记录 Requested 状态；不投递 Emit，不发 signal，也不调用 observer hook。 */
        auto RequestCancellation() noexcept -> void;
        /** @brief 读取绑定 executor 是否已实际执行 Emit；不代表 task/resource 已退休。 */
        [[nodiscard]] auto IsCancelled() const noexcept -> bool;
        /** @brief 读取本域及父域是否记录 Requested；不表示 hook/signal 已交付。 */
        [[nodiscard]] auto IsCancellationRequested() const noexcept -> bool;
        /** @brief 读取本域或 Reclaimer 是否阻断后续交付；不能当成成功取消或资源完成。 */
        [[nodiscard]] auto IsDispatchBlocked() const noexcept -> bool;
        /** @brief 借用绑定 executor 的 cancellation slot；不得跨越该域最终退休保存。 */
        [[nodiscard]] auto Slot() noexcept -> Net::cancellation_slot;
        /** @brief 按值返回绑定 executor；调用方保持其 context 至全部 I/O/task 真实退栈。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor;
        /** @brief 借用原 executor 的交付 owner；不转移 context 或资源最终关闭责任。 */
        [[nodiscard]] auto Reclaimer() const
            -> const std::shared_ptr<Prism::Executor::ExecutorReclaimer>&;

    private:
        std::shared_ptr<State> State_;
    };
}
