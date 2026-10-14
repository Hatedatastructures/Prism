/** @file TrackedCompletion.hpp @brief 实际完成持有槽，最后回调退出后才允许原域退休。 */
#pragma once
#include <Preview/Transport/Detail/IoActivity.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>
#include <atomic>
namespace Preview::Transport::Detail
{
    /**
     * @brief 把 IoActivity 的操作预约与用户 completion 绑成恰好消费一次的转交体。
     * @details 输入所有权：Operation_（:46）独占 IoActivity::Operation 预约（move-only，
     *          IoActivity.hpp:100-:102），Handler_（:47）拥有用户 completion；移动构造（:36-:37）
     *          一并转移 Returned_（:48），预约随对象移动，既不复制也不悬空。
     *          输出与错误：operator()（:49-:59）先用原子 exchange 抢占唯一完成权，再以 RAII
     *          guard 调用 Operation_.Returned()，最后把 IoResult 原样转交，不折叠错误；用户 handler
     *          抛异常时预约仍由 guard 归还。
     *          取消：executor/allocator/cancellation slot 三个关联属性一律委托 Handler_（:39-:42），
     *          包装不吞掉用户取消；取消后的 operation_aborted 经 NativeCompletion
     *          经 NativeCompletion 映射为 Canceled 并与真实字节数同次交付。
     *          半关闭：本类型不触及任何传输方向，写半关闭属 WriteDriver::WriteShutdown 与 leaf 载体。
     *          最终关闭者：不关闭任何资源，只在 Operation 析构（IoActivity.hpp:104-:109）归还一次
     *          槽预约；未被调用即析构时，handler 连同其 buffer/frame 的拥有权被存进该槽的 Abandoned
     *          （:38、IoActivity.hpp:45、:113-:114），而槽归还（IoActivity.hpp:90-:91）并不清空它。
     * @note 重复 ABI 回调由 Returned_.exchange 丢弃；未调用即析构仍把 handler 留在预建槽，
     *       由 IoActivity 的阻断语义保留真实 owner。该原子门只防重复交付，不替代 Asio 的
     *       cancellation/close 语义；运行期退栈仍需 Activity()->Drain() 验收。
     */
    class TrackedCompletion final
    {
    public:
        using executor_type = boost::asio::associated_executor_t<IoCompletion>;
        using allocator_type = boost::asio::associated_allocator_t<IoCompletion>;
        using cancellation_slot_type = boost::asio::associated_cancellation_slot_t<IoCompletion>;
        TrackedCompletion(IoActivity::Operation Operation, IoCompletion Handler)
            : Operation_(std::move(Operation)), Handler_(std::move(Handler)) {}
        TrackedCompletion(TrackedCompletion&& Other) noexcept
            : Operation_(std::move(Other.Operation_)), Handler_(std::move(Other.Handler_)),
              Returned_(Other.Returned_.load(std::memory_order_acquire)) {}
        ~TrackedCompletion()
        {
            if (!Returned_.load(std::memory_order_acquire) && Handler_)
                Operation_.RetainHandler(std::move(Handler_));
        }
        [[nodiscard]] auto get_executor() const noexcept -> executor_type { return boost::asio::get_associated_executor(Handler_); }
        [[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return boost::asio::get_associated_allocator(Handler_); }
        [[nodiscard]] auto get_cancellation_slot() const noexcept -> cancellation_slot_type
        { return boost::asio::get_associated_cancellation_slot(Handler_); }
        auto operator()(Preview::IoResult Result) -> void
        {
            if (Returned_.exchange(true, std::memory_order_acq_rel)) return;
            struct ReturnGuard final
            {
                IoActivity::Operation& Operation;
                ~ReturnGuard() { Operation.Returned(); }
            } Guard{Operation_};
            auto Handler = std::move(Handler_);
            if (Handler) Handler(Result);
        }
    private:
        IoActivity::Operation Operation_;
        IoCompletion Handler_;
        std::atomic_bool Returned_{false};
    };
}
