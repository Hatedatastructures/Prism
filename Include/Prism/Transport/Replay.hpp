/** @file Replay.hpp @brief 唯一有界候选回放owner，捕获与重放共享同一个拥有缓冲。 */
#pragma once
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Transport/ActivityGroupFactory.hpp>
#include <atomic>
#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <utility>
namespace Prism::Transport
{
    enum class ReplayMode { Candidate, Owned };
    /**
     * @brief 候选回放的冷配置值：捕获上限、关闭权限模式与实际字节池共享所有权。
     * @details 输入所有权：本结构按值转移到 Create（内部 std::move 后不再被调用方使用）；Bytes 必须是
     *          装配层真实共享的 BytePool 所有者，为空即 InvalidArgument，且 MaxBytes 超过池单块容量时
     *          返回 OversizedMsg——上限只约束捕获长度，不预租任何块，首个实际捕获才向该池 TryAcquire
     *          一份 OwnedBytes 并由回放层独占持有。
     *          输出与错误：本类型自身不返回结果，全部校验由 ReplayTransmission::Create 的
     *          expected<shared_ptr, Fault::Failure> 表达，取消、EOF、底层错误与容量拒绝四类各自保留。
     *          取消与半关闭：Mode 决定 Close/Cancel 是否转交 Inner，但本配置值不执行任何取消或半关闭动作。
     *          最终关闭者与 executor：Mode 为 Candidate 时最终关闭权仍属底层 owner，Owned 或 Commit 后
     *          才由本层行使；本类型不绑定 executor，实际执行域一律取自 Inner->Executor()。
     */
    struct ReplayOptions final
    {
        std::size_t MaxBytes{64U * 1024U};
        ReplayMode Mode{ReplayMode::Candidate};
        std::shared_ptr<Memory::BytePool> Bytes;
    };
    /** @brief 所有状态修改必须回到原域；候选借用Close不取得Inner关闭权，Commit后正式接管。
     * @details Candidate的Close/Cancel只完成本层局部控制命令，不关闭或全局取消共享Inner。
     *          Close 交付本层局部关闭，使本层控制 owner 在命令全部退出后可以退休，但它不 Seal、
     *          不关闭底层，调用者不得把候选 Close 的成功当作底层已经关闭，并应停止在该候选上发起
     *          新操作。Candidate 的 Cancel 保留每次真实命令预约，只在 OwnsClose 时转交
     *          Inner->Cancel()，因此候选 Cancel 成功只表示本层没有继续向底层取消，不表示底层 I/O
     *          已经取消；底层取消仍属于底层 owner。本层已发起 I/O 仍须通过自身取消 slot 及真实
     *          Activity 退出。底层最终关闭权只在 Commit 或 CloseUnderlying() 之后由本层行使；
     *          CloseUnderlying 可独立发起关闭，或在候选 Close 完成后升级，实际退栈由 Activity()->Drain 等待。
     *          缓冲区所有权：StartRead/StartWrite 的 span 同样只借用到本操作 completion；捕获内容复制到
     *          本层独占的唯一 OwnedBytes 租约，exact 组合与内层 partial 共用同一外层预约。
     *          半关闭：StartWriteShutdown 只在 OwnsClose() 为真时下发内层 WriteShutdown 并保持读取方向
     *          可用；候选未提交时以 InvalidArgument 拒绝，绝不替共享 Inner 关闭写方向。
     *          executor：所有状态（Offset_/Committed_/Wrote_/StoredFailure_/Cache_）固定在冷构造传入的
     *          Inner->Executor() 原域上变更，控制命令与 completion 也回到该域，要求单一执行域。
     * @note 候选 Close 本身不 Seal 底层；失败候选序列结束后调用 CloseUnderlying 转移最终关闭权。
     */
    class ReplayTransmission final : public Transmission
    {
    public:
        /** @brief 只冷建候选owner；首个实际捕获才租池块，失败不消费Inner。 */
        [[nodiscard]] static auto Create(const SharedTransmission& Inner, ReplayOptions Options)
            -> std::expected<std::shared_ptr<ReplayTransmission>, Fault::Failure>;
        [[nodiscard]] auto NextLayer() noexcept -> Transmission* override { return Inner_.get(); }
        [[nodiscard]] auto Activity() const noexcept -> std::shared_ptr<Contract::CarrierActivity> override { return Activity_.Activity(); }
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission* override { return Inner_.get(); }
        [[nodiscard]] auto Inner() const noexcept -> SharedTransmission { return Inner_; }
        [[nodiscard]] auto IsOpen() const -> bool override { return Inner_ && Inner_->IsOpen(); }
        /** @brief 未真实写入且未提交时才可重新读取同一捕获内容；失败不改偏移。 */
        [[nodiscard]] auto Rewind() noexcept -> ControlResult;
        [[nodiscard]] auto CanRewind() const noexcept -> bool { return !Committed_ && !Wrote_; }
        /** @brief 提交后保留尚未消费的捕获尾，不清空字节或热路径shrink。 */
        auto Commit() noexcept -> void;
        auto EnableWrites() noexcept -> void { WritesEnabled_ = true; }
        [[nodiscard]] auto Release() -> SharedTransmission override;
        /**
         * @brief 所有候选失败时在 owner executor 接管底层最终关闭权。
         * @details 可在没有先前 Close 时独立调用，也可等待候选 close 终态后升级；调用协程切换到本层固定
         *          executor，等待下层 close attempt 成功后再登记 child drain，并封止本层。同步拒绝、下层
         *          close 失败或 quarantine 保留首因且不登记 child drain。重叠调用返回 WouldBlock。
         *          返回值仅表示控制命令已交付；实际 child 退栈由 Activity()->Drain() 等待。
         *          取消不会中断最终关闭流程。
         */
        [[nodiscard]] auto CloseUnderlying() -> Net::awaitable<ControlResult>;
    protected:
        [[nodiscard]] auto OwnsClose() const noexcept -> bool override;
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override;
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override;
        auto StartWriteShutdown(Completion Handler) -> void override;
        [[nodiscard]] auto OnClose() -> ControlResult override;
        [[nodiscard]] auto OnCancel() -> ControlResult override;
    private:
        ReplayTransmission(SharedTransmission Inner, ReplayOptions Options);
        class CaptureCompletion;
        SharedTransmission Inner_;
        std::shared_ptr<Memory::BytePool> Bytes_;
        Memory::OwnedBytes Cache_;
        std::size_t MaxBytes_, Offset_{0};
        Fault::Failure StoredFailure_;
        ReplayMode Mode_;
        bool Committed_{false}, WritesEnabled_{false}, Wrote_{false};
        bool UnderlyingCloseDelivered_{false};
        std::atomic_bool ClosingUnderlying_{false};
        ForwardActivityOwner Activity_;
    };
}
