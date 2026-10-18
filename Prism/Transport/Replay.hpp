/** @file Replay.hpp @brief 唯一有界候选回放owner，捕获与重放共享同一个拥有缓冲。 */
#pragma once
#include <Prism/Transport/Transmission.hpp>
#include <algorithm>
#include <cstring>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Transport/Detail/ForwardActivity.hpp>
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
     *          Activity 退出。底层最终关闭权只在 Commit 或 CloseUnderlying() 之后由本层行使。
     *          缓冲区所有权：StartRead/StartWrite 的 span 同样只借用到本操作 completion；捕获内容复制到
     *          本层独占的唯一 OwnedBytes 租约，exact 组合与内层 partial 共用同一外层预约。
     *          半关闭：StartWriteShutdown 只在 OwnsClose() 为真时下发内层 WriteShutdown 并保持读取方向
     *          可用；候选未提交时以 InvalidArgument 拒绝，绝不替共享 Inner 关闭写方向。
     *          executor：所有状态（Offset_/Committed_/Wrote_/StoredFailure_/Cache_）固定在冷构造传入的
     *          Inner->Executor() 原域上变更，控制命令与 completion 也回到该域，要求单一执行域。
     * @note 未定义：候选 Close 不 Seal 底层，Close 成功后「底层何时真正关闭」在本层没有可指出的等待点，
     *       调用方须自行持有 Inner 的 Activity()->Drain()；该收口时机留待 M13 决定。
     */
    class ReplayTransmission final : public Transmission
    {
    public:
        /** @brief 只冷建候选owner；首个实际捕获才租池块，失败不消费Inner。 */
        [[nodiscard]] static auto Create(const SharedTransmission& Inner, ReplayOptions Options)
            -> std::expected<std::shared_ptr<ReplayTransmission>, Fault::Failure>
        {
            if (!Inner || !Options.Bytes || Options.MaxBytes == 0)
                return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            if (Options.MaxBytes > Options.Bytes->BlockSize())
                return std::unexpected(Fault::Failure{Fault::Code::OversizedMsg});
            return std::shared_ptr<ReplayTransmission>(new ReplayTransmission(Inner, std::move(Options)));
        }
        [[nodiscard]] auto NextLayer() noexcept -> Transmission* override { return Inner_.get(); }
        [[nodiscard]] auto Activity() const noexcept -> std::shared_ptr<Contract::CarrierActivity> override { return Activity_; }
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission* override { return Inner_.get(); }
        [[nodiscard]] auto Inner() const noexcept -> SharedTransmission { return Inner_; }
        [[nodiscard]] auto IsOpen() const -> bool override { return Inner_ && Inner_->IsOpen(); }
        /** @brief 未真实写入且未提交时才可重新读取同一捕获内容；失败不改偏移。 */
        [[nodiscard]] auto Rewind() noexcept -> ControlResult
        {
            if (!CanRewind()) return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            Offset_ = 0;
            return {};
        }
        [[nodiscard]] auto CanRewind() const noexcept -> bool { return !Committed_ && !Wrote_; }
        /** @brief 提交后保留尚未消费的捕获尾，不清空字节或热路径shrink。 */
        auto Commit() noexcept -> void
        { Committed_ = true; if (Offset_ == Cache_.Size()) { Cache_.Release(); Offset_ = 0; } }
        auto EnableWrites() noexcept -> void { WritesEnabled_ = true; }
        [[nodiscard]] auto Release() -> SharedTransmission override
        { if (!Committed_ || Offset_ != Cache_.Size()) return {}; return std::move(Inner_); }
        /** @brief 所有候选失败时显式接管最终关闭权，按同一个原域交付合同提交。 */
        [[nodiscard]] auto CloseUnderlying() -> ControlResult { Mode_ = ReplayMode::Owned; return Close(); }
    protected:
        [[nodiscard]] auto OwnsClose() const noexcept -> bool override
        { return Committed_ || Mode_ == ReplayMode::Owned; }
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (!Inner_) { Detail::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
            if (Buffer.empty()) { Detail::PostResult(Executor(), std::move(Handler), {}); return; }
            if (Offset_ < Cache_.Size())
            {
                const auto Count = (std::min)(Buffer.size(), Cache_.Size() - Offset_);
                std::memcpy(Buffer.data(), Cache_.Bytes().data() + Offset_, Count);
                Offset_ += Count;
                Detail::PostResult(Executor(), std::move(Handler), {Count, {}});
                return;
            }
            if (StoredFailure_.Failed()) { Detail::PostResult(Executor(), std::move(Handler), {0, StoredFailure_}); return; }
            if (Committed_ || Wrote_)
            { Cache_.Release(); Offset_ = 0; Inner_->ReadSome(Buffer, std::move(Handler)); return; }
            if (Cache_.Size() >= MaxBytes_)
            { Detail::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::OversizedMsg}}); return; }
            if (Cache_.Capacity() == 0)
            {
                auto Bytes = Bytes_->TryAcquire(0);
                if (!Bytes) { Detail::PostResult(Executor(), std::move(Handler), {0, Bytes.error()}); return; }
                Cache_ = std::move(*Bytes);
            }
            const auto Window = Buffer.first((std::min)(Buffer.size(), MaxBytes_ - Cache_.Size()));
            Inner_->ReadSome(Window, CaptureCompletion(this, Window, std::move(Handler)));
        }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (!Inner_ || (!Committed_ && !WritesEnabled_))
            { Detail::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
            Wrote_ = true;
            Inner_->WriteSome(Buffer, std::move(Handler));
        }
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!OwnsClose() || !Inner_) { Detail::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
            Inner_->WriteShutdown(std::move(Handler));
        }
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (!OwnsClose() || !Inner_) return {};
            const auto Result = Inner_->Close();
            if (Result) Activity_->RequireChildDrain();
            return Result;
        }
        [[nodiscard]] auto OnCancel() -> ControlResult override
        { if (OwnsClose() && Inner_) return Inner_->Cancel(); return {}; }
    private:
        ReplayTransmission(SharedTransmission Inner, ReplayOptions Options)
            : Transmission(Inner->Executor()), Inner_(std::move(Inner)), Bytes_(std::move(Options.Bytes)),
              MaxBytes_(Options.MaxBytes), Mode_(Options.Mode),
              Activity_(std::make_shared<Detail::ForwardActivity>(Transmission::Activity(), Inner_->Activity()))
        { if (Mode_ == ReplayMode::Owned) WritesEnabled_ = true; }
        class CaptureCompletion final : public Detail::AssociatedCompletion<Completion>
        {
        public:
            using executor_type = ExecutorType;
            CaptureCompletion(ReplayTransmission* Owner, std::span<std::byte> Buffer, Completion Handler)
                : AssociatedCompletion(std::move(Handler)), Owner_(Owner), Buffer_(Buffer) {}
            [[nodiscard]] auto get_executor() const noexcept -> executor_type { return Owner_->Executor(); }
            auto operator()(IoResult Result) -> void
            {
                if (Result.Bytes > Buffer_.size()) Result = {0, {Fault::Code::InvalidArgument}};
                if (Result.Bytes != 0)
                {
                    const auto Size = Owner_->Cache_.Size();
                    const auto Resized = Owner_->Cache_.Resize(Size + Result.Bytes);
                    if (!Resized) { Result.Failure = Resized.error(); Detail::PostResult(Owner_->Executor(), std::move(Handler_), Result); return; }
                    std::memcpy(Owner_->Cache_.WritableBytes().data() + Size, Buffer_.data(), Result.Bytes);
                    Owner_->Offset_ += Result.Bytes;
                }
                Owner_->StoredFailure_ = Result.Failure;
                Detail::PostResult(Owner_->Executor(), std::move(Handler_), Result);
            }
        private:
            ReplayTransmission* Owner_;
            std::span<std::byte> Buffer_;
        };
        SharedTransmission Inner_;
        std::shared_ptr<Memory::BytePool> Bytes_;
        Memory::OwnedBytes Cache_;
        std::size_t MaxBytes_, Offset_{0};
        Fault::Failure StoredFailure_;
        ReplayMode Mode_;
        bool Committed_{false}, WritesEnabled_{false}, Wrote_{false};
        std::shared_ptr<Detail::ForwardActivity> Activity_;
    };
}
