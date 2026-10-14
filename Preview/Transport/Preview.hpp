/** @file Preview.hpp @brief 拥有一次预读前缀，真实partial I/O及关联属性沿正式前门传递。 */
#pragma once
#include <Preview/Transport/Transmission.hpp>
#include <algorithm>
#include <cstring>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Transport/Detail/ForwardActivity.hpp>
namespace Preview::Transport
{
    /** @brief 创建期间借用Data；Bytes为装配层实际池，Terminal随前缀最后字节移交。
     * @details 输入所有权：Data 只借用到 Create 返回——内部先向池实际 TryAcquire 再 memcpy，成功后前缀
     *          由回放层独占（OwnedBytes 租约）；Bytes 是装配层实际池的共享 owner，仅在 Create 内被借用，
     *          不被本层保存，已发放租约自行保活池存储；Terminal 是纯值，随前缀最后一块同次交付。
     *          输出与错误：空前缀不租块、不增加 owner；池拒绝原样返回其 Failure（ResourceUnavailable/
     *          OversizedMsg），空前缀带 Terminal 时直接 unexpected(Terminal)，均不消费 Inner。
     *          取消、半关闭、最终关闭者、executor：本结构是冷配置值，不执行取消或写半关闭，不拥有描述符，
     *          也不绑定执行域；实际语义全部由 PreviewTransport 承担。
     */
    struct PrefixInput final
    {
        std::span<const std::byte> Data;
        std::shared_ptr<Memory::BytePool> Bytes;
        Fault::Failure Terminal;
    };
    /**
     * @brief 唯一一次预读前缀的持有层：先把前缀作为真实读结果交付，再把剩余 I/O 透传给 Inner。
     * @details 输入所有权：构造共享持有 Inner 的 owner，前缀由本层独占一份 OwnedBytes 租约；读写 span 都
     *          只借用到该操作 completion，completion 恰好一次且异步交付。Release() 只在 IoIdle() 且前缀
     *          已完整消费时把 Inner 的所有权移交出去，否则返回空 shared_ptr 并保留实物。
     *          输出与错误：Create 返回 expected<SharedTransmission, Fault::Failure>，Inner/Bytes 缺失为
     *          InvalidArgument，池拒绝保留其原 Failure；读方向把前缀的末次字节与 Terminal 同次交付，
     *          因此 EOF、取消与底层原生错误四类各自保留 Code 与 Native，随后未消费的 Inner 缺失为
     *          InvalidArgument，写与半关闭一律透传 Inner。
     *          取消：OnCancel 直接转交 Inner->Cancel()，本层不额外封止；已在途的本层读由前门在原域检出
     *          取消后交付一次 Canceled，可重复取消。
     *          半关闭：StartWriteShutdown 原样转交 Inner 的 WriteShutdown，读取方向（含未消费前缀）保持可用。
     *          最终关闭者：OnClose 转交 Inner->Close() 并在成功后标记需要排空 child；本层未覆写 OwnsClose，
     *          Close 交付即行使本层关闭权，裸描述符的最终关闭者仍是 Inner 指向的叶子载体，实际退出须等待
     *          Activity()->Drain()（父前门先退，再在已转交关闭时排空 child）。
     *          executor：冷构造固定 Inner->Executor() 为唯一原域，Offset_/Preread_/Terminal_ 为非原子成员，
     *          只能在原域串行变更，要求单一执行域。
     */
    class PreviewTransport final : public Transmission
    {
    public:
        /** @brief 先租实际有界块再复制；失败不消费Inner，空前缀不增加owner或租块。 */
        [[nodiscard]] static auto Create(const SharedTransmission& Inner, PrefixInput Input)
            -> std::expected<SharedTransmission, Fault::Failure>
        {
            if (!Inner || !Input.Bytes) return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            if (Input.Data.empty())
            { if (Input.Terminal.Failed()) return std::unexpected(Input.Terminal); return Inner; }
            auto Bytes = Input.Bytes->TryAcquire(Input.Data.size());
            if (!Bytes) return std::unexpected(Bytes.error());
            std::memcpy(Bytes->WritableBytes().data(), Input.Data.data(), Input.Data.size());
            return SharedTransmission(new PreviewTransport(Inner, OwnedPrefix{std::move(*Bytes), Input.Terminal}));
        }
        [[nodiscard]] auto NextLayer() noexcept -> Transmission* override { return Inner_.get(); }
        [[nodiscard]] auto Activity() const noexcept -> std::shared_ptr<Contract::CarrierActivity> override { return Activity_; }
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission* override { return Inner_.get(); }
        [[nodiscard]] auto Inner() const noexcept -> SharedTransmission { return Inner_; }
        [[nodiscard]] auto Release() -> SharedTransmission override
        { if (!IoIdle() || Offset_ != Preread_.Size()) return {}; return std::move(Inner_); }
    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (Buffer.empty()) { Detail::PostResult(Executor(), std::move(Handler), {}); return; }
            if (Offset_ < Preread_.Size())
            {
                const auto Count = (std::min)(Buffer.size(), Preread_.Size() - Offset_);
                std::memcpy(Buffer.data(), Preread_.Bytes().data() + Offset_, Count);
                Offset_ += Count;
                IoResult Result{Count, {}};
                if (Offset_ == Preread_.Size())
                { Result.Failure = Terminal_; Terminal_ = {}; Preread_.Release(); Offset_ = 0; }
                Detail::PostResult(Executor(), std::move(Handler), Result);
                return;
            }
            if (!Inner_) { Detail::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
            Inner_->ReadSome(Buffer, std::move(Handler));
        }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (!Inner_) { Detail::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
            Inner_->WriteSome(Buffer, std::move(Handler));
        }
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!Inner_) { Detail::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
            Inner_->WriteShutdown(std::move(Handler));
        }
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (!Inner_) return {};
            const auto Result = Inner_->Close();
            if (Result) Activity_->RequireChildDrain();
            return Result;
        }
        [[nodiscard]] auto OnCancel() -> ControlResult override { if (Inner_) return Inner_->Cancel(); return {}; }
    private:
        struct OwnedPrefix final { Memory::OwnedBytes Bytes; Fault::Failure Terminal; };
        PreviewTransport(SharedTransmission Inner, OwnedPrefix Input)
            : Transmission(Inner->Executor()), Inner_(std::move(Inner)), Preread_(std::move(Input.Bytes)), Terminal_(Input.Terminal),
              Activity_(std::make_shared<Detail::ForwardActivity>(Transmission::Activity(), Inner_->Activity())) {}
        SharedTransmission Inner_;
        Memory::OwnedBytes Preread_;
        std::size_t Offset_{0};
        Fault::Failure Terminal_;
        std::shared_ptr<Detail::ForwardActivity> Activity_;
    };
}
