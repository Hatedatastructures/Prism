/** @file Replay.cpp @brief 有界候选捕获、重放、提交与关闭权限实现。 */
#include <Prism/Transport/Replay.hpp>
#include <Prism/Transport/Io/Completion.hpp>

#include <boost/asio/cancellation_state.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <cstring>
#include <expected>
#include <memory>
#include <span>
#include <utility>

namespace Prism::Transport
{
    auto ReplayTransmission::Create(const SharedTransmission& Inner, ReplayOptions Options)
        -> std::expected<std::shared_ptr<ReplayTransmission>, Fault::Failure>
    {
        if (!Inner || !Options.Bytes || Options.MaxBytes == 0)
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        if (Options.MaxBytes > Options.Bytes->BlockSize())
            return std::unexpected(Fault::Failure{Fault::Code::OversizedMsg});
        return std::shared_ptr<ReplayTransmission>(new ReplayTransmission(Inner, std::move(Options)));
    }

    auto ReplayTransmission::Rewind() noexcept -> ControlResult
    {
        if (!CanRewind()) return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        Offset_ = 0;
        return {};
    }

    auto ReplayTransmission::Commit() noexcept -> void
    {
        Committed_ = true;
        if (Offset_ == Cache_.Size()) { Cache_.Release(); Offset_ = 0; }
    }

    auto ReplayTransmission::Release() -> SharedTransmission
    {
        if (!Committed_ || Offset_ != Cache_.Size()) return {};
        return std::move(Inner_);
    }

    class ReplayTransmission::CaptureCompletion final : public Detail::AssociatedCompletion<Completion>
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
                if (!Resized) { Result.Failure = Resized.error(); Prism::Transmission::PostResult(Owner_->Executor(), std::move(Handler_), Result); return; }
                std::memcpy(Owner_->Cache_.WritableBytes().data() + Size, Buffer_.data(), Result.Bytes);
                Owner_->Offset_ += Result.Bytes;
            }
            Owner_->StoredFailure_ = Result.Failure;
            Prism::Transmission::PostResult(Owner_->Executor(), std::move(Handler_), Result);
        }
    private:
        ReplayTransmission* Owner_;
        std::span<std::byte> Buffer_;
    };

    auto ReplayTransmission::CloseUnderlying() -> Net::awaitable<ControlResult>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        auto Self = std::static_pointer_cast<ReplayTransmission>(shared_from_this());
        if (Self->ClosingUnderlying_.exchange(true, std::memory_order_acq_rel))
            co_return std::unexpected(Fault::Failure{Fault::Code::WouldBlock});
        struct EscalationGuard final
        {
            std::atomic_bool& Active;
            ~EscalationGuard() { Active.store(false, std::memory_order_release); }
        } Guard{Self->ClosingUnderlying_};
        co_await Net::dispatch(Self->Executor(), Net::use_awaitable);

        const auto ExistingClose = co_await Self->CloseReceipt()->AwaitCloseDispatch();
        if (!ExistingClose) co_return std::unexpected(ExistingClose.error());

        if (!Self->UnderlyingCloseDelivered_ && Self->Inner_)
        {
            const auto Closed = Self->Inner_->Close();
            if (!Closed) co_return Closed;
            const auto ChildClose = co_await Self->Inner_->CloseReceipt()->AwaitCloseDispatch();
            if (!ChildClose) co_return std::unexpected(ChildClose.error());
            Self->Activity_.RequireChildDrain();
            Self->UnderlyingCloseDelivered_ = true;
        }
        Self->Mode_ = ReplayMode::Owned;
        const auto Closed = Self->Transmission::Close();
        if (!Closed) co_return Closed;
        const auto CloseDispatch = co_await Self->CloseReceipt()->AwaitCloseDispatch();
        if (!CloseDispatch) co_return std::unexpected(CloseDispatch.error());
        co_return Closed;
    }

    auto ReplayTransmission::OwnsClose() const noexcept -> bool
    {
        return Committed_ || Mode_ == ReplayMode::Owned;
    }

    auto ReplayTransmission::StartRead(std::span<std::byte> Buffer, Completion Handler) -> void
    {
        if (!Inner_) { Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
        if (Buffer.empty()) { Prism::Transmission::PostResult(Executor(), std::move(Handler), {}); return; }
        if (Offset_ < Cache_.Size())
        {
            const auto Count = (std::min)(Buffer.size(), Cache_.Size() - Offset_);
            std::memcpy(Buffer.data(), Cache_.Bytes().data() + Offset_, Count);
            Offset_ += Count;
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {Count, {}});
            return;
        }
        if (StoredFailure_.Failed()) { Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, StoredFailure_}); return; }
        if (Committed_ || Wrote_)
        { Cache_.Release(); Offset_ = 0; Inner_->ReadSome(Buffer, std::move(Handler)); return; }
        if (Cache_.Size() >= MaxBytes_)
        { Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::OversizedMsg}}); return; }
        if (Cache_.Capacity() == 0)
        {
            auto Bytes = Bytes_->TryAcquire(0);
            if (!Bytes) { Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, Bytes.error()}); return; }
            Cache_ = std::move(*Bytes);
        }
        const auto Window = Buffer.first((std::min)(Buffer.size(), MaxBytes_ - Cache_.Size()));
        Inner_->ReadSome(Window, CaptureCompletion(this, Window, std::move(Handler)));
    }

    auto ReplayTransmission::StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void
    {
        if (!Inner_ || (!Committed_ && !WritesEnabled_))
        { Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
        Wrote_ = true;
        Inner_->WriteSome(Buffer, std::move(Handler));
    }

    auto ReplayTransmission::StartWriteShutdown(Completion Handler) -> void
    {
        if (!OwnsClose() || !Inner_) { Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
        Inner_->WriteShutdown(std::move(Handler));
    }

    auto ReplayTransmission::OnClose() -> ControlResult
    {
        if (!Inner_) return {};
        if (!OwnsClose())
        {
            return {};
        }
        if (UnderlyingCloseDelivered_) return {};
        const auto Result = Inner_->Close();
        if (Result)
        {
            Activity_.RequireChildDrain();
            UnderlyingCloseDelivered_ = true;
        }
        return Result;
    }

    auto ReplayTransmission::OnCancel() -> ControlResult
    {
        if (OwnsClose() && Inner_) return Inner_->Cancel();
        return {};
    }

    ReplayTransmission::ReplayTransmission(SharedTransmission Inner, ReplayOptions Options)
        : Transmission(Inner->Executor()), Inner_(std::move(Inner)), Bytes_(std::move(Options.Bytes)),
          MaxBytes_(Options.MaxBytes), Mode_(Options.Mode),
          Activity_(Transmission::Activity(), Inner_->Activity())
    {
        if (Mode_ == ReplayMode::Owned) WritesEnabled_ = true;
    }

}
