/** @file Preview.cpp @brief 预读前缀、粘滞终态与 child drain 的 owning transport 实现。 */
#include <Prism/Transport/Preview.hpp>

#include <algorithm>
#include <cstring>
#include <expected>
#include <memory>
#include <span>
#include <utility>

namespace Prism::Transport
{
    auto PreviewTransport::Create(const SharedTransmission& Inner, PrefixInput Input)
        -> std::expected<SharedTransmission, Fault::Failure>
    {
        if (!Inner || !Input.Bytes) return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        if (Input.Data.empty())
        {
            if (Input.Terminal.Failed())
            {
                return SharedTransmission(new PreviewTransport(
                    Inner, OwnedPrefix{{}, Input.Terminal}));
            }
            return Inner;
        }
        auto Bytes = Input.Bytes->TryAcquire(Input.Data.size());
        if (!Bytes) return std::unexpected(Bytes.error());
        std::memcpy(Bytes->WritableBytes().data(), Input.Data.data(), Input.Data.size());
        return SharedTransmission(new PreviewTransport(Inner, OwnedPrefix{std::move(*Bytes), Input.Terminal}));
    }

    auto PreviewTransport::Release() -> SharedTransmission
    {
        if (!IoIdle() || Offset_ != Preread_.Size() || Terminal_.Failed()) return {};
        return std::move(Inner_);
    }

    auto PreviewTransport::StartRead(std::span<std::byte> Buffer, Completion Handler) -> void
    {
        if (Buffer.empty()) { Prism::Transmission::PostResult(Executor(), std::move(Handler), {}); return; }
        if (Offset_ < Preread_.Size())
        {
            const auto Count = (std::min)(Buffer.size(), Preread_.Size() - Offset_);
            std::memcpy(Buffer.data(), Preread_.Bytes().data() + Offset_, Count);
            Offset_ += Count;
            IoResult Result{Count, {}};
            if (Offset_ == Preread_.Size())
            { Result.Failure = Terminal_; Preread_.Release(); Offset_ = 0; }
            Prism::Transmission::PostResult(Executor(), std::move(Handler), Result);
            return;
        }
        if (Terminal_.Failed())
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {0, Terminal_});
            return;
        }
        if (!Inner_) { Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
        Inner_->ReadSome(Buffer, std::move(Handler));
    }

    auto PreviewTransport::StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void
    {
        if (!Inner_) { Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
        Inner_->WriteSome(Buffer, std::move(Handler));
    }

    auto PreviewTransport::StartWriteShutdown(Completion Handler) -> void
    {
        if (!Inner_) { Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
        Inner_->WriteShutdown(std::move(Handler));
    }

    auto PreviewTransport::OnClose() -> ControlResult
    {
        if (!Inner_) return {};
        const auto Result = Inner_->Close();
        if (Result) Activity_.RequireChildDrain();
        return Result;
    }

    auto PreviewTransport::OnCancel() -> ControlResult
    {
        if (Inner_) return Inner_->Cancel();
        return {};
    }

    PreviewTransport::PreviewTransport(SharedTransmission Inner, OwnedPrefix Input)
        : Transmission(Inner->Executor()), Inner_(std::move(Inner)), Preread_(std::move(Input.Bytes)), Terminal_(Input.Terminal),
          Activity_(Transmission::Activity(), Inner_->Activity())
    {
    }
}
