/**
 * @file SubmissionSlot.cpp
 * @brief 诊断 facade backend 单槽准入与生命周期实现。
 */
#include <Prism/Foundation/Utility/Diagnose/Submission/Slot.hpp>

#include <utility>

namespace Prism::Diagnose::Detail
{
    auto GetSubmissionSlot() noexcept -> SubmissionSlot&
    {
        static constinit SubmissionSlot Slot;
        return Slot;
    }

    SubmissionCall::SubmissionCall(SubmissionCall&& Other) noexcept
        : Slot_(std::exchange(Other.Slot_, nullptr)), Epoch_(Other.Epoch_), Closed_(Other.Closed_)
    {
    }

    SubmissionCall::~SubmissionCall()
    {
        if (Slot_)
        {
            Slot_->Admission.fetch_sub(1U, std::memory_order_acq_rel);
            Slot_->Admission.notify_all();
        }
    }

    auto SubmissionCall::Try(SubmissionSlot& Slot) noexcept -> SubmissionCall
    {
        SubmissionCall Result;
        auto State = Slot.Admission.load(std::memory_order_acquire);
        for (unsigned Attempt = 0U; Attempt < 4U; ++Attempt)
        {
            const auto Epoch = SubmissionEpoch(State);
            const bool Closed = (State & SubmissionSlot::ClosedBit) != 0U;
            if (Epoch == 0U || Closed)
            {
                Result.Closed_ = true;
                return Result;
            }
            if ((State & SubmissionSlot::ActiveMask) == SubmissionSlot::ActiveMask) { return Result; }
            if (Slot.Admission.compare_exchange_strong(State, State + 1U,
                std::memory_order_acquire, std::memory_order_relaxed))
            {
                Result.Slot_ = &Slot;
                Result.Epoch_ = Epoch;
                return Result;
            }
        }
        return Result;
    }

    auto InstallSubmissionBackend(const SubmissionBackendBinding Binding) noexcept
        -> std::expected<SubmissionRegistration, Prism::Fault::Failure>
    {
        if (!Binding.Owner || !Binding.Submit || !Binding.CaptureContext)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto& Slot = GetSubmissionSlot();
        void* Empty = nullptr;
        if (!Slot.Owner.compare_exchange_strong(Empty, Binding.Owner, std::memory_order_acq_rel))
        {
            auto Call = SubmissionCall::Try(Slot);
            if (!Call.Acquired() || Slot.Owner.load(std::memory_order_acquire) != Binding.Owner ||
                Slot.Submit.load(std::memory_order_acquire) != Binding.Submit ||
                Slot.CaptureContext.load(std::memory_order_acquire) != Binding.CaptureContext ||
                Slot.Level.load(std::memory_order_acquire) != static_cast<std::uint8_t>(Binding.Level))
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            return SubmissionRegistration{Binding.Owner, Call.Epoch()};
        }
        auto State = Slot.Admission.load(std::memory_order_acquire);
        const auto Epoch = SubmissionEpoch(State);
        if ((State & SubmissionSlot::ClosedBit) != 0U && (State & SubmissionSlot::ActiveMask) == 0U &&
            Epoch < 0x7FFFFFFEU)
        {
            Slot.Level.store(static_cast<std::uint8_t>(Binding.Level), std::memory_order_relaxed);
            Slot.Submit.store(Binding.Submit, std::memory_order_relaxed);
            Slot.CaptureContext.store(Binding.CaptureContext, std::memory_order_relaxed);
            const auto Next = std::uint64_t{Epoch + 1U} << 32U;
            if (Slot.Admission.compare_exchange_strong(State, Next, std::memory_order_release,
                std::memory_order_relaxed)) { return SubmissionRegistration{Binding.Owner, Epoch + 1U}; }
        }
        Slot.Owner.store(nullptr, std::memory_order_release);
        return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
    }

    auto DisableSubmissionBackend(const SubmissionRegistration Registration) noexcept -> bool
    {
        if (!Registration.Owner || Registration.Epoch == 0U) { return false; }
        auto& Slot = GetSubmissionSlot();
        auto State = Slot.Admission.load(std::memory_order_acquire);
        while (SubmissionEpoch(State) == Registration.Epoch)
        {
            if (Slot.Owner.load(std::memory_order_acquire) != Registration.Owner) { return false; }
            if ((State & SubmissionSlot::ClosedBit) != 0U) { return true; }
            if (Slot.Admission.compare_exchange_weak(State, State | SubmissionSlot::ClosedBit,
                std::memory_order_acq_rel, std::memory_order_acquire))
            {
                Slot.Admission.notify_all();
                return true;
            }
        }
        return false;
    }

    auto RemoveSubmissionBackend(const SubmissionRegistration Registration) noexcept -> void
    {
        auto& Slot = GetSubmissionSlot();
        if (!DisableSubmissionBackend(Registration)) { return; }
        for (auto State = Slot.Admission.load(std::memory_order_acquire);
            SubmissionEpoch(State) == Registration.Epoch && (State & SubmissionSlot::ActiveMask) != 0U;
            State = Slot.Admission.load(std::memory_order_acquire))
        {
            Slot.Admission.wait(State, std::memory_order_acquire);
        }
        auto State = Slot.Admission.load(std::memory_order_acquire);
        if (SubmissionEpoch(State) != Registration.Epoch) { return; }
        const auto Retired = SubmissionSlot::ClosedBit | (std::uint64_t{Registration.Epoch + 1U} << 32U);
        if (!Slot.Admission.compare_exchange_strong(State, Retired, std::memory_order_acq_rel)) { return; }
        Slot.Owner.store(nullptr, std::memory_order_release);
    }

    auto UpdateSubmissionBackendLevel(const SubmissionRegistration Registration,
        const LogLevel Level) noexcept -> bool
    {
        if (!Registration.Owner || Registration.Epoch == 0U) { return false; }
        auto &Slot = GetSubmissionSlot();
        const auto State = Slot.Admission.load(std::memory_order_acquire);
        if ((State & SubmissionSlot::ClosedBit) != 0U ||
            SubmissionEpoch(State) != Registration.Epoch ||
            Slot.Owner.load(std::memory_order_acquire) != Registration.Owner)
        {
            return false;
        }
        Slot.Level.store(static_cast<std::uint8_t>(Level), std::memory_order_release);
        return true;
    }

    auto CaptureCurrentContext() noexcept -> ContextState
    {
        auto &Slot = GetSubmissionSlot();
        auto Call = SubmissionCall::Try(Slot);
        if (!Call.Acquired())
        {
            return ContextState::Empty();
        }
        const auto Capture = Slot.CaptureContext.load(std::memory_order_relaxed);
        auto *Owner = Slot.Owner.load(std::memory_order_relaxed);
        return Capture && Owner ? Capture(Owner) : ContextState::Empty();
    }
} // namespace Prism::Diagnose::Detail
