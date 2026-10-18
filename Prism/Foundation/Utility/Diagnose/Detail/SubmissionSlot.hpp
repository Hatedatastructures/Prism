/** @file SubmissionSlot.hpp
 * @brief facade 的单原子封止、活动预约和安装 epoch 合同。
 */
#pragma once
#include <Prism/Foundation/Utility/Diagnose/Detail/SubmissionRequest.hpp>
#include <atomic>
#include <expected>
#include <cstdint>
#include <utility>

namespace Prism::Diagnose::Detail
{
    using SubmissionFunction = SubmissionReceipt (*)(void*, const SubmissionRequest&) noexcept;
    using CurrentContextFunction = ContextState (*)(void*) noexcept;
    /** @brief 关闭位、活动数和 epoch 是一份原子准入事实。 */
    struct SubmissionSlot final
    {
        static constexpr std::uint64_t ClosedBit = std::uint64_t{1U} << 63U;
        static constexpr std::uint64_t ActiveMask = UINT32_MAX;
        static constexpr std::uint64_t EpochMask = std::uint64_t{0x7FFFFFFFU} << 32U;
        std::atomic<std::uint64_t> Admission{ClosedBit};
        std::atomic<void*> Owner{nullptr};
        std::atomic<SubmissionFunction> Submit{nullptr};
        std::atomic<CurrentContextFunction> CaptureContext{nullptr};
        std::atomic<std::uint8_t> Level{static_cast<std::uint8_t>(LogLevel::Info)};
        std::atomic<std::uint64_t> FormatFailures{0U};
        std::atomic<std::uint64_t> AdmissionFailures{0U}; ///< process 范围的 facade 预约竞争拒绝量。
    };
    /** @brief 只标识实际安装，不转移 backend 的最终关闭责任。 */
    struct SubmissionRegistration final
    {
        void* Owner{nullptr};
        std::uint32_t Epoch{0U};
    };
    /** @brief 完整 facade backend 冷绑定；Submit 和 Context capture 属于同一 owner。 */
    struct SubmissionBackendBinding final
    {
        void *Owner{nullptr};
        SubmissionFunction Submit{nullptr};
        CurrentContextFunction CaptureContext{nullptr};
        LogLevel Level{LogLevel::Info};
    };
    [[nodiscard]] inline auto GetSubmissionSlot() noexcept -> SubmissionSlot&
    {
        static constinit SubmissionSlot Slot;
        return Slot;
    }
    [[nodiscard]] inline auto SubmissionEpoch(const std::uint64_t State) noexcept -> std::uint32_t
    {
        return static_cast<std::uint32_t>((State & SubmissionSlot::EpochMask) >> 32U);
    }
    /**
     * @brief 成功的 CAS 同时预约实际活动数与当前 epoch。
     * @details 普通提交只接受 open 状态，预约成立后才能读取 raw Owner/Submit。
     *          epoch 的冷重新发布要求同一原子中的活动数为零，不能跨 epoch 使用旧回调。
     *          请求最多尝试四次；不等待、不锁、不分配。最后归还通知控制线程。
     */
    class SubmissionCall final
    {
    public:
        SubmissionCall() = default;
        SubmissionCall(const SubmissionCall&) = delete;
        auto operator=(const SubmissionCall&) -> SubmissionCall& = delete;
        SubmissionCall(SubmissionCall&& Other) noexcept : Slot_(std::exchange(Other.Slot_, nullptr)),
            Epoch_(Other.Epoch_), Closed_(Other.Closed_) {}
        ~SubmissionCall()
        {
            if (Slot_)
            {
                Slot_->Admission.fetch_sub(1U, std::memory_order_acq_rel);
                Slot_->Admission.notify_all();
            }
        }
        /** @brief 只准入当前 open epoch；已封止后没有任何新增活动预约。 */
        [[nodiscard]] static auto Try(SubmissionSlot& Slot) noexcept
            -> SubmissionCall
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
        [[nodiscard]] auto Acquired() const noexcept -> bool { return Slot_ != nullptr; }
        [[nodiscard]] auto Closed() const noexcept -> bool { return Closed_; }
        [[nodiscard]] auto Epoch() const noexcept -> std::uint32_t { return Epoch_; }
    private:
        SubmissionSlot* Slot_{nullptr};
        std::uint32_t Epoch_{0U};
        bool Closed_{false};
    };
    /** @brief 冷安装事务；owner 与 callback 先准备，再以单次 release CAS 发布新 epoch。 */
    [[nodiscard]] inline auto InstallSubmissionBackend(const SubmissionBackendBinding Binding) noexcept
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
    /** @brief CAS 封止精确 epoch；失败说明其他原子操作前进，不等待活动调用退出。 */
    [[nodiscard]] inline auto DisableSubmissionBackend(const SubmissionRegistration Registration) noexcept -> bool
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
    /** @brief 仅非协程控制线程等待同一原子中的实际预约归还，再移除 owner。 */
    inline auto RemoveSubmissionBackend(const SubmissionRegistration Registration) noexcept -> void
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
    /** @brief 发布新 generation 后更新无上下文 facade 的默认级别阈值。 */
    inline auto UpdateSubmissionBackendLevel(const SubmissionRegistration Registration,
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

    /** @brief 在外部 owner 创建时 pin 当前 epoch；后续日志不随 active epoch 漂移。 */
    [[nodiscard]] inline auto CaptureCurrentContext() noexcept -> ContextState
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
    [[nodiscard]] inline auto FormatFailures() noexcept -> std::uint64_t
    {
        return GetSubmissionSlot().FormatFailures.load(std::memory_order_relaxed);
    }
    [[nodiscard]] inline auto AdmissionFailures() noexcept -> std::uint64_t
    {
        return GetSubmissionSlot().AdmissionFailures.load(std::memory_order_relaxed);
    }
}
