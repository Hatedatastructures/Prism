/** @file SubmissionSlot.hpp
 * @brief facade 的单原子封止、活动预约和安装 epoch 合同。
 */
#pragma once
#include <Prism/Foundation/Utility/Diagnose/Detail/SubmissionRequest.hpp>
#include <atomic>
#include <expected>
#include <cstdint>

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
    [[nodiscard]] auto GetSubmissionSlot() noexcept -> SubmissionSlot&;
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
        SubmissionCall(SubmissionCall&& Other) noexcept;
        ~SubmissionCall();
        /** @brief 只准入当前 open epoch；已封止后没有任何新增活动预约。 */
        [[nodiscard]] static auto Try(SubmissionSlot& Slot) noexcept -> SubmissionCall;
        [[nodiscard]] auto Acquired() const noexcept -> bool { return Slot_ != nullptr; }
        [[nodiscard]] auto Closed() const noexcept -> bool { return Closed_; }
        [[nodiscard]] auto Epoch() const noexcept -> std::uint32_t { return Epoch_; }
    private:
        SubmissionSlot* Slot_{nullptr};
        std::uint32_t Epoch_{0U};
        bool Closed_{false};
    };
    /** @brief 冷安装事务；owner 与 callback 先准备，再以单次 release CAS 发布新 epoch。 */
    [[nodiscard]] auto InstallSubmissionBackend(const SubmissionBackendBinding Binding) noexcept
        -> std::expected<SubmissionRegistration, Prism::Fault::Failure>;
    /** @brief CAS 封止精确 epoch；失败说明其他原子操作前进，不等待活动调用退出。 */
    [[nodiscard]] auto DisableSubmissionBackend(const SubmissionRegistration Registration) noexcept -> bool;
    /** @brief 仅非协程控制线程等待同一原子中的实际预约归还，再移除 owner。 */
    auto RemoveSubmissionBackend(const SubmissionRegistration Registration) noexcept -> void;
    /** @brief 发布新 generation 后更新无上下文 facade 的默认级别阈值。 */
    auto UpdateSubmissionBackendLevel(const SubmissionRegistration Registration,
        LogLevel Level) noexcept -> bool;

    /** @brief 在外部 owner 创建时 pin 当前 epoch；后续日志不随 active epoch 漂移。 */
    [[nodiscard]] auto CaptureCurrentContext() noexcept -> ContextState;
    [[nodiscard]] inline auto FormatFailures() noexcept -> std::uint64_t
    {
        return GetSubmissionSlot().FormatFailures.load(std::memory_order_relaxed);
    }
    [[nodiscard]] inline auto AdmissionFailures() noexcept -> std::uint64_t
    {
        return GetSubmissionSlot().AdmissionFailures.load(std::memory_order_relaxed);
    }
}
