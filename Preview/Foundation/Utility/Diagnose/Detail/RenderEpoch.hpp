/**
 * @file RenderEpoch.hpp
 * @brief 固定 Diagnose 渲染设置、sink 与 generation lease 的中立值。
 */
#pragma once

#include <Preview/Foundation/Utility/Diagnose/RenderMode.hpp>
#include <Preview/Foundation/Utility/Diagnose/RuntimeOptions.hpp>
#include <Preview/Foundation/Utility/Text/TraceSelection.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

namespace Preview::Diagnose::Detail
{
    class SinkSet;

    enum class BackendErrorCode : std::uint8_t
    {
        InvalidOptions, Directory, FileOpen, LegacyArchive, ConfigurationConflict, OwnerConflict,
        WorkerStart, ResourceUnavailable,
    };

    /** @brief Diagnose 冷准备的分类错误；路径仅供本地控制面诊断。 */
    struct BackendError final
    {
        BackendErrorCode Code{BackendErrorCode::InvalidOptions};
        std::string Path{};
        std::string Message{};
    };

    /** @brief 已安装 backend 的不可变配置值。 */
    struct BackendSettings final
    {
        RuntimeOptions Logging{}; ///< 冷校验后冻结的 sink 与真实队列预算。
        RenderMode Mode{RenderMode::CompactHuman}; ///< 后台输出方式。
        Text::TraceSelection TraceSelection{}; ///< 扩展输出的身份字段选择。
        std::uint32_t FlushIntervalMs{250U}; ///< Application 周期 flush 间隔。
        std::uint64_t GenerationId{0U}; ///< 已发布配置代次，阻止并发 CAS 回执逆序覆盖 active epoch。
    };

    /** @brief 单 worker 的唤醒共享量；epoch pin 释放只投递唤醒。 */
    struct BackendWakeSignal final
    {
        std::atomic<std::uint64_t> Value{0U};

        auto Notify() noexcept -> void
        {
            Value.fetch_add(1U, std::memory_order_release);
            Value.notify_one();
        }
    };

    /** @brief 不持有 renderer/sink 的关闭观察值。 */
    struct RenderEpochCloseState final
    {
        mutable std::atomic<bool> Closed{false};
        std::atomic<bool> Failed{false};
    };

    /** @brief 隔离同一进程中多个 Diagnose backend 的 epoch 序号。 */
    struct RenderEpochIdentity final
    {
        std::uint64_t Id{0U};
        std::uint64_t OwnerId{0U};
    };

    /** @brief 单 Diagnose backend 内一代不可变设置及其 sink owner。 */
    class RenderEpoch final
    {
    public:
        RenderEpoch(const RenderEpochIdentity Identity, BackendSettings SettingsValue,
            std::shared_ptr<SinkSet> SinksValue)
            : Id(Identity.Id), OwnerId(Identity.OwnerId),
              Settings(std::move(SettingsValue)), Sinks(std::move(SinksValue))
        {
        }

        const std::uint64_t Id;
        const std::uint64_t OwnerId;
        const BackendSettings Settings;
        std::atomic<std::shared_ptr<SinkSet>> Sinks;
        const std::shared_ptr<RenderEpochCloseState> CloseState{
            std::make_shared<RenderEpochCloseState>()};
        mutable std::atomic<bool> Active{false};
        mutable std::atomic<bool> Closed{false};
    };

    /** @brief ContextState 与唯一队列槽共同持有的一代 lease。 */
    class RenderEpochPin final
    {
    public:
        RenderEpochPin(const RenderEpochPin &) = delete;
        auto operator=(const RenderEpochPin &) -> RenderEpochPin & = delete;

        ~RenderEpochPin() noexcept
        {
            Epoch_.reset();
            if (const auto Wake = Wake_.lock())
            {
                Wake->Notify();
            }
        }

        [[nodiscard]] auto Value() const noexcept -> const RenderEpoch &
        {
            return *Epoch_;
        }

        [[nodiscard]] auto CloseState() const noexcept
            -> std::shared_ptr<const RenderEpochCloseState>
        {
            return Epoch_->CloseState;
        }

    private:
        friend class BackendLifecycle;

        RenderEpochPin(std::shared_ptr<RenderEpoch> Epoch,
            const std::weak_ptr<BackendWakeSignal> Wake) noexcept
            : Epoch_(std::move(Epoch)), Wake_(Wake)
        {
        }

        std::shared_ptr<RenderEpoch> Epoch_;
        std::weak_ptr<BackendWakeSignal> Wake_;
    };
}

namespace Preview::Diagnose
{
    using RenderEpochPin = std::shared_ptr<const Detail::RenderEpochPin>;
}
