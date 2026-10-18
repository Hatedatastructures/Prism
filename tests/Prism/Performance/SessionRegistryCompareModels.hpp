/**
 * @file SessionRegistryCompareModels.hpp
 * @brief A/B/C 注册表候选的统一实验接口。
 */

#pragma once

#include "SessionRegistryCompareTrace.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>

namespace Prism::Runtime::Perf
{

    inline constexpr std::size_t ConcurrentRegistryCount = 4;

    class HookGate final
    {
    public:
        HookGate() = default;
        ~HookGate() = default;

        auto Arm() -> void
        {
            std::lock_guard Lock(Mutex_);
            Armed_ = true;
            Entered_ = false;
            Released_ = false;
        }

        auto PauseAfterCheck() -> void
        {
            std::unique_lock Lock(Mutex_);
            if (!Armed_)
            {
                return;
            }
            Entered_ = true;
            Condition_.notify_all();
            Condition_.wait(Lock, [this] { return Released_; });
            Armed_ = false;
        }

        auto WaitUntilEntered() -> bool
        {
            std::unique_lock Lock(Mutex_);
            return Condition_.wait_for(
                Lock, std::chrono::seconds(5), [this] { return Entered_; });
        }

        auto Release() -> void
        {
            std::lock_guard Lock(Mutex_);
            Released_ = true;
            Condition_.notify_all();
        }

    private:
        std::mutex Mutex_;
        std::condition_variable Condition_;
        bool Armed_{false};
        bool Entered_{false};
        bool Released_{false};
    };

    struct HookPair final
    {
        std::function<void()> Error;
        std::function<void()> Metrics;
    };

    struct HookCounts final
    {
        std::uint64_t Errors{0};
        std::uint64_t Metrics{0};
    };

    struct TokenState
    {
        virtual ~TokenState() = default;
    };

    struct TokenHandle final
    {
        std::uint64_t Id{0};
        std::shared_ptr<TokenState> State;
        HookPair Hooks;
    };

    using Token = std::shared_ptr<TokenHandle>;

    class IModel
    {
    public:
        virtual ~IModel() = default;

        virtual auto Register(const SessionInfo &Info) -> Token = 0;
        virtual auto Find(std::uint64_t Id, SessionInfo &Output) -> bool = 0;
        virtual auto Size() -> std::size_t = 0;
        virtual auto Snapshot() -> SnapshotMap = 0;
        virtual auto Cancel(std::uint64_t Id) -> bool = 0;
        virtual auto Reset(const Token &Value) -> bool = 0;
        virtual auto TokenActive(const Token &Value) const -> bool = 0;
        virtual auto FailNextCompaction(std::uint64_t Id) -> void = 0;
        virtual auto FailNextHookInstallation() -> void = 0;
        virtual auto EmitFailedErrorHook() -> bool = 0;
        virtual auto SetHookGate(std::shared_ptr<HookGate> Gate) -> void = 0;
        virtual auto PendingRemovals() -> std::size_t = 0;
        virtual auto Shutdown() -> void = 0;
        virtual auto HookSnapshot() const -> HookCounts = 0;
    };

    /** @brief 并发提交固定四个唯一会话并等待全部注册完成。 */
    auto RunConcurrentRegistrations(
        IModel &Model, const std::array<SessionInfo, ConcurrentRegistryCount> &Infos)
        -> std::array<Token, ConcurrentRegistryCount>;

    /** @brief 并发消费失败 hook 槽位并返回每个调用的 exactly-once 结果。 */
    auto RunConcurrentFailedHookEmits(IModel &Model)
        -> std::array<bool, ConcurrentRegistryCount>;

} // namespace Prism::Runtime::Perf
