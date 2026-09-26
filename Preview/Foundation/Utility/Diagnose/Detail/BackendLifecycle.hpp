/**
 * @file BackendLifecycle.hpp
 * @brief Preview Diagnose 异步 backend 的初始化、排空和关闭。
 */
#pragma once

#include <spdlog/async.h>
#include <spdlog/details/thread_pool.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>

#include <Preview/Foundation/Utility/Diagnose/Detail/AsyncBackendState.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/BackendBridge.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/SinkSet.hpp>

namespace Preview::Diagnose::Detail
{
    /**
     * @brief 独占管理进程级异步 backend 的初始化、停止接收和最终关闭。
     * @details 一个进程同时只允许一个实例拥有 Diagnose backend。实例持有可原子替换的状态快照，
     *          提交方可在关闭期间安全保留正在使用的状态。
     * @note 本类型不可复制；析构会 join spdlog worker，因此只能在运行时协程退出后销毁。
     */
    class BackendLifecycle final
    {
    public:
        BackendLifecycle() = default;
        BackendLifecycle(const BackendLifecycle &) = delete;
        auto operator=(const BackendLifecycle &) -> BackendLifecycle & = delete;

        /** @brief 关闭仍由本对象拥有的 backend；析构期间会等待 spdlog worker 退出。 */
        ~BackendLifecycle() noexcept
        {
            (void)Shutdown();
        }

        /**
         * @brief 校验设置并安装唯一的 spdlog 异步 backend。
         * @param Settings 日志 sink、队列、渲染模式和字段选择配置。
         * @return 安装成功返回空 expected；已有相同配置时幂等成功；配置冲突或初始化失败时返回 BackendError。
         * @details 为本模块创建独占的 spdlog thread pool，不读取或关闭进程级全局 pool。
         */
        [[nodiscard]] auto Install(BackendSettings Settings) -> std::expected<void, BackendError>
        {
            const auto Existing = State_.load(std::memory_order_acquire);
            if (Existing)
            {
                if (SameSettings(Existing->Settings_, Settings))
                {
                    return {};
                }
                return std::unexpected(
                    BackendError{BackendErrorCode::ConfigurationConflict, Settings.Logging.Directory.string(),
                                 "Diagnose backend is already installed with another configuration"});
            }

            if (const auto Invalid = Validate(Settings); Invalid)
            {
                return std::unexpected(*Invalid);
            }

            // 先占用进程级 facade owner，再创建独立 spdlog pool，避免并发安装两个 Diagnose backend。
            const BackendLifecycle *ExpectedOwner = nullptr;
            if (!OwnerSlot().compare_exchange_strong(ExpectedOwner, this, std::memory_order_acq_rel,
                                                     std::memory_order_acquire))
            {
                return std::unexpected(
                    BackendError{BackendErrorCode::OwnerConflict, Settings.Logging.Directory.string(),
                                 "another Diagnose backend owner is active in this process"});
            }

            try
            {
                auto Pool =
                    std::make_shared<spdlog::details::thread_pool>(Settings.Logging.QueueCapacity, 1U);
                auto CreatedSinks = SinkSet::Create(Settings, Pool);
                if (!CreatedSinks)
                {
                    Pool.reset();
                    ReleaseOwner();
                    return std::unexpected(CreatedSinks.error());
                }
                auto NewState = std::make_shared<AsyncBackendState>(Settings, std::move(Pool), *CreatedSinks,
                                                                    (*CreatedSinks)->Logger());
                NewState->Accepting_.store(true, std::memory_order_release);
                State_.store(std::move(NewState), std::memory_order_release);
                LastShutdown_.store(SubmissionStatus::Accepted, std::memory_order_release);
                return {};
            }
            catch (const std::exception &Error)
            {
                ReleaseOwner();
                return std::unexpected(BackendError{BackendErrorCode::WorkerStart,
                                                    Settings.Logging.Directory.string(), Error.what()});
            }
            catch (...)
            {
                ReleaseOwner();
                return std::unexpected(BackendError{BackendErrorCode::WorkerStart,
                                                    Settings.Logging.Directory.string(),
                                                    "unknown spdlog backend initialization failure"});
            }
        }

        /**
         * @brief 将 facade 请求转交给当前 backend 状态。
         * @param Request 已格式化的消息和借用上下文。
         * @return Bridge 返回的提交状态；backend 未安装或正在关闭时为 Stopped。
         */
        [[nodiscard]] auto Submit(const SubmissionRequest &Request) noexcept -> SubmissionReceipt
        {
            const auto State = SnapshotState();
            return BackendBridge::Submit(Request, State.get());
        }

        /**
         * @brief 禁止 backend 接收后续提交，但不等待当前调用或日志队列。
         * @details 可在 Asio 协程中调用；最终 worker join 必须留到运行循环退出后执行。
         */
        auto BeginShutdown() noexcept -> void
        {
            const auto State = SnapshotState();
            if (State)
            {
                State->Accepting_.store(false, std::memory_order_release);
            }
        }

        /**
         * @brief 向异步 sink 队列提交 flush 请求。
         * @details spdlog 会异步处理请求；本方法不等待 flush 完成。
         */
        auto Flush() noexcept -> void
        {
            const auto State = SnapshotState();
            if (State)
            {
                AsyncSubmission::Flush(*State);
            }
        }

        /**
         * @brief 使用队列内 barrier 在控制线程等待此前记录写入并 flush。
         * @param Timeout 最长等待时长。
         * @return barrier 完成且 sink flush 成功时返回 Accepted；等待超时返回 TimedOut；sink flush 失败返回 Failed。
         * @note 这是同步控制接口，禁止从协程或 Asio I/O worker 调用。
         */
        [[nodiscard]] auto DrainOnControlThread(const std::chrono::milliseconds Timeout) const noexcept
            -> SubmissionReceipt
        {
            const auto State = SnapshotState();
            if (!State || !State->Sinks_)
            {
                return {SubmissionStatus::Accepted, 0U};
            }
            const auto Deadline = std::chrono::steady_clock::now() + Timeout;
            const auto Drained = State->Sinks_->DrainOnControlThread(Deadline, State->EnqueueGate_);
            if (!Drained)
            {
                return {SubmissionStatus::TimedOut, 0U};
            }
            return {*Drained ? SubmissionStatus::Accepted : SubmissionStatus::Failed, 0U};
        }

        /**
         * @brief 关闭给定 backend 状态及其独占 spdlog pool。
         * @param State 要关闭的 backend 状态。
         * @return 关闭完成后返回 Accepted。
         * @details 只允许在运行循环停止后调用。提交 flush 请求后释放 pool owner，由 spdlog pool 析构排空队列并 join worker。
         */
        [[nodiscard]] static auto ShutdownState(AsyncBackendState &State) noexcept -> SubmissionReceipt
        {
            State.Accepting_.store(false, std::memory_order_release);
            if (State.Sinks_)
            {
                State.Sinks_->Shutdown();
            }
            State.Logger_.reset();
            auto Pool = State.Pool_.exchange(std::shared_ptr<spdlog::details::thread_pool>{},
                                             std::memory_order_acq_rel);
            Pool.reset();
            if (State.Sinks_ && !State.Sinks_->FlushSinksOnControlThread())
            {
                return {SubmissionStatus::Failed, 0U};
            }
            return {SubmissionStatus::Accepted, 0U};
        }

        /**
         * @brief 最终关闭 backend 并等待 spdlog worker 退出。
         * @return 关闭完成后返回 Accepted；已关闭时返回上次结果。
         * @details 只允许在 Asio 运行循环退出后调用。本函数可能等待队列处理和 worker join，不能从协程或 I/O 线程调用。
         */
        [[nodiscard]] auto Shutdown() noexcept -> SubmissionReceipt
        {
            BeginShutdown();
            // 先摘除状态，阻止后续提交；局部 shared_ptr 保证最终关闭期间状态仍然存活。
            const auto State =
                State_.exchange(std::shared_ptr<AsyncBackendState>{}, std::memory_order_acq_rel);
            if (!State)
            {
                return {LastShutdown_.load(std::memory_order_acquire), 0U};
            }
            const auto Result = ShutdownState(*State);
            LastShutdown_.store(Result.Status, std::memory_order_release);
            ReleaseOwner();
            return Result;
        }

        /**
         * @brief 判断 backend 当前是否已安装且仍接受提交。
         * @return 当前状态存在且 Accepting 标志为 true 时返回 true。
         */
        [[nodiscard]] auto IsInstalled() const noexcept -> bool
        {
            const auto State = SnapshotState();
            return State && State->Accepting_.load(std::memory_order_acquire);
        }

        /**
         * @brief 查询指定级别发生异步队列失败的次数。
         * @param Level 要查询的日志级别。
         * @return 该级别未能进入队列的记录数；包含入队门闩竞争和队列容量耗尽。
         */
        [[nodiscard]] auto Dropped(const LogLevel Level) const noexcept -> std::uint64_t
        {
            const auto State = SnapshotState();
            if (State)
            {
                return State->Dropped(Level);
            }
            return 0U;
        }

        /**
         * @brief 查询 backend 运行期间观察到的队列最高长度。
         * @return 自安装或上次重置以来记录的最高水位；backend 未安装时返回 0。
         */
        [[nodiscard]] auto QueueHighWatermark() const noexcept -> std::size_t
        {
            const auto State = SnapshotState();
            if (State)
            {
                return State->QueueHighWatermark();
            }
            return 0U;
        }

        /** @brief 返回因队列未接收而失败的 Audit 记录数。 */
        [[nodiscard]] auto TerminalFailures() const noexcept -> std::uint64_t
        {
            const auto State = SnapshotState();
            return State ? State->TerminalFailures_.load(std::memory_order_relaxed) : 0U;
        }

        /** @brief 返回消息或上下文捕获失败的累计次数。 */
        [[nodiscard]] auto CaptureFailures() const noexcept -> std::uint64_t
        {
            const auto State = SnapshotState();
            return State ? State->CaptureFailures_.load(std::memory_order_relaxed) : 0U;
        }

        /** @brief 返回 spdlog sink 错误处理器观察到的错误数。 */
        [[nodiscard]] auto SinkFailures() const noexcept -> std::uint64_t
        {
            const auto State = SnapshotState();
            return State && State->Sinks_ ? State->Sinks_->ErrorCount() : 0U;
        }

        /** @brief 将队列最高水位重置为调用时观察到的当前队列长度。 */
        auto ResetQueueHighWatermark() noexcept -> void
        {
            const auto State = SnapshotState();
            if (State)
            {
                State->ResetQueueHighWatermark();
            }
        }

    private:
        /**
         * @brief 取得当前 backend 状态的共享快照。
         * @return 已安装状态的 shared_ptr；未安装时为空。
         * @details shared_ptr 保证调用者在并发 Shutdown 摘除状态后仍可安全检查状态对象。
         */
        [[nodiscard]] auto SnapshotState() const noexcept -> std::shared_ptr<AsyncBackendState>
        {
            return State_.load(std::memory_order_acquire);
        }

        /**
         * @brief 检查文件名、队列、轮转和 flush 配置范围。
         * @param Settings 待检查的完整 backend 设置。
         * @return 配置无效时返回对应 BackendError；全部通过时返回空 optional。
         */
        [[nodiscard]] static auto Validate(const BackendSettings &Settings) noexcept
            -> std::optional<BackendError>
        {
            const auto &Options = Settings.Logging;
            if (Options.Directory.empty() || Options.FileName.empty() || Options.FileName == "." ||
                Options.FileName == ".." || Options.FileName.find_first_of("/\\:") != std::string::npos ||
                Options.QueueCapacity == 0U || Options.RotateBytes < 4096U ||
                Options.RotateBytes > 1024ULL * 1024ULL * 1024ULL || Options.RotateFiles == 0U ||
                Options.RotateFiles > 64U || Settings.FlushIntervalMs == 0U ||
                Settings.FlushIntervalMs > 600000U)
            {
                return BackendError{BackendErrorCode::InvalidOptions, Options.Directory.string(),
                                    "invalid Diagnose backend options"};
            }
            return {};
        }

        /**
         * @brief 比较两份 backend 设置是否完全相同。
         * @param Left 第一份设置。
         * @param Right 第二份设置。
         * @return 所有日志、渲染、trace 和 flush 选项相同时返回 true。
         */
        [[nodiscard]] static auto SameSettings(const BackendSettings &Left,
                                               const BackendSettings &Right) noexcept -> bool
        {
            const auto &A = Left.Logging;
            const auto &B = Right.Logging;
            return A.Level == B.Level && A.Directory == B.Directory && A.FileName == B.FileName &&
                   A.Console == B.Console && A.QueueCapacity == B.QueueCapacity &&
                   A.RotateBytes == B.RotateBytes && A.RotateFiles == B.RotateFiles &&
                   Left.Mode == Right.Mode &&
                   Left.TraceSelection.IncludeCorrelation == Right.TraceSelection.IncludeCorrelation &&
                   Left.TraceSelection.IncludeWorker == Right.TraceSelection.IncludeWorker &&
                   Left.TraceSelection.IncludeSession == Right.TraceSelection.IncludeSession &&
                   Left.TraceSelection.IncludeStream == Right.TraceSelection.IncludeStream &&
                   Left.FlushIntervalMs == Right.FlushIntervalMs;
        }

        /**
         * @brief 获取进程级 backend owner 原子槽位。
         * @return 保存当前 BackendLifecycle owner 的静态原子引用。
         */
        static auto OwnerSlot() noexcept -> std::atomic<const BackendLifecycle *> &
        {
            static std::atomic<const BackendLifecycle *> Owner{nullptr};
            return Owner;
        }

        /** @brief 仅当进程级 owner 仍指向 this 时释放该 owner 槽位。 */
        auto ReleaseOwner() noexcept -> void
        {
            const BackendLifecycle *ExpectedOwner = this;
            (void)OwnerSlot().compare_exchange_strong(ExpectedOwner, nullptr, std::memory_order_acq_rel,
                                                      std::memory_order_acquire);
        }

        std::atomic<std::shared_ptr<AsyncBackendState>>
            State_{}; ///< 当前可提交状态；Shutdown 通过 exchange 原子摘除。
        std::atomic<SubmissionStatus> LastShutdown_{
            SubmissionStatus::Accepted}; ///< 最近一次 Shutdown 的结果。
    };

} // namespace Preview::Diagnose::Detail
