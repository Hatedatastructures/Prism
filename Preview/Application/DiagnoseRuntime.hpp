/**
 * @file DiagnoseRuntime.hpp
 * @brief PreviewApplication 唯一 Diagnose backend owner 的私有启动桥。
 */
#pragma once

#include <Preview/Foundation/Utility/Diagnose/Detail/BackendLifecycle.hpp>
#include <Preview/Foundation/Utility/Diagnose/Facade.hpp>
#include <Preview/Foundation/Utility/Diagnose/RuntimeOptions.hpp>
#include <Preview/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Preview/Statistics/Trace.hpp>

#include <chrono>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <utility>

namespace Preview::Application
{

    struct DiagnoseRuntimeConfiguration final
    {
        Preview::Diagnose::RuntimeOptions Logging{}; ///< 文件、队列、轮转和级别设置。
        Preview::Diagnose::RenderMode Mode{Preview::Diagnose::RenderMode::CompactHuman}; ///< 单条记录的渲染模式。
        Preview::Statistics::TraceSelection TraceSelection{}; ///< HumanWithFields 模式的身份字段选择。
        std::uint32_t FlushIntervalMs{250U}; ///< 应用通过 Asio timer 投递异步 flush 请求的间隔，单位毫秒。
    };

    using DiagnoseRuntimeErrorCode = Preview::Diagnose::Detail::BackendErrorCode;
    using DiagnoseRuntimeError = Preview::Diagnose::Detail::BackendError;

    /**
     * @brief 管理应用级 Diagnose backend 和同步日志 facade 的提交目标。
     * @details 日志提交只做格式化和非阻塞入队；BeginShutdown 可在协程中调用，最终 Shutdown 会 join spdlog worker。
     * @note 最终关闭和析构必须发生在 Asio 运行循环退出之后。
     */
    class DiagnoseRuntime final
    {
    public:
        DiagnoseRuntime() = default;
        DiagnoseRuntime(const DiagnoseRuntime &) = delete;
        auto operator=(const DiagnoseRuntime &) -> DiagnoseRuntime & = delete;

        ~DiagnoseRuntime() noexcept
        {
            (void)Shutdown();
        }

        [[nodiscard]] auto Install(const DiagnoseRuntimeConfiguration &Configuration)
            -> std::expected<void, DiagnoseRuntimeError>
        {
            const auto Installed = Lifecycle_.Install(Preview::Diagnose::Detail::BackendSettings{
                Configuration.Logging,
                Configuration.Mode,
                Configuration.TraceSelection,
                Configuration.FlushIntervalMs});
            if (!Installed)
            {
                return Installed;
            }
            if (!Preview::Diagnose::Detail::InstallSubmissionBackend(
                    this, &SubmitFromFacade, Configuration.Logging.Level))
            {
                (void)Lifecycle_.Shutdown();
                return std::unexpected(DiagnoseRuntimeError{
                    DiagnoseRuntimeErrorCode::OwnerConflict,
                    Configuration.Logging.Directory.string(),
                    "another facade owner is installed in this process"});
            }
            return {};
        }

        [[nodiscard]] auto Submit(const Preview::Diagnose::LogLevel Level,
                                  const Preview::Diagnose::ContextState &Context,
                                  std::string Message) noexcept
            -> Preview::Diagnose::SubmissionReceipt
        {
            DirectCalls_.fetch_add(1U, std::memory_order_acq_rel);
            if (!Lifecycle_.IsInstalled())
            {
                ReleaseDirectCall();
                return {Preview::Diagnose::SubmissionStatus::Stopped, 0U};
            }
            Preview::Diagnose::Detail::SubmissionRequest Request{Level, &Context, std::move(Message), Preview::Diagnose::SubmissionKind::Ordinary};
            const auto Receipt = Lifecycle_.Submit(Request);
            ReleaseDirectCall();
            return Receipt;
        }

        [[nodiscard]] auto Audit(const Preview::Diagnose::ContextState &Context,
                                 std::string Message) noexcept
            -> Preview::Diagnose::SubmissionReceipt
        {
            DirectCalls_.fetch_add(1U, std::memory_order_acq_rel);
            if (!Lifecycle_.IsInstalled())
            {
                ReleaseDirectCall();
                return {Preview::Diagnose::SubmissionStatus::Stopped, 0U};
            }
            Preview::Diagnose::Detail::SubmissionRequest Request{
                Preview::Diagnose::LogLevel::Access,
                &Context,
                std::move(Message),
                Preview::Diagnose::SubmissionKind::Audit};
            const auto Receipt = Lifecycle_.Submit(Request);
            ReleaseDirectCall();
            return Receipt;
        }

        /**
         * @brief 异步请求 sink flush，不等待队列或文件写入完成。
         * @details 可从协程或 I/O 线程调用；具体 sink 操作由 spdlog worker 执行。
         */
        auto Flush() noexcept -> void
        {
            DirectCalls_.fetch_add(1U, std::memory_order_acq_rel);
            if (Lifecycle_.IsInstalled())
            {
                Lifecycle_.Flush();
            }
            ReleaseDirectCall();
        }

        /**
         * @brief 在非 Asio 控制线程等待队列 barrier 完成。
         * @param Timeout 最长等待时长。
         * @return barrier 完成且 sink flush 成功时返回 Accepted；等待超时返回 TimedOut；sink flush 失败返回 Failed。
         * @note 禁止从协程或 I/O worker 调用；运行时停机不使用此同步接口。
         */
        [[nodiscard]] auto DrainOnControlThread(const std::chrono::milliseconds Timeout) noexcept
            -> Preview::Diagnose::SubmissionReceipt
        {
            DirectCalls_.fetch_add(1U, std::memory_order_acq_rel);
            if (!Lifecycle_.IsInstalled())
            {
                ReleaseDirectCall();
                return {Preview::Diagnose::SubmissionStatus::Stopped, 0U};
            }
            const auto Receipt = Lifecycle_.DrainOnControlThread(Timeout);
            ReleaseDirectCall();
            return Receipt;
        }

        /**
         * @brief 立即关闭 facade/backend 的新提交入口。
         * @details 不等待活动调用、不排空队列、不 join worker；可在应用关闭协程中调用。
         */
        auto BeginShutdown() noexcept -> void
        {
            (void)Preview::Diagnose::Detail::DisableSubmissionBackend(this);
            Lifecycle_.BeginShutdown();
        }

        /**
         * @brief 最终关闭 backend 并等待 spdlog worker 退出。
         * @return 最终关闭完成后返回 Accepted。
         * @note 该同步操作可能等待队列写入和 worker join，只能在 Asio 运行循环退出后调用。
         */
        [[nodiscard]] auto FinalizeShutdown() noexcept
            -> Preview::Diagnose::SubmissionReceipt
        {
            BeginShutdown();
            Preview::Diagnose::Detail::RemoveSubmissionBackend(this);
            for (auto Active = DirectCalls_.load(std::memory_order_acquire); Active != 0U;
                 Active = DirectCalls_.load(std::memory_order_acquire))
            {
                DirectCalls_.wait(Active, std::memory_order_acquire);
            }
            return Lifecycle_.Shutdown();
        }

        /**
         * @brief 在非 Asio 控制线程上停止并最终关闭 backend。
         * @return 最终关闭完成后返回 Accepted。
         * @note 不能从协程或 I/O 线程调用；运行时关闭路径应分别调用 BeginShutdown 和 FinalizeShutdown。
         */
        [[nodiscard]] auto Shutdown() noexcept -> Preview::Diagnose::SubmissionReceipt
        {
            return FinalizeShutdown();
        }

        [[nodiscard]] auto IsInstalled() const noexcept -> bool
        {
            return Lifecycle_.IsInstalled();
        }

        [[nodiscard]] auto Dropped(const Preview::Diagnose::LogLevel Level) const noexcept
            -> std::uint64_t
        {
            return Lifecycle_.Dropped(Level);
        }

        [[nodiscard]] auto QueueHighWatermark() const noexcept -> std::size_t
        {
            return Lifecycle_.QueueHighWatermark();
        }

        /** @brief 返回因队列未接收而失败的终态 Audit 记录数。 */
        [[nodiscard]] auto DroppedAudits() const noexcept -> std::uint64_t
        {
            return Lifecycle_.TerminalFailures();
        }

        /** @brief 返回消息或上下文捕获失败的累计次数。 */
        [[nodiscard]] auto CaptureFailures() const noexcept -> std::uint64_t
        {
            return Lifecycle_.CaptureFailures();
        }

        /** @brief 返回 spdlog sink 错误处理器观察到的错误数。 */
        [[nodiscard]] auto SinkFailures() const noexcept -> std::uint64_t
        {
            return Lifecycle_.SinkFailures();
        }

        /** @brief 返回当前进程内 facade 格式化异常的累计次数。 */
        [[nodiscard]] auto FormatFailures() const noexcept -> std::uint64_t
        {
            return Preview::Diagnose::Detail::FormatFailures();
        }

        auto ResetQueueHighWatermark() noexcept -> void
        {
            DirectCalls_.fetch_add(1U, std::memory_order_acq_rel);
            if (Lifecycle_.IsInstalled())
            {
                Lifecycle_.ResetQueueHighWatermark();
            }
            ReleaseDirectCall();
        }

    private:
        auto ReleaseDirectCall() noexcept -> void
        {
            if (DirectCalls_.fetch_sub(1U, std::memory_order_acq_rel) == 1U)
            {
                DirectCalls_.notify_all();
            }
        }

        static auto SubmitFromFacade(
            void *Owner,
            const Preview::Diagnose::Detail::SubmissionRequest &Request) noexcept
            -> Preview::Diagnose::SubmissionReceipt
        {
            auto *Runtime = static_cast<DiagnoseRuntime *>(Owner);
            if (Runtime == nullptr)
            {
                return {Preview::Diagnose::SubmissionStatus::Stopped, 0U};
            }
            return Runtime->Lifecycle_.Submit(Request);
        }

        Preview::Diagnose::Detail::BackendLifecycle Lifecycle_{};
        std::atomic<std::uint32_t> DirectCalls_{0U}; ///< 直接调用 Submit/Audit 的活动调用数。
    };

} // namespace Preview::Application
