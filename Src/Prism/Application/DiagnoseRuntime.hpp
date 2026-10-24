/**
 * @file DiagnoseRuntime.hpp
 * @brief PrismApplication 唯一 Diagnose backend owner 的私有启动桥。
 */
#pragma once

#include <Prism/Foundation/Utility/Diagnose/BackendLifecycle.hpp>
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Foundation/Utility/Diagnose/RuntimeOptions.hpp>
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/SubmissionSlot.hpp>
#include <Prism/Foundation/Utility/Text/TraceSelection.hpp>

#include <chrono>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace Prism::Application
{

    struct DiagnoseRuntimeConfiguration final
    {
        Prism::Diagnose::RuntimeOptions Logging{}; ///< 文件、队列、轮转和级别设置。
        Prism::Diagnose::RenderMode Mode{Prism::Diagnose::RenderMode::CompactHuman}; ///< 单条记录的渲染模式。
        Prism::Text::TraceSelection TraceSelection{}; ///< HumanWithFields 模式的身份字段选择。
        std::uint32_t FlushIntervalMs{250U}; ///< 应用通过 Asio timer 投递异步 flush 请求的间隔，单位毫秒。
        std::uint64_t GenerationId{0U}; ///< Runtime generation identity for ordered diagnose publication.
    };

    using DiagnoseRuntimeErrorCode = Prism::Diagnose::Detail::BackendErrorCode;
    using DiagnoseRuntimeError = Prism::Diagnose::Detail::BackendError;

    /**
     * @brief 管理应用级 Diagnose backend 和同步日志 facade 的提交目标。
     * @details 日志提交只复制固定快照并非阻塞入队；BeginShutdown 可在协程中调用，最终 Shutdown 会 join 日志 worker。
     * @note 最终关闭和析构必须发生在 Asio 运行循环退出之后。
     */
    class DiagnoseRuntime final
    {
        friend struct DiagnoseRuntimeTestAccess;

    public:
        DiagnoseRuntime();
        DiagnoseRuntime(const DiagnoseRuntime &) = delete;
        auto operator=(const DiagnoseRuntime &) -> DiagnoseRuntime & = delete;

        ~DiagnoseRuntime() noexcept;

        [[nodiscard]] auto Install(const DiagnoseRuntimeConfiguration &Configuration)
            -> std::expected<void, DiagnoseRuntimeError>;

        /** @brief 冷准备新 renderer/sink epoch；不重装 facade 或创建新 worker。 */
        [[nodiscard]] auto PrepareEpoch(const DiagnoseRuntimeConfiguration &Configuration)
            -> std::expected<Prism::Diagnose::RenderEpochPin, DiagnoseRuntimeError>;

        /** @brief 仅在 generation snapshot CAS 成功后选为无上下文调用的默认 epoch。 */
        auto PublishEpoch(const Prism::Diagnose::RenderEpochPin &Epoch) noexcept -> bool;

        [[nodiscard]] auto CurrentEpoch() const noexcept -> Prism::Diagnose::RenderEpochPin;

        [[nodiscard]] auto Submit(const Prism::Diagnose::LogLevel Level,
                                  const Prism::Diagnose::ContextState &Context,
                                  std::string_view Message) noexcept
            -> Prism::Diagnose::SubmissionReceipt;

        [[nodiscard]] auto Audit(const Prism::Diagnose::ContextState &Context,
                                 std::string_view Message) noexcept
            -> Prism::Diagnose::SubmissionReceipt;

        /**
         * @brief 异步请求 sink flush，不等待队列或文件写入完成。
         * @details 可从协程或 I/O 线程调用；具体 sink 操作由 Diagnose 唯一后台 worker 执行。
         */
        auto Flush() noexcept -> void;

        /**
         * @brief 在非 Asio 控制线程等待队列 barrier 完成。
         * @param Timeout 最长等待时长。
         * @return barrier 覆盖的写入与 sink flush 成功时返回 Flushed；等待超时返回 TimedOut；输出失败返回 Failed。
         * @note 禁止从协程或 I/O worker 调用；运行时停机不使用此同步接口。
         */
        [[nodiscard]] auto DrainOnControlThread(const std::chrono::milliseconds Timeout)
            -> Prism::Diagnose::SubmissionReceipt;

        /**
         * @brief 立即关闭 facade/backend 的新提交入口。
         * @details 不等待活动调用、不排空队列、不 join worker；可在应用关闭协程中调用。
         */
        auto BeginShutdown() noexcept -> void;

        /**
         * @brief 最终关闭 backend 并等待日志 worker 退出。
         * @return 所有 sink 释放且 worker 退出后返回 Closed；输出失败保留为 typed failure。
         * @note 该同步操作可能等待队列写入和 worker join，只能在 Asio 运行循环退出后调用。
         */
        [[nodiscard]] auto FinalizeShutdown() noexcept
            -> Prism::Diagnose::SubmissionReceipt;

        /**
         * @brief 在非 Asio 控制线程上停止并最终关闭 backend。
         * @return 所有 sink 释放且 worker 退出后返回 Closed；输出失败保留为 typed failure。
         * @note 不能从协程或 I/O 线程调用；运行时关闭路径应分别调用 BeginShutdown 和 FinalizeShutdown。
         */
        [[nodiscard]] auto Shutdown() noexcept -> Prism::Diagnose::SubmissionReceipt;

        [[nodiscard]] auto IsInstalled() const noexcept -> bool;

        [[nodiscard]] auto Dropped(const Prism::Diagnose::LogLevel Level) const noexcept
            -> std::uint64_t;

        [[nodiscard]] auto QueueHighWatermark() const noexcept -> std::size_t;

        /** @brief 返回因队列未接收而失败的终态 Audit 记录数。 */
        [[nodiscard]] auto DroppedAudits() const noexcept -> std::uint64_t;

        /** @brief 返回消息或上下文捕获失败的累计次数。 */
        [[nodiscard]] auto CaptureFailures() const noexcept -> std::uint64_t;

        /** @brief 返回唯一后台 worker 观察到的输出错误数。 */
        [[nodiscard]] auto SinkFailures() const noexcept -> std::uint64_t;

        /** @brief 返回当前进程内 facade 消息格式/参数快照被拒绝的累计次数。 */
        [[nodiscard]] auto FormatFailures() const noexcept -> std::uint64_t;
        /** @brief process 范围 facade 预约拒绝量，不能冒充当前 backend 队列拒绝量。 */
        [[nodiscard]] auto AdmissionFailures() const noexcept -> std::uint64_t;

        /** @brief 返回后台无法渲染而退休的已接受记录数。 */
        [[nodiscard]] auto RenderFailures() const noexcept -> std::uint64_t;
        /** @brief 返回实际 sink 写入成功的记录数。 */
        [[nodiscard]] auto Written() const noexcept -> std::uint64_t;

        auto ResetQueueHighWatermark() noexcept -> void;

    private:
        /** @brief 已进入的直接调用立即拥有计数，异常退栈也不会遗留预约。 */
        class DirectCallGuard final
        {
        public:
            explicit DirectCallGuard(DiagnoseRuntime& Owner) noexcept;
            ~DirectCallGuard();
        private:
            DiagnoseRuntime& Owner_;
        };
        auto ReleaseDirectCall() noexcept -> void;

        static auto SubmitFromFacade(
            void *Owner,
            const Prism::Diagnose::Detail::SubmissionRequest &Request) noexcept
            -> Prism::Diagnose::SubmissionReceipt;

        static auto CaptureContextFromFacade(void *Owner) noexcept
            -> Prism::Diagnose::ContextState;

        std::optional<Prism::Diagnose::Detail::SubmissionRegistration> Registration_{};
        Prism::Diagnose::Detail::BackendLifecycle Lifecycle_{};
        std::atomic<std::uint32_t> DirectCalls_{0U}; ///< 直接调用 Submit/Audit 的活动调用数。
    };

} // namespace Prism::Application
