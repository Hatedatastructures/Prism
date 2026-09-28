/**
 * @file BackendBridge.hpp
 * @brief Diagnose 值类型与唯一 backend owner 的窄边界。
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>

#include <Preview/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/AsyncBackendState.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/SubmissionRequest.hpp>
#include <Preview/Foundation/Utility/Diagnose/SubmissionReceipt.hpp>
#include <Preview/Statistics/Redaction.hpp>

namespace Preview::Diagnose::Detail
{

    /**
     * @brief 将 facade 请求捕获为拥有型记录并交给异步提交策略。
     * @details 本桥接层校验状态和过滤级别，复制消息与上下文快照；它不持有 backend 生命周期。
     */
    class BackendBridge final
    {
    public:
        /**
         * @brief 校验请求并提交拥有型记录。
         * @param Request facade 创建的请求；Context 在调用期间必须有效。
         * @param State 当前 backend 状态；空指针表示 backend 不可用。
         * @return 后端提交回执。捕获消息或上下文失败时返回 Failed。
         * @details Structured 模式在提交线程捕获时间戳；线程身份由上下文中的 Worker 字段表达，不记录操作系统线程号。
         */
        [[nodiscard]] static auto Submit(const SubmissionRequest &Request, AsyncBackendState *State) noexcept
            -> SubmissionReceipt
        {
            if (State == nullptr || Request.Context == nullptr ||
                !State->Accepting_.load(std::memory_order_acquire))
            {
                return {SubmissionStatus::Stopped, 0U};
            }
            if (!AsyncSubmission::ShouldWrite(State->Settings_.Logging.Level, Request.Level) &&
                Request.Kind != SubmissionKind::Audit && Request.Level != LogLevel::Critical)
            {
                return {SubmissionStatus::Filtered, 0U};
            }

            try
            {
                SubmissionRecord Record;
                Record.Level = Request.Level;
                if (State->Settings_.Mode == RenderMode::Structured)
                {
                    Record.TimestampMilliseconds =
                        static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                       std::chrono::system_clock::now().time_since_epoch())
                                                       .count());
                }
                Record.Message = Preview::Statistics::RedactSensitiveText(Request.Message);
                Record.Context = ContextDecoder::Capture(*Request.Context, State->Settings_.Mode,
                                                         State->Settings_.TraceSelection);
                return AsyncSubmission::Submit(*State, std::move(Record), Request.Kind);
            }
            catch (...)
            {
                State->CaptureFailures_.fetch_add(1U, std::memory_order_relaxed);
                return {SubmissionStatus::Failed, 0U};
            }
        }
    };

} // namespace Preview::Diagnose::Detail
