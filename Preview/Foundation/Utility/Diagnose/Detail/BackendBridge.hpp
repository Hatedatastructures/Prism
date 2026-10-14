/** @file BackendBridge.hpp
 * @brief facade 请求到唯一有界快照队列的窄边界。
 */
#pragma once
#include <Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp>

#include <utility>
namespace Preview::Diagnose::Detail
{
    class BackendBridge final
    {
    public:
        /** @brief 过滤后同步捕获输入；不格式化、不分配、不执行 sink fallback。 */
        [[nodiscard]] static auto Submit(const SubmissionRequest& Request, AsyncBackendState* State) noexcept
            -> SubmissionReceipt
        {
            if (!State || !Request.Context) { return {SubmissionStatus::Stopped, 0U}; }
            if (static_cast<std::uint8_t>(Request.Level) > static_cast<std::uint8_t>(LogLevel::Off))
            {
                return {SubmissionStatus::Failed, 0U, {Preview::Fault::Code::InvalidArgument}};
            }
            auto Epoch = Request.Context->RenderEpoch();
            if (!Epoch)
            {
                Epoch = State->ActiveEpoch_.load(std::memory_order_acquire);
            }
            if (!Epoch || Epoch->Value().Closed.load(std::memory_order_acquire))
            {
                return {SubmissionStatus::Stopped, 0U};
            }
            if (!AsyncSubmission::ShouldWrite(Epoch->Value().Settings.Logging.Level, Request.Level) &&
                Request.Kind != SubmissionKind::Audit && Request.Level != LogLevel::Critical)
            {
                return {SubmissionStatus::Filtered, 0U};
            }
            auto EpochRequest = Request;
            EpochRequest.Epoch = std::move(Epoch);
            return AsyncSubmission::Submit(*State, EpochRequest);
        }
    };
}
