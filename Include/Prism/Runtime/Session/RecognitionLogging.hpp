/** @file RecognitionLogging.hpp
 * @brief recognition、认证与目标日志的无分配观察 writer。
 */
#pragma once
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Runtime/Recognition/Recognition.hpp>
#include <Prism/Runtime/Session/LogState.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Foundation/Utility/Text/FixedText.hpp>
#include <format>
#include <memory>
#include <string_view>
#include <utility>

namespace Prism::Runtime::SessionSupport
{
    struct LogTarget final
    {
        Prism::Diagnose::LogLevel Level;
        const Prism::Diagnose::ContextState& Context;
    };
    struct RecognitionLogRequest final
    {
        Prism::Diagnose::LogLevel Level;
        std::string_view Stage;
        const Prism::Recognition::RecognizeResult& Result;
        Prism::Fault::Code FaultCode;
        std::string_view ProtocolOverride{};
    };
    struct RecognitionFailureRequest final
    {
        LogTarget Target;
        std::string_view Event;
        std::string_view Protocol;
        std::string_view FaultCode;
        std::string_view Reason;
        std::string_view Error;
        bool ErrorTruncated{false};
    };
    /** @brief 同步借用业务值，提交返回后 backend 不 pin 业务 session。 */
    class SessionLogWriter final
    {
    public:
        SessionLogWriter() = default;
        SessionLogWriter(std::shared_ptr<SessionLogState> State, Prism::Recognition::SharedProfile Profile)
            : State_(std::move(State)), Profile_(std::move(Profile)) {}
        /** @brief 普通观察失败只计入 backend，不能改写业务状态。 */
        auto WriteRecognition(const RecognitionLogRequest Request) noexcept -> void;
        auto WriteAuthenticationInfo(const Prism::Middleware::Context& Context) noexcept -> void;
        auto WriteRequestInfo(const Prism::Middleware::Context& Context) noexcept -> void;
            template <typename... Args>
            [[nodiscard]] static auto WriteLog(
                const LogTarget Target,
                const std::format_string<Args...> Format,
                Args &&...Arguments) noexcept -> Prism::Diagnose::SubmissionReceipt
            {
                const auto Level = Target.Level;
                const auto &Context = Target.Context;
                using Prism::Diagnose::LogLevel;
                switch (Level)
                {
                case LogLevel::Trace:
                    return Prism::Diagnose::Trace(Context, Format,
                                                    std::forward<Args>(Arguments)...);
                case LogLevel::Debug:
                    return Prism::Diagnose::Debug(Context, Format,
                                                     std::forward<Args>(Arguments)...);
                case LogLevel::Info:
                    return Prism::Diagnose::Info(Context, Format,
                                                   std::forward<Args>(Arguments)...);
                case LogLevel::Access:
                    return Prism::Diagnose::Access(Context, Format,
                                                     std::forward<Args>(Arguments)...);
                case LogLevel::Warn:
                    return Prism::Diagnose::Warn(Context, Format,
                                                   std::forward<Args>(Arguments)...);
                case LogLevel::Error:
                    return Prism::Diagnose::Error(Context, Format,
                                                    std::forward<Args>(Arguments)...);
                case LogLevel::Critical:
                    return Prism::Diagnose::Critical(Context, Format,
                                                       std::forward<Args>(Arguments)...);
                case LogLevel::Off:
                    return {Prism::Diagnose::SubmissionStatus::Filtered, 0U};
                }
                return {Prism::Diagnose::SubmissionStatus::Filtered, 0U};
            }

        [[nodiscard]] auto State() const noexcept -> const std::shared_ptr<SessionLogState>& { return State_; }
    private:
        [[nodiscard]] static auto FailureEvent(const std::string_view Stage, const Prism::Fault::Code Code,
            const bool Carrier) noexcept -> Prism::Text::FixedText<128U>;
        auto WriteRecognitionDetails(const Prism::Recognition::RecognizeResult& Result,
            const std::string_view Protocol) noexcept -> void;
        static auto WriteRecognitionFailure(const RecognitionFailureRequest Request) noexcept -> void;
        std::shared_ptr<SessionLogState> State_;
        Prism::Recognition::SharedProfile Profile_;
    };
}
