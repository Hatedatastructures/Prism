/** @file RecognitionLogging.hpp
 * @brief recognition、认证与目标日志的无分配观察 writer。
 */
#pragma once
#include <Preview/Runtime/Session/Logging.hpp>
#include <memory>
#include <string_view>
#include <utility>

namespace Preview::Runtime::SessionSupport
{
    struct LogTarget final
    {
        Preview::Diagnose::LogLevel Level;
        const Preview::Diagnose::ContextState& Context;
    };
    struct RecognitionLogRequest final
    {
        Preview::Diagnose::LogLevel Level;
        std::string_view Stage;
        const Preview::Recognition::RecognizeResult& Result;
        Preview::Fault::Code FaultCode;
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
        SessionLogWriter(std::shared_ptr<SessionLogState> State, Preview::Recognition::SharedProfile Profile)
            : State_(std::move(State)), Profile_(std::move(Profile)) {}
        /** @brief 普通观察失败只计入 backend，不能改写业务状态。 */
        auto WriteRecognition(const RecognitionLogRequest Request) noexcept -> void
        {
            if (!State_) { return; }
            const auto& Result = Request.Result;
            const bool RecognitionStage = Request.Stage == "recognition";
            auto FaultCode = Request.FaultCode;
            if (RecognitionStage && Result.FaultCode != Preview::Fault::Code::Success) { FaultCode = Result.FaultCode; }
            const bool CarrierFailure = RecognitionStage && !Result.Carrier.Carrier.empty() &&
                Preview::Fault::Failed(FaultCode) && FaultCode != Preview::Fault::Code::Canceled;
            const bool Accepted = RecognitionStage && Result.success && FaultCode == Preview::Fault::Code::Success;
            auto Stage = Request.Stage;
            if (CarrierFailure) { Stage = "CarrierCommit"; }
            State_->MarkStage(Stage);
            auto Level = Request.Level;
            if (RecognitionStage && !Accepted && FaultCode != Preview::Fault::Code::Canceled)
            {
                Level = Preview::Diagnose::LogLevel::Warn;
            }
            if (Accepted)
            {
                if (!Preview::Diagnose::IsContextEnabled(
                        State_->Trace, Preview::Diagnose::LogLevel::Debug) &&
                    !Preview::Diagnose::IsContextEnabled(
                        State_->Trace, Preview::Diagnose::LogLevel::Trace)) { return; }
            }
            else if (!Preview::Diagnose::IsContextEnabled(State_->Trace, Level)) { return; }
            auto ProtocolValue = Preview::Contract::ToStringView(Result.detected);
            if (Result.detected == Preview::Contract::ProtocolType::Unknown && !Request.ProtocolOverride.empty())
            {
                ProtocolValue = Request.ProtocolOverride;
            }
            const auto Protocol = Preview::Text::PascalCaseValue(ProtocolValue);
            RecordCarrierMetadata(State_->Trace, Result.Carrier);
            if (Accepted)
            {
                const auto Sanitized = SanitizeCandidateName(Result.CandidateName);
                const auto Candidate = Preview::Text::PascalCaseValue(Sanitized.View());
                (void)Preview::Diagnose::Debug(State_->Trace, "RecognitionAccepted Candidate={} CandidateTruncated={}",
                    Candidate, Sanitized.Truncated());
                WriteRecognitionDetails(Result, Protocol.View());
                return;
            }
            const auto Fault = Preview::Text::PascalCaseValue(Preview::Fault::Describe(FaultCode));
            if (Request.Stage == "auth") { Stage = "Authentication"; }
            const auto PascalStage = Preview::Text::PascalCaseValue(Stage);
            Preview::Text::FixedText<128U> Error;
            if (Result.NativeError) { Error = FormatErrorCode(Result.NativeError); }
            else if (Result.Error) { Error = FormatErrorCode(Result.Error); }
            Preview::Text::FixedText<128U> Reason;
            if (CarrierFailure)
            {
                Reason = Preview::Text::PascalCaseValue(ClassifyCarrierFailure(FaultCode, Result.NativeError));
            }
            auto Context = State_->Trace.With(Preview::Diagnose::Fields::Stage, PascalStage.View())
                .With(Preview::Diagnose::Fields::FaultCode, Fault.View());
            auto Status = Fault.View();
            if (!Reason.Empty()) { Status = Reason.View(); }
            Context = Context.With(Preview::Diagnose::Fields::Status, Status);
            if (!Error.Empty()) { Context = Context.With(Preview::Diagnose::Fields::NativeError, Error.View()); }
            const auto Event = FailureEvent(Request.Stage, FaultCode, CarrierFailure);
            WriteRecognitionFailure({LogTarget{Level, Context}, Event.View(), Protocol.View(), Fault.View(),
                Reason.View(), Error.View(), Error.Truncated()});
        }
        auto WriteAuthenticationInfo(const Preview::Middleware::Context& Context) noexcept -> void
        {
            if (!State_ || !Preview::Diagnose::IsContextEnabled(
                    State_->Trace, Preview::Diagnose::LogLevel::Info)) { return; }
            const auto User = UserLogValue(Context);
            auto Name = User.View();
            if (Name.empty()) { Name = "Unknown"; }
            auto Source = std::string_view(Context.SourceIp);
            if (Source.empty()) { Source = "Unknown"; }
            (void)Preview::Diagnose::Info(State_->Trace,
                "AuthenticationSucceeded SourceIp={} User={} UserTruncated={}", Source, Name, User.Truncated());
        }
        auto WriteRequestInfo(const Preview::Middleware::Context& Context) noexcept -> void
        {
            if (!State_ || !Preview::Diagnose::IsContextEnabled(
                    State_->Trace, Preview::Diagnose::LogLevel::Info) ||
                Context.Target().Host.Empty() || Context.Target().Port == 0U) { return; }
            const auto Literal = Preview::Network::IpAddress(Context.Target().Host);
            if (Context.IsDatagram() && Literal && Literal->is_unspecified()) { return; }
            const auto User = UserLogValue(Context);
            auto Source = std::string_view(Context.SourceIp);
            if (Source.empty()) { Source = "Unknown"; }
            const auto Target = Preview::Network::ToText(Context.Target().Host);
            if (User.Empty())
            {
                (void)Preview::Diagnose::Info(State_->Trace, "Request SourceIp={} Target={}:{}",
                    Source, Target.View(), Context.Target().Port);
            }
            else
            {
                (void)Preview::Diagnose::Info(State_->Trace, "Request SourceIp={} Target={}:{} User={} UserTruncated={}",
                    Source, Target.View(), Context.Target().Port, User, User.Truncated());
            }
        }
            template <typename... Args>
            [[nodiscard]] static auto WriteLog(
                const LogTarget Target,
                const std::format_string<Args...> Format,
                Args &&...Arguments) noexcept -> Preview::Diagnose::SubmissionReceipt
            {
                const auto Level = Target.Level;
                const auto &Context = Target.Context;
                using Preview::Diagnose::LogLevel;
                switch (Level)
                {
                case LogLevel::Trace:
                    return Preview::Diagnose::Trace(Context, Format,
                                                    std::forward<Args>(Arguments)...);
                case LogLevel::Debug:
                    return Preview::Diagnose::Debug(Context, Format,
                                                     std::forward<Args>(Arguments)...);
                case LogLevel::Info:
                    return Preview::Diagnose::Info(Context, Format,
                                                   std::forward<Args>(Arguments)...);
                case LogLevel::Access:
                    return Preview::Diagnose::Access(Context, Format,
                                                     std::forward<Args>(Arguments)...);
                case LogLevel::Warn:
                    return Preview::Diagnose::Warn(Context, Format,
                                                   std::forward<Args>(Arguments)...);
                case LogLevel::Error:
                    return Preview::Diagnose::Error(Context, Format,
                                                    std::forward<Args>(Arguments)...);
                case LogLevel::Critical:
                    return Preview::Diagnose::Critical(Context, Format,
                                                       std::forward<Args>(Arguments)...);
                case LogLevel::Off:
                    return {Preview::Diagnose::SubmissionStatus::Filtered, 0U};
                }
                return {Preview::Diagnose::SubmissionStatus::Filtered, 0U};
            }

        [[nodiscard]] auto State() const noexcept -> const std::shared_ptr<SessionLogState>& { return State_; }
    private:
        [[nodiscard]] static auto FailureEvent(const std::string_view Stage, const Preview::Fault::Code Code,
            const bool Carrier) noexcept -> Preview::Text::FixedText<128U>
        {
            if (Carrier) { return Preview::Text::FixedText<128U>("CarrierCommitFailed"); }
            if (Stage == "recognition")
            {
                if (Code == Preview::Fault::Code::Canceled) { return Preview::Text::FixedText<128U>("RecognitionCanceled"); }
                return Preview::Text::FixedText<128U>("RecognitionFailed");
            }
            if (Stage == "auth") { return Preview::Text::FixedText<128U>("AuthenticationFailed"); }
            auto Result = Preview::Text::PascalCaseValue(Stage);
            Result.Append("Failed");
            return Result;
        }
        auto WriteRecognitionDetails(const Preview::Recognition::RecognizeResult& Result,
            const std::string_view Protocol) noexcept -> void
        {
            if (!State_ || !Preview::Diagnose::IsContextEnabled(
                    State_->Trace, Preview::Diagnose::LogLevel::Trace)) { return; }
            std::string_view ModeValue{"legacy"};
            if (Profile_) { ModeValue = Preview::Recognition::ToStringView(Profile_->Mode()); }
            const auto Mode = Preview::Text::PascalCaseValue(ModeValue);
            auto ProbeBytes = Result.ProbeBytes;
            if (ProbeBytes == 0U) { ProbeBytes = Result.preread.size(); }
            const auto Byte = FormatFirstByte(Result);
            (void)WriteLog(LogTarget{Preview::Diagnose::LogLevel::Trace, State_->Trace},
                "RecognitionDetails Protocol={} Mode={} ProbeBytes={} FirstByte={} CryptoTrials={}",
                Protocol, Mode, ProbeBytes, Byte, Result.CryptoTrials);
        }
        static auto WriteRecognitionFailure(const RecognitionFailureRequest Request) noexcept -> void
        {
            const auto Target = Request.Target;
            if (!Request.Reason.empty() && !Request.Error.empty())
            {
                (void)WriteLog(Target, "{} Protocol={} FaultCode={} Reason={} Error={} ErrorTruncated={}",
                    Request.Event, Request.Protocol, Request.FaultCode, Request.Reason, Request.Error, Request.ErrorTruncated);
            }
            else if (!Request.Reason.empty())
            {
                (void)WriteLog(Target, "{} Protocol={} FaultCode={} Reason={}", Request.Event,
                    Request.Protocol, Request.FaultCode, Request.Reason);
            }
            else if (!Request.Error.empty())
            {
                (void)WriteLog(Target, "{} Protocol={} FaultCode={} Error={} ErrorTruncated={}", Request.Event,
                    Request.Protocol, Request.FaultCode, Request.Error, Request.ErrorTruncated);
            }
            else { (void)WriteLog(Target, "{} Protocol={} FaultCode={}", Request.Event, Request.Protocol, Request.FaultCode); }
        }
        std::shared_ptr<SessionLogState> State_;
        Preview::Recognition::SharedProfile Profile_;
    };
}
