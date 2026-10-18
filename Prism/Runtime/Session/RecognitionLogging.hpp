/** @file RecognitionLogging.hpp
 * @brief recognition、认证与目标日志的无分配观察 writer。
 */
#pragma once
#include <Prism/Runtime/Session/Logging.hpp>
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
        auto WriteRecognition(const RecognitionLogRequest Request) noexcept -> void
        {
            if (!State_) { return; }
            const auto& Result = Request.Result;
            const bool RecognitionStage = Request.Stage == "recognition";
            auto FaultCode = Request.FaultCode;
            if (RecognitionStage && Result.FaultCode != Prism::Fault::Code::Success) { FaultCode = Result.FaultCode; }
            const bool CarrierFailure = RecognitionStage && !Result.Carrier.Carrier.empty() &&
                Prism::Fault::Failed(FaultCode) && FaultCode != Prism::Fault::Code::Canceled;
            const bool Accepted = RecognitionStage && Result.success && FaultCode == Prism::Fault::Code::Success;
            auto Stage = Request.Stage;
            if (CarrierFailure) { Stage = "CarrierCommit"; }
            State_->MarkStage(Stage);
            auto Level = Request.Level;
            if (RecognitionStage && !Accepted && FaultCode != Prism::Fault::Code::Canceled)
            {
                Level = Prism::Diagnose::LogLevel::Warn;
            }
            if (Accepted)
            {
                if (!Prism::Diagnose::IsContextEnabled(
                        State_->Trace, Prism::Diagnose::LogLevel::Debug) &&
                    !Prism::Diagnose::IsContextEnabled(
                        State_->Trace, Prism::Diagnose::LogLevel::Trace)) { return; }
            }
            else if (!Prism::Diagnose::IsContextEnabled(State_->Trace, Level)) { return; }
            auto ProtocolValue = Prism::Contract::ToStringView(Result.detected);
            if (Result.detected == Prism::Contract::ProtocolType::Unknown && !Request.ProtocolOverride.empty())
            {
                ProtocolValue = Request.ProtocolOverride;
            }
            const auto Protocol = Prism::Text::PascalCaseValue(ProtocolValue);
            RecordCarrierMetadata(State_->Trace, Result.Carrier);
            if (Accepted)
            {
                const auto Sanitized = SanitizeCandidateName(Result.CandidateName);
                const auto Candidate = Prism::Text::PascalCaseValue(Sanitized.View());
                (void)Prism::Diagnose::Debug(State_->Trace, "RecognitionAccepted Candidate={} CandidateTruncated={}",
                    Candidate, Sanitized.Truncated());
                WriteRecognitionDetails(Result, Protocol.View());
                return;
            }
            const auto Fault = Prism::Text::PascalCaseValue(Prism::Fault::Describe(FaultCode));
            if (Request.Stage == "auth") { Stage = "Authentication"; }
            const auto PascalStage = Prism::Text::PascalCaseValue(Stage);
            Prism::Text::FixedText<128U> Error;
            if (Result.NativeError) { Error = FormatErrorCode(Result.NativeError); }
            else if (Result.Error) { Error = FormatErrorCode(Result.Error); }
            Prism::Text::FixedText<128U> Reason;
            if (CarrierFailure)
            {
                Reason = Prism::Text::PascalCaseValue(ClassifyCarrierFailure(FaultCode, Result.NativeError));
            }
            auto Context = State_->Trace.With(Prism::Diagnose::Fields::Stage, PascalStage.View())
                .With(Prism::Diagnose::Fields::FaultCode, Fault.View());
            auto Status = Fault.View();
            if (!Reason.Empty()) { Status = Reason.View(); }
            Context = Context.With(Prism::Diagnose::Fields::Status, Status);
            if (!Error.Empty()) { Context = Context.With(Prism::Diagnose::Fields::NativeError, Error.View()); }
            const auto Event = FailureEvent(Request.Stage, FaultCode, CarrierFailure);
            WriteRecognitionFailure({LogTarget{Level, Context}, Event.View(), Protocol.View(), Fault.View(),
                Reason.View(), Error.View(), Error.Truncated()});
        }
        auto WriteAuthenticationInfo(const Prism::Middleware::Context& Context) noexcept -> void
        {
            if (!State_ || !Prism::Diagnose::IsContextEnabled(
                    State_->Trace, Prism::Diagnose::LogLevel::Info)) { return; }
            const auto User = UserLogValue(Context);
            auto Name = User.View();
            if (Name.empty()) { Name = "Unknown"; }
            auto Source = std::string_view(Context.SourceIp);
            if (Source.empty()) { Source = "Unknown"; }
            (void)Prism::Diagnose::Info(State_->Trace,
                "AuthenticationSucceeded SourceIp={} User={} UserTruncated={}", Source, Name, User.Truncated());
        }
        auto WriteRequestInfo(const Prism::Middleware::Context& Context) noexcept -> void
        {
            if (!State_ || !Prism::Diagnose::IsContextEnabled(
                    State_->Trace, Prism::Diagnose::LogLevel::Info) ||
                Context.Target().Host.Empty() || Context.Target().Port == 0U) { return; }
            const auto Literal = Prism::Network::IpAddress(Context.Target().Host);
            if (Context.IsDatagram() && Literal && Literal->is_unspecified()) { return; }
            const auto User = UserLogValue(Context);
            auto Source = std::string_view(Context.SourceIp);
            if (Source.empty()) { Source = "Unknown"; }
            const auto Target = Prism::Network::ToText(Context.Target().Host);
            if (User.Empty())
            {
                (void)Prism::Diagnose::Info(State_->Trace, "Request SourceIp={} Target={}:{}",
                    Source, Target.View(), Context.Target().Port);
            }
            else
            {
                (void)Prism::Diagnose::Info(State_->Trace, "Request SourceIp={} Target={}:{} User={} UserTruncated={}",
                    Source, Target.View(), Context.Target().Port, User, User.Truncated());
            }
        }
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
            const bool Carrier) noexcept -> Prism::Text::FixedText<128U>
        {
            if (Carrier) { return Prism::Text::FixedText<128U>("CarrierCommitFailed"); }
            if (Stage == "recognition")
            {
                if (Code == Prism::Fault::Code::Canceled) { return Prism::Text::FixedText<128U>("RecognitionCanceled"); }
                return Prism::Text::FixedText<128U>("RecognitionFailed");
            }
            if (Stage == "auth") { return Prism::Text::FixedText<128U>("AuthenticationFailed"); }
            auto Result = Prism::Text::PascalCaseValue(Stage);
            Result.Append("Failed");
            return Result;
        }
        auto WriteRecognitionDetails(const Prism::Recognition::RecognizeResult& Result,
            const std::string_view Protocol) noexcept -> void
        {
            if (!State_ || !Prism::Diagnose::IsContextEnabled(
                    State_->Trace, Prism::Diagnose::LogLevel::Trace)) { return; }
            std::string_view ModeValue{"legacy"};
            if (Profile_) { ModeValue = Prism::Recognition::ToStringView(Profile_->Mode()); }
            const auto Mode = Prism::Text::PascalCaseValue(ModeValue);
            auto ProbeBytes = Result.ProbeBytes;
            if (ProbeBytes == 0U) { ProbeBytes = Result.preread.size(); }
            const auto Byte = FormatFirstByte(Result);
            (void)WriteLog(LogTarget{Prism::Diagnose::LogLevel::Trace, State_->Trace},
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
        Prism::Recognition::SharedProfile Profile_;
    };
}
