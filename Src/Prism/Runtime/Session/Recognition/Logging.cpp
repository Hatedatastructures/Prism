/** @file Logging.cpp @brief 会话识别与认证日志实现。 */
#include <Prism/Runtime/Session/RecognitionLogging.hpp>

#include <Prism/Net/HostText.hpp>
#include <Prism/Runtime/Recognition/Tls.hpp>
#include <Prism/Runtime/Session/Logging.hpp>

#include <openssl/ssl.h>

#include <cstddef>
#include <string_view>

namespace Prism::Runtime::SessionSupport
{
    auto RecordCarrierMetadata(
        Prism::Diagnose::ContextState& Trace,
        const Prism::Recognition::CarrierMetadata& Metadata) noexcept -> void
    {
        if (!Metadata.Carrier.empty())
        {
            const auto Carrier = Prism::Text::PascalCaseValue(Metadata.Carrier);
            Trace = Trace.With(Prism::Diagnose::Fields::Carrier, Carrier.View());
        }
        if (!Metadata.Sni.empty()) { Trace = Trace.With(Prism::Diagnose::Fields::Sni, Metadata.Sni); }
        if (!Metadata.Alpn.empty()) { Trace = Trace.With(Prism::Diagnose::Fields::Alpn, Metadata.Alpn); }
        if (!Metadata.TlsVersion.empty()) { Trace = Trace.With(Prism::Diagnose::Fields::TlsVersion, Metadata.TlsVersion); }
    }

    auto RecordClientHello(
        Prism::Diagnose::ContextState& Trace,
        const Prism::Recognition::ClientHelloFeatures& Features) noexcept -> void
    {
        Trace = Trace.With(Prism::Diagnose::Fields::Carrier, std::string_view{"Native"});
        if (!Features.ServerName.empty())
        {
            Trace = Trace.With(Prism::Diagnose::Fields::Sni, std::string_view(Features.ServerName));
        }
    }

    auto RecordTlsNegotiation(
        Prism::Diagnose::ContextState& Trace,
        const Prism::SharedTransmission& Transport) noexcept -> void
    {
        if (!Transport) { return; }
        auto* Encrypted = dynamic_cast<Prism::Transport::Encrypted*>(Transport.get());
        if (!Encrypted) { return; }
        auto* Ssl = Encrypted->Stream().native_handle();
        if (!Ssl) { return; }
        if (const auto* Version = SSL_get_version(Ssl))
        {
            Trace = Trace.With(Prism::Diagnose::Fields::TlsVersion, std::string_view(Version));
        }
        const unsigned char* Alpn = nullptr;
        unsigned int Length = 0U;
        SSL_get0_alpn_selected(Ssl, &Alpn, &Length);
        if (Alpn && Length != 0U)
        {
            const auto Value = std::string_view(reinterpret_cast<const char*>(Alpn), Length);
            Trace = Trace.With(Prism::Diagnose::Fields::Alpn, Value);
        }
    }

    auto SanitizeCandidateName(const std::string_view Value) noexcept -> Prism::Text::FixedText<64U>
    {
        Prism::Text::FixedText<64U> Result;
        for (const auto Character : Value)
        {
            const auto Byte = static_cast<unsigned char>(Character);
            if (Byte >= 0x21U && Byte <= 0x7EU && Character != '=' && Character != '[' && Character != ']' && Character != ';')
            {
                Result.PushBack(Character);
            }
            else { Result.PushBack('_'); }
        }
        if (Result.Empty()) { Result.Append("none"); }
        return Result;
    }

    auto FormatFirstByte(const Prism::Recognition::RecognizeResult& Result) noexcept
        -> Prism::Text::FixedText<8U>
    {
        Prism::Text::FixedText<8U> Value;
        if (Result.preread.empty()) { Value.Append("None"); return Value; }
        constexpr char Hex[] = "0123456789ABCDEF";
        const auto Byte = std::to_integer<unsigned int>(Result.preread.front());
        Value.Append("0x");
        Value.PushBack(Hex[(Byte >> 4U) & 0x0FU]);
        Value.PushBack(Hex[Byte & 0x0FU]);
        return Value;
    }

    auto UserLogValue(const Prism::Middleware::Context& Context) noexcept
        -> Prism::Text::FixedText<256U>
    {
        Prism::Text::FixedText<256U> Result;
        if (!Context.DisplayIdentity().empty()) { Result.Append(Context.DisplayIdentity()); }
        else if (Context.AccountId()) { Result.AppendNumber(Context.AccountId().Value()); }
        return Result;
    }

    auto SessionLogWriter::WriteRecognition(const RecognitionLogRequest Request) noexcept -> void
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

    auto SessionLogWriter::WriteAuthenticationInfo(const Prism::Middleware::Context& Context) noexcept -> void
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

    auto SessionLogWriter::WriteRequestInfo(const Prism::Middleware::Context& Context) noexcept -> void
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

    auto SessionLogWriter::FailureEvent(const std::string_view Stage, const Prism::Fault::Code Code,
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

    auto SessionLogWriter::WriteRecognitionDetails(
        const Prism::Recognition::RecognizeResult& Result,
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

    auto SessionLogWriter::WriteRecognitionFailure(const RecognitionFailureRequest Request) noexcept -> void
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
}
