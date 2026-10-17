/**
 * @file RecognitionAdmission.hpp
 * @brief Session 载体探测、协议识别、接入和上下文装配
 * @details 该 owner 只负责把入站传输物化为带有协议身份和认证上下文的
 *          middleware context；typed data-plane 的执行由 DataPlaneRelay 拥有。
 */

#pragma once
#include <Preview/Contract/Ingress/StreamFactory.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <string>
#include <string_view>
#include <utility>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Runtime/Recognition/RawIngressProbe.hpp>
#include <Preview/Runtime/Recognition/Recognition.hpp>
#include <Preview/Runtime/Session/ClosePolicy.hpp>
#include <Preview/Runtime/Session/CarrierInstallation.hpp>
#include <Preview/Runtime/Session/Detail/NegotiatedTlsRoute.hpp>
#include <Preview/Runtime/Session/RunContext.hpp>
#include <Preview/Transport/NativeTls.hpp>

namespace Preview::Runtime
{

    namespace Net = boost::asio;

    /**
     * @class SessionRecognitionAdmission
     * @brief 识别与协议接入 owner
     */
    class SessionRecognitionAdmission final
    {
    public:
        /** @brief 按载体、识别和协议接入阶段移交唯一数据面。 */
        [[nodiscard]] static auto Run(SessionRunContext& Run)
            -> Net::awaitable<Preview::Fault::Failure>
        {
            if (!Run.Control || !Run.Active || !Run.LogState)
                co_return Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument};
            if (!Run.Services || !Run.Services->Bytes)
            {
                const auto Closed = SessionClosePolicy::CloseActive(Run.Active);
                if (!Closed) co_return Closed.error();
                co_return Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument};
            }
            const auto CarrierError = co_await ProbeCarrier(Run);
            if (CarrierError.Failed()) co_return CarrierError;
            const auto HasRecognition = static_cast<bool>(Run.Profile);
            if (HasRecognition && Run.TraceWriter)
            {
                Run.TraceWriter->Record(SessionTraceStage::RecognitionStarted);
            }
            const auto RecognitionError = co_await Recognize(Run);
            if (HasRecognition && Run.TraceWriter)
            {
                Run.TraceWriter->Record(SessionTraceStage::RecognitionCompleted,
                    RecognitionError.Code);
            }
            if (RecognitionError.Failed()) co_return RecognitionError;
            auto Factory = ResolveFactory(Run);
            if (!Factory) co_return Factory.error();
            co_return co_await Accept(Run, std::move(*Factory));
        }

    private:
        static auto ProbeCarrier(SessionRunContext& Run) -> Net::awaitable<Preview::Fault::Failure>
        {
            if (Run.Services->NativeTls &&
                (!Run.Profile || !Run.Profile->HasTlsCandidate()))
            {
                if (Run.TraceWriter)
                {
                    Run.TraceWriter->Record(SessionTraceStage::CarrierProbeStarted);
                }
                Run.LogState->MarkStage("CarrierProbe");
                const auto HandshakeDeadline = std::chrono::steady_clock::now() +
                                               Run.Services->HandshakeTimeout;
                auto ProbeResult = co_await Preview::Recognition::RawIngressProbe::Run(
                    Preview::Recognition::RawIngressProbeRequest{
                        Run.Inbound, Run.Services->HandshakeTimeout, Run.Services->Bytes});
                if (Preview::Fault::Failed(ProbeResult.Code) || !ProbeResult.Transport)
                {
                    const auto FailureCode = ProbeResult.Code == Preview::Fault::Code::Success
                                                 ? Preview::Fault::Code::ProtocolError
                                                 : ProbeResult.Code;
                    const auto Outcome = FailureCode == Preview::Fault::Code::Timeout
                                             ? std::string_view{"client_hello_timeout"}
                                             : FailureCode == Preview::Fault::Code::Canceled
                                                   ? std::string_view{"cancelled"}
                                                   : std::string_view{"carrier_no_match"};
                    const auto NativeErrorText = ProbeResult.NativeError
                                                     ? ProbeResult.NativeError.message()
                                                     : std::string{};
                    const auto FaultText = Preview::Diagnose::PascalCaseToken(
                        Preview::Fault::Describe(FailureCode));
                    const auto OutcomeText = Preview::Diagnose::PascalCaseToken(Outcome);
                    if (NativeErrorText.empty())
                    {
                        (void)SessionSupport::SessionLogWriter::WriteLog(
                            SessionSupport::LogTarget{Preview::Diagnose::LogLevel::Warn, Run.LogState->Trace},
                            "CarrierProbeFailed Outcome={} FaultCode={}", OutcomeText, FaultText);
                    }
                    else
                    {
                        (void)SessionSupport::SessionLogWriter::WriteLog(
                            SessionSupport::LogTarget{Preview::Diagnose::LogLevel::Warn, Run.LogState->Trace},
                            "CarrierProbeFailed Outcome={} FaultCode={} Error={}",
                            OutcomeText, FaultText, NativeErrorText);
                    }
                    if (Run.TraceWriter)
                    {
                        Run.TraceWriter->Record(SessionTraceStage::CarrierProbeCompleted, FailureCode);
                    }
                    co_return Preview::Fault::Failure{FailureCode, ProbeResult.NativeError};
                }

                Run.Inbound = std::move(ProbeResult.Transport);
                if (const auto Stored = SessionCarrierInstallation::Inbound(*Run.Active, Run.Inbound); !Stored)
                {
                    if (Run.TraceWriter)
                    {
                        Run.TraceWriter->Record(SessionTraceStage::CarrierProbeCompleted,
                                                Stored.error().Code);
                    }
                    co_return Stored.error();
                }
                if (Run.TraceWriter)
                {
                    Run.TraceWriter->Record(SessionTraceStage::CarrierProbeCompleted,
                                            Preview::Fault::Code::Success);
                }
                if (ProbeResult.Kind != Preview::Recognition::RawIngressKind::Cleartext)
                {
                    SessionSupport::RecordClientHello(Run.LogState->Trace,
                                                      ProbeResult.ClientHello);
                    co_return co_await CommitNativeTls(Run, HandshakeDeadline);
                }
            }
            co_return Preview::Fault::Failure{};
        }

        static auto CommitNativeTls(SessionRunContext& Run,
                                    std::chrono::steady_clock::time_point HandshakeDeadline)
            -> Net::awaitable<Preview::Fault::Failure>
        {
            Run.LogState->MarkStage("CarrierCommit");
            auto TlsResult = co_await Preview::Transport::UpgradeNativeTls(
                Preview::Transport::NativeTlsRequest{
                    std::move(Run.Inbound), Run.Services->NativeTls,
                    HandshakeDeadline - std::chrono::steady_clock::now(), Run.Services->Bytes});
            if (Preview::Fault::Failed(TlsResult.Failure.Code) || !TlsResult.Transport ||
                !TlsResult.Attempted)
            {
                auto FailureCode = TlsResult.Failure.Code;
                if (FailureCode == Preview::Fault::Code::Success)
                    FailureCode = Preview::Fault::Code::ProtocolError;
                const auto Outcome = SessionSupport::ClassifyNativeTlsFailure(TlsResult);
                const auto ErrorText = SessionSupport::FormatErrorCode(TlsResult.Failure.Native);
                const auto FaultText = Preview::Text::PascalCaseValue(Preview::Fault::Describe(FailureCode));
                const auto OutcomeText = Preview::Text::PascalCaseValue(Outcome);
                auto FailureContext = Run.LogState->Trace;
                FailureContext = FailureContext.With(Preview::Diagnose::Fields::Stage,
                    std::string_view{"CarrierCommit"});
                FailureContext = FailureContext.With(Preview::Diagnose::Fields::Status, OutcomeText.View());
                FailureContext = FailureContext.With(Preview::Diagnose::Fields::FaultCode, FaultText.View());
                if (TlsResult.Failure.Native)
                    FailureContext = FailureContext.With(Preview::Diagnose::Fields::NativeError, ErrorText.View());
                (void)SessionSupport::SessionLogWriter::WriteLog(
                    SessionSupport::LogTarget{Preview::Diagnose::LogLevel::Warn, FailureContext},
                    "CarrierCommitFailed Outcome={} FaultCode={} Error={}",
                    OutcomeText, FaultText, ErrorText);
                co_return Preview::Fault::Failure{
                    FailureCode, static_cast<std::error_code>(TlsResult.Failure.Native)};
            }
            Run.Inbound = std::move(TlsResult.Transport);
            if (const auto Stored = SessionCarrierInstallation::Inbound(*Run.Active, Run.Inbound); !Stored)
                co_return Stored.error();
            SessionSupport::RecordTlsNegotiation(Run.LogState->Trace, Run.Inbound);
            co_return Preview::Fault::Failure{};
        }

        /** @brief 按握手后的真实 SNI 选择同一 TLS carrier 的路由目标。 */
        [[nodiscard]] static auto ApplyNegotiatedTlsRoute(SessionRunContext& Run) -> bool
        {
            auto Route = Detail::ResolveNegotiatedTlsRoute(
                Run.Profile.get(), Run.Recognition.Carrier);
            if (!Route)
            {
                return false;
            }
            if (!Route->has_value())
            {
                return true;
            }
            const auto& Candidate = **Route;
            Run.Recognition.Candidate = Candidate.Id();
            Run.Recognition.CandidateName = Candidate.Name();
            Run.Recognition.detected = Candidate.Protocol();
            return true;
        }

        static auto Recognize(SessionRunContext& Run) -> Net::awaitable<Preview::Fault::Failure>
        {
            if (Run.Profile)
            {
                Preview::Recognition::Pipeline Recognizer(
                    Run.Profile, Run.Services->Bytes, Run.LogState->Trace);
                Preview::Recognition::RecognitionControl RecognitionControl;
                RecognitionControl.Cancelled = [Control = Run.Control]
                {
                    return Control->IsCancelled();
                };
                RecognitionControl.Wait = [Cancellation = Run.Cancellation]()
                    -> Net::awaitable<Preview::Recognition::RecognitionControlEvent>
                {
                    co_await Cancellation->async_receive(Net::use_awaitable);
                    co_return Preview::Recognition::RecognitionControlEvent::Cancelled;
                };
                RecognitionControl.CancelTransport = [Active = Run.Active]
                {
                    SessionClosePolicy::CloseActive(Active);
                };
                RecognitionControl.WaitCancellationSafe = true;
                Preview::Recognition::ProbeBuffer Probe(
                    Run.Profile ? Run.Profile->Budget().MaxProbeBytes
                                : Preview::Recognition::MaxTlsClientHelloBytes,
                    Run.Services->Bytes);
                Run.Recognition = co_await Recognizer.Recognize(
                    std::move(Run.Inbound), Probe, std::move(RecognitionControl));
            if (Run.Recognition.transport)
            {
                if (const auto Stored = SessionCarrierInstallation::Inbound(*Run.Active, Run.Recognition.transport); !Stored)
                    co_return Stored.error();
            }
            if (Run.Recognition.Cancelled || Run.Control->IsCancelled())
            {
                Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                    Preview::Diagnose::LogLevel::Trace, "recognition", Run.Recognition,
                    Preview::Fault::Code::Canceled});
                co_return Preview::Fault::Failure{Preview::Fault::Code::Canceled};
            }
            if (Run.Profile)
            {
                auto Candidate = Run.Recognition.Candidate;
                if (Candidate == Preview::Recognition::InvalidCandidate)
                {
                    Candidate = Run.Profile->ConfiguredCandidate();
                }
                if (Candidate == Preview::Recognition::InvalidCandidate &&
                    Run.Profile->CandidateCount() != 0U)
                {
                    Candidate = Run.Profile->CandidateIdAt(0);
                }
                if (Run.Recognition.CandidateName.empty())
                {
                    Run.Recognition.CandidateName = Run.Profile->CandidateName(Candidate);
                }
                if (Run.Recognition.detected == Preview::Contract::ProtocolType::Unknown)
                {
                    Run.Recognition.detected = Run.Profile->CandidateProtocol(Candidate);
                }
                const auto Handle = Run.Profile->FindCandidate(Candidate);
                if (Handle.IsValid())
                {
                    Run.Recognition.Candidate = Candidate;
                }
                Run.Recognition.Candidate = Candidate;
            }
            if (Run.Recognition.success && !ApplyNegotiatedTlsRoute(Run))
            {
                Run.Recognition.success = false;
                Run.Recognition.Status = Preview::Recognition::RecognitionStatus::NoMatch;
                Run.Recognition.Candidate = Preview::Recognition::InvalidCandidate;
                Run.Recognition.CandidateName.clear();
                Run.Recognition.FaultCode = Preview::Fault::Code::ProtocolError;
            }
            SessionSupport::RecordCarrierMetadata(Run.LogState->Trace, Run.Recognition.Carrier);
            if (Run.Recognition.success && !Run.Recognition.Carrier.Carrier.empty())
            {
                SessionSupport::RecordTlsNegotiation(Run.LogState->Trace,
                                                     Run.Recognition.transport);
            }
            Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                Run.Recognition.success ? Preview::Diagnose::LogLevel::Trace
                                        : Preview::Diagnose::LogLevel::Warn,
                "recognition", Run.Recognition,
                Run.Recognition.success ? Preview::Fault::Code::Success
                                        : Preview::Fault::Code::ProtocolError});

            }
            else
            {
                Run.Recognition.transport = std::move(Run.Inbound);
                Run.Recognition.success = true;
                Run.Recognition.Status = Preview::Recognition::RecognitionStatus::Accepted;
            }
            if (!Run.Recognition.success)
            {
                auto Failure = RecognitionFailure(Run.Recognition);
                co_return Failure;
            }
            co_return Preview::Fault::Failure{};
        }

        static auto ResolveFactory(SessionRunContext& Run)
            -> std::expected<std::shared_ptr<Preview::Contract::StreamFactory>,
                              Preview::Fault::Failure>
        {
            std::shared_ptr<Preview::Contract::StreamFactory> Acceptor;
            if (Run.Profile)
            {
                if (!Run.Recognition.success ||
                    Run.Recognition.Status != Preview::Recognition::RecognitionStatus::Accepted ||
                    Run.Recognition.Candidate == Preview::Recognition::InvalidCandidate)
                {
                    const auto FailureCode = Run.Recognition.FaultCode == Preview::Fault::Code::Success
                                                 ? Preview::Fault::Code::ProtocolError
                                                 : Run.Recognition.FaultCode;
                    if (Run.Recognition.Carrier.Carrier.empty())
                    {
                        Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                            Preview::Diagnose::LogLevel::Warn, "accept", Run.Recognition, FailureCode});
                    }
                    return std::unexpected(RecognitionFailure(Run.Recognition, FailureCode));
                }
                const auto& CandidateResolver = Run.ResolveCandidate;
                if (CandidateResolver)
                {
                    Acceptor = CandidateResolver(Run.Recognition.Candidate);
                }
                if (!Acceptor)
                {
                    Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                        Preview::Diagnose::LogLevel::Warn, "accept", Run.Recognition,
                        Preview::Fault::Code::ProtocolError});
                    return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::ProtocolError});
                }
            }
            else
            {
                if (!Run.AcceptProtocol &&
                    (!Run.Recognition.success ||
                     Run.Recognition.detected == Preview::Contract::ProtocolType::Unknown))
                {
                    Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                        Preview::Diagnose::LogLevel::Warn, "accept", Run.Recognition,
                        Preview::Fault::Code::ProtocolError});
                    return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::ProtocolError});
                }
                Acceptor = Run.AcceptProtocol;
            }
            return Acceptor;
        }

        static auto Accept(SessionRunContext& Run,
                           std::shared_ptr<Preview::Contract::StreamFactory> Acceptor)
            -> Net::awaitable<Preview::Fault::Failure>
        {
            auto &Context = Run.Context;
            Context.SourceIp = Run.SourceIp;
            Context.DataPlane.Protocol = Run.Recognition.detected;
            Context.Inbound() = std::move(Run.Recognition.transport);
            Run.AuthenticationInfoLogged = false;
            Context.TaskIdentity = Run.Control->CurrentIdentity();
            Context.Control = Run.Control;
            if (const auto Stored = SessionCarrierInstallation::Inbound(*Run.Active, Context.Inbound()); !Stored)
                co_return Stored.error();
            Context.Traffic = Run.Traffic;
            Context.Bytes = Run.Services->Bytes;
            Context.Dial = Run.Dial;
            Context.Pad = Run.Pad;
            if (Acceptor)
            {
                Context.ProtocolNameForLog = std::string(Acceptor->Name());
                if (Run.TraceWriter)
                {
                    Run.TraceWriter->Record(SessionTraceStage::ProtocolAcceptStarted);
                }
                auto Accepted = co_await Acceptor->Accept(
                    Preview::Contract::StreamAcceptInput{
                        std::move(Context.Inbound()),
                        Preview::Contract::RequestMetadata{
                            Context.TaskIdentity, Context.SourceIp, Run.LogState->Trace},
                        Run.Services->Bytes,
                        Run.Services->GenerationUseState});
                if (!Accepted)
                {
                    const auto Error = Accepted.error().Code;
                    if (Run.TraceWriter)
                    {
                        Run.TraceWriter->Record(SessionTraceStage::ProtocolAcceptCompleted, Error);
                    }
                    Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                        Preview::Diagnose::LogLevel::Warn, "accept", Run.Recognition, Error,
                        Context.ProtocolNameForLog});
                    co_return Accepted.error();
                }
                if (!Accepted->HasTransport())
                {
                    if (Run.TraceWriter)
                    {
                        Run.TraceWriter->Record(SessionTraceStage::ProtocolAcceptCompleted,
                                                Preview::Fault::Code::IoError);
                    }
                    co_return Preview::Fault::Failure{Preview::Fault::Code::IoError};
                }
                Context.SetDataPlane(std::move(*Accepted));
                if (Run.TraceWriter)
                {
                    Run.TraceWriter->SetAccount(Context.AccountId());
                    Run.TraceWriter->SetTaskIdentity(Context.TaskIdentity);
                    Run.TraceWriter->Record(SessionTraceStage::ProtocolAcceptCompleted,
                                            Preview::Fault::Code::Success);
                }
                if (const auto Stored = SessionCarrierInstallation::Inbound(*Run.Active, Context.Inbound()); !Stored)
                    co_return Stored.error();
            }
            else
            {
                co_return Preview::Fault::Failure{Preview::Fault::Code::NotSupported};
            }
            if (Context.ProtocolAuthenticated())
            {
                if (Run.TraceWriter)
                {
                    Run.TraceWriter->Record(SessionTraceStage::AuthenticationConfirmed,
                                            Preview::Fault::Code::Success);
                }
                Run.Logger.WriteAuthenticationInfo(Context);
                Run.AuthenticationInfoLogged = true;
            }
            const auto InnerProtocol =
                Context.DataPlane.Protocol;
            if (InnerProtocol != Preview::Contract::ProtocolType::Unknown &&
                InnerProtocol != Run.Recognition.detected)
            {
                Run.Recognition.detected = InnerProtocol;
                Run.Recognition.CandidateName = "protocol-" +
                                                std::string(Preview::Contract::ToStringView(InnerProtocol));
                if (!Run.Recognition.scheme.empty())
                {
                    Run.Recognition.CandidateName += "+" + Run.Recognition.scheme;
                }
            }
            if (Run.Traffic && Context.DataPlane.Protocol != Preview::Contract::ProtocolType::Unknown)
            {
                const auto Identity = Run.Control->CurrentIdentity();
                Run.Traffic->Report(Preview::Foundation::TrafficEvent{
                    .Generation = Identity.Generation, .Worker = Identity.WorkerId,
                    .Session = Identity.SessionId, .Account = Context.DataPlane.AccountId,
                    .Kind = Preview::Foundation::TrafficEventKind::ProtocolAssociated,
                    .Protocol = static_cast<std::uint64_t>(Context.DataPlane.Protocol)});
            }
            if (Run.Registration && *Run.Registration)
            {
                const auto Identity = Run.Control->CurrentIdentity();
                Preview::Runtime::SessionInfo Info;
                Info.Id = Run.Registration->Id();
                Info.AccountId = Context.DataPlane.AccountId;
                Info.AccountRuntime = Context.AccountLease().RuntimeIdentity();
                Info.identity = Context.DataPlane.Identity;
                Info.peer = Context.SourceIp;
                const auto Text = Preview::Network::ToText(Context.DataPlane.Target.Host);
                Info.Target = Text.View();
                if (Context.DataPlane.Target.Port != 0)
                {
                    Info.Target += ":";
                    Info.Target += std::to_string(Context.DataPlane.Target.Port);
                }
                Info.Protocol = static_cast<std::uint16_t>(Context.DataPlane.Protocol);
                Info.Worker = Identity.WorkerId;
                Info.Generation = Identity.Generation;
                if (!Run.Registration->Update(std::move(Info)))
                {
                    co_return Preview::Fault::Failure{Preview::Fault::Code::Canceled};
                }
            }
            Run.LogState->MarkStage("Accept");
            co_return Preview::Fault::Failure{};
        }

        [[nodiscard]] static auto RecognitionFailure(
            const Preview::Recognition::RecognizeResult& Result,
            const Preview::Fault::Code Fallback = Preview::Fault::Code::ProtocolError) noexcept
            -> Preview::Fault::Failure
        {
            const auto Code = Result.FaultCode == Preview::Fault::Code::Success
                ? Fallback
                : Result.FaultCode;
            return {Code, static_cast<std::error_code>(Result.NativeError)};
        }
    };
} // namespace Preview::Runtime
