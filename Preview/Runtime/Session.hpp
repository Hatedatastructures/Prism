/**
 * @file Session.hpp
 * @brief 会话编排（T4-2）
 * @details 把协议识别 → 上下文装配 → 中间件管线串成完整会话：
 *          1. Recognition::Pipeline 探测协议类型（预读回注）
 *          2. Prepare 回调按识别结果装配 Target / 凭据
 *          3. Middleware 管线：Auth（可选）→ Dial → relay
 *          - 识别失败 / 未知协议 → protocol_error
 *          - 认证失败 → auth_failed（管线终止）
 *          - relay 结束点自动上报流量（traffic sink）
 * @note 对应生产 Session::diversion；协议握手由各协议 Conn 承担
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <Preview/Foundation/Authenticator.hpp>
#include <Preview/Foundation/Utility/Diagnose/Log.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Runtime/Middleware/Builtin/Auth.hpp>
#include <Preview/Runtime/Middleware/Builtin/Dial.hpp>
#include <Preview/Runtime/Middleware/Builtin/Mux.hpp>
#include <Preview/Runtime/Middleware/Builtin/Pad.hpp>
#include <Preview/Runtime/Middleware/Builtin/Relay.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Middleware/Pipeline.hpp>
#include <Preview/Runtime/Recognition/Recognition.hpp>
#include <Preview/Runtime/SessionControl.hpp>
#include <Preview/Runtime/SessionServices.hpp>
#include <Preview/Lifecycle/TaskState.hpp>
#include <Preview/Transport/NativeTls.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Runtime
{

    namespace Net = boost::asio;

    /**
     * @struct SessionOptions
     * @brief 会话编排选项
     */
    struct SessionOptions
    {
        /// 协议接入函数：完成握手并将入站传输替换为协议数据连接
        using ProtocolAcceptFn = SessionServices::ProtocolAcceptFn;

        /// 按识别候选 ID 解析 winner-only 协议接入函数
        using ResolveCandidateFn = SessionServices::ResolveCandidateFn;

        /// owner-held 服务上下文；存在时优先于下方 legacy 字段
        SharedSessionServices Services{};
        /// 会话控制上下文；为空时由 Session 按入站执行器创建
        std::shared_ptr<SessionControl> Control{};

        /// SNI 路由表（可选，TLS 分流）
        Preview::Recognition::SniRouteTable *routes{nullptr};
        /// 伪装方案执行器（可选；由启动层拥有）
        Preview::Recognition::SchemeExecutor *Scheme{nullptr};
        /// 认证器（可选；缺省跳过认证）
        Preview::SharedAuthenticator Auth{};
        /// 中继空闲超时（0 = 禁用）
        std::chrono::milliseconds RelayIdleTimeout{std::chrono::seconds(60)};
        /// 协议接入函数（可选；缺省保留识别后的原始传输）
        ProtocolAcceptFn AcceptProtocol{};
        /// Profile 路径的不可变候选配置
        Preview::Recognition::SharedProfile Profile{};
        /// Profile 路径按 CandidateId 解析接入函数；仅 winner 调用一次
        ResolveCandidateFn ResolveCandidate{};
        /// Resolver 命名兼容别名；Profile 路径优先使用 ResolveCandidate
        ResolveCandidateFn Resolver{};
        /// 装配回调：按识别结果填充 ctx（Target/凭据）；返回非 success 终止
        SessionServices::PrepareFn Prepare{};
        /// 多路复用引导函数（可选；缺省直通）
        Preview::Middleware::Builtin::MuxMiddleware::MuxFn mux{};
        /// 填充配置（可选；缺省不填充）
        const Preview::Middleware::Context::PadConfig *pad{nullptr};
        /// 拨号函数（缺省 Dial 中间件返回 not_supported）
        Preview::Middleware::Builtin::DialMiddleware::DialFn Dial{};
        /// Dgram 会话服务（ctx.IsDgram 时替代 Dial/relay；协议无关）
        SessionServices::UdpServiceFn udp_service{};
        /// 流量统计 sink（relay 结束点上报）
        Preview::Middleware::Context::TrafficSink *traffic{nullptr};
    };

    /**
     * @class Session
     * @brief 单连接会话编排
     * @details 识别 → 装配 → 管线（Auth/Dial/relay）。
     *          每个连接构造一次，Run() 结束后销毁。
     */
    class Session
    {
    private:
        struct ActiveTransports
        {
            Preview::SharedTransmission Inbound;
            Preview::SharedTransmission Outbound;
        };

        struct SessionLogState final
        {
            static constexpr std::uint32_t RecognitionPhase = 1U << 0U;
            static constexpr std::uint32_t AcceptPhase = 1U << 1U;
            static constexpr std::uint32_t AuthPhase = 1U << 2U;
            static constexpr std::uint32_t DialPhase = 1U << 3U;
            static constexpr std::uint32_t RelayPhase = 1U << 4U;
            static constexpr std::uint32_t CarrierProbePhase = 1U << 5U;
            static constexpr std::uint32_t CarrierCommitPhase = 1U << 6U;

            Preview::Diagnose::Logger::Owner Logger;
            std::shared_ptr<Preview::Diagnose::TraceContext> Trace;
            std::atomic<bool> CloseLogged{false};
            std::atomic<std::uint32_t> PhaseMask{0};
            std::chrono::steady_clock::time_point StartedAt{std::chrono::steady_clock::now()};
            Preview::Fault::Code FinalCode{Preview::Fault::Code::Success};

            auto MarkStage(const std::string_view Stage) noexcept -> void
            {
                if (Stage == "recognition")
                {
                    PhaseMask.fetch_or(RecognitionPhase, std::memory_order_relaxed);
                }
                else if (Stage == "accept")
                {
                    PhaseMask.fetch_or(AcceptPhase, std::memory_order_relaxed);
                }
                else if (Stage == "auth")
                {
                    PhaseMask.fetch_or(AuthPhase, std::memory_order_relaxed);
                }
                else if (Stage == "dial")
                {
                    PhaseMask.fetch_or(DialPhase, std::memory_order_relaxed);
                }
                else if (Stage == "relay")
                {
                    PhaseMask.fetch_or(RelayPhase, std::memory_order_relaxed);
                }
                else if (Stage == "carrier_probe")
                {
                    PhaseMask.fetch_or(CarrierProbePhase, std::memory_order_relaxed);
                }
                else if (Stage == "carrier_commit")
                {
                    PhaseMask.fetch_or(CarrierCommitPhase, std::memory_order_relaxed);
                }
            }

            [[nodiscard]] auto PhaseSequence() const -> std::string
            {
                const auto Mask = PhaseMask.load(std::memory_order_relaxed);
                std::string Result;
                if ((Mask & CarrierProbePhase) != 0U)
                {
                    Result.append("carrier_probe");
                }
                if ((Mask & CarrierCommitPhase) != 0U)
                {
                    if (!Result.empty())
                    {
                        Result.push_back('>');
                    }
                    Result.append("carrier_commit");
                }
                if ((Mask & RecognitionPhase) != 0U)
                {
                    if (!Result.empty())
                    {
                        Result.push_back('>');
                    }
                    Result.append("recognition");
                }
                if ((Mask & AcceptPhase) != 0U)
                {
                    if (!Result.empty())
                    {
                        Result.push_back('>');
                    }
                    Result.append("accept");
                }
                if ((Mask & AuthPhase) != 0U)
                {
                    if (!Result.empty())
                    {
                        Result.push_back('>');
                    }
                    Result.append("auth");
                }
                if ((Mask & DialPhase) != 0U)
                {
                    if (!Result.empty())
                    {
                        Result.push_back('>');
                    }
                    Result.append("dial");
                }
                if ((Mask & RelayPhase) != 0U)
                {
                    if (!Result.empty())
                    {
                        Result.push_back('>');
                    }
                    Result.append("relay");
                }
                if (Result.empty())
                {
                    Result = "none";
                }
                return Result + ">close";
            }

            auto LogClose() noexcept -> void
            {
                if (CloseLogged.exchange(true, std::memory_order_acq_rel))
                {
                    return;
                }
                if (Logger && Trace)
                {
                    try
                    {
                        const auto Elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                  std::chrono::steady_clock::now() - StartedAt)
                                                  .count();
                        Trace->SetStage("close");
                        Trace->SetStatus(std::string(Preview::Fault::Describe(FinalCode)));
                        Trace->SetFaultCode(std::string(Preview::Fault::Describe(FinalCode)));
                        Trace->SetElapsedMs(static_cast<std::uint64_t>(Elapsed));
                        const auto Message = std::string("event=session_closed status=") +
                                             std::string(Preview::Fault::Describe(FinalCode)) +
                                             " elapsed_ms=" + std::to_string(Elapsed) +
                                             " phase_sequence=" + PhaseSequence();
                        (void)Logger->TryWrite(
                            Preview::Diagnose::LogLevel::Access, Message, Trace->Snapshot());
                    }
                    catch (...)
                    {
                    }
                }
                Logger.reset();
            }
        };

    public:
        /**
         * @brief 构造
         * @param Options 编排选项
         */
        explicit Session(SessionOptions Options)
            : Opts_(std::move(Options)), Services_(Opts_.Services),
              Control_(Opts_.Control ? Opts_.Control : std::make_shared<SessionControl>()),
              Active_(std::make_shared<ActiveTransports>())
        {
        }

        /**
         * @brief 获取 owner-held 会话控制器
         */
        [[nodiscard]] auto Control() const noexcept -> std::shared_ptr<SessionControl>
        {
            return Control_;
        }

        /**
         * @brief 获取 owner-held 服务上下文
         */
        [[nodiscard]] auto Services() const noexcept -> SharedSessionServices
        {
            return Services_;
        }

        /**
         * @brief 请求会话取消
         */
        void Cancel() noexcept
        {
            Control_->Cancel();
        }

        /**
         * @brief exactly-once 关闭当前会话传输
         */
        void Close()
        {
            const auto Active = Active_;
            (void)Control_->CloseOnce([Active] { CloseActive(Active); });
        }

        /**
         * @brief 运行会话
         * @param Inbound 入站传输
         * @return 最终错误码（success = 隧道正常结束）
         */
        [[nodiscard]] auto Run(
            Preview::SharedTransmission Inbound) -> Net::awaitable<Preview::Fault::Code>
        {
            const auto LogState = std::make_shared<SessionLogState>();
            try
            {
                const auto Result = co_await RunCore(std::move(Inbound), LogState);
                LogState->FinalCode = Result;
                CloseAndLog(Control_, Active_, LogState);
                co_return Result;
            }
            catch (...)
            {
                LogState->FinalCode = Preview::Fault::Code::IoError;
                CloseAndLog(Control_, Active_, LogState);
                throw;
            }
        }

        [[nodiscard]] auto RunCore(
            Preview::SharedTransmission Inbound,
            const std::shared_ptr<SessionLogState> &LogState) -> Net::awaitable<Preview::Fault::Code>
        {
            if (Inbound)
            {
                (void)Control_->Bind(Inbound->Executor());
            }
            Active_->Inbound = Inbound;

            auto *Routes = Services_ && Services_->Routes ? Services_->Routes.get() : Opts_.routes;
            auto *Scheme = Services_ && Services_->Scheme ? Services_->Scheme.get() : Opts_.Scheme;
            const auto Auth = Services_ && Services_->Auth ? Services_->Auth : Opts_.Auth;
            const auto &RelayIdleTimeout = Services_ ? Services_->RelayIdleTimeout
                                                     : Opts_.RelayIdleTimeout;
            const auto AcceptProtocol = Services_ && Services_->AcceptProtocol
                                             ? Services_->AcceptProtocol
                                             : Opts_.AcceptProtocol;
            const auto Profile = Services_ && Services_->Profile ? Services_->Profile : Opts_.Profile;
            const auto ResolveCandidate = Services_ && Services_->ResolveCandidate
                                              ? Services_->ResolveCandidate
                                              : Opts_.ResolveCandidate;
            const auto ResolverAlias = Services_ && Services_->Resolver
                                            ? Services_->Resolver
                                            : Opts_.Resolver;
            const auto Prepare = Services_ && Services_->Prepare ? Services_->Prepare : Opts_.Prepare;
            const auto Mux = Services_ && Services_->Mux ? Services_->Mux : Opts_.mux;
            auto *Pad = Services_ && Services_->Pad ? Services_->Pad.get() : Opts_.pad;
            const auto Dial = Services_ && Services_->Dial ? Services_->Dial : Opts_.Dial;
            const auto UdpService = Services_ && Services_->UdpService
                                        ? Services_->UdpService
                                        : Opts_.udp_service;
            auto *Traffic = Services_ && Services_->Traffic ? Services_->Traffic.get() : Opts_.traffic;

            const auto LoggerOwner = Services_ ? Services_->Logger : Preview::Diagnose::Logger::Owner{};
            const auto Trace = std::make_shared<Preview::Diagnose::TraceContext>(
                Services_ ? Services_->TraceSelection : Preview::Statistics::TraceSelection{});
            auto Cancellation = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
                Inbound->Executor(), 1);
            LogState->Logger = LoggerOwner;
            LogState->Trace = Trace;
            const auto Identity = Control_->CurrentIdentity();
            if (Identity.WorkerId)
            {
                Trace->SetWorker(Identity.WorkerId);
            }
            if (Identity.SessionId)
            {
                Trace->SetSession(Identity.SessionId);
            }
            if (Identity.TaskId)
            {
                Trace->SetCorrelation(Preview::RequestId{Identity.TaskId.Value()});
            }
            if (Identity.TaskId)
            {
                Trace->SetTask(Identity.TaskId);
            }
            if (Identity.Generation)
            {
                Trace->SetGeneration(Identity.Generation);
            }
            const auto WriteLog = [LoggerOwner, Trace](
                                       const Preview::Diagnose::LogLevel Level,
                                       const std::string_view Message) noexcept
            {
                if (LoggerOwner)
                {
                    (void)LoggerOwner->TryWrite(Level, Message, Trace->Snapshot());
                }
            };

            const auto WriteStage = [&WriteLog, Trace, LogState](const Preview::Diagnose::LogLevel Level,
                                                          const std::string_view Stage,
                                                          const std::string_view Outcome) noexcept
            {
                LogState->MarkStage(Stage);
                Trace->SetStage(std::string(Stage));
                Trace->SetStatus(std::string(Outcome));
                try
                {
                    const auto Message = FormatStageLog(Stage, Outcome);
                    WriteLog(Level, Message);
                }
                catch (...)
                {
                }
            };

            const auto WriteRecognition = [&WriteLog, Trace, Identity, LogState, Profile](
                                              const Preview::Diagnose::LogLevel Level,
                                              const std::string_view Stage,
                                              const Preview::Recognition::RecognizeResult &Result,
                                              const Preview::Fault::Code FaultCode) noexcept
            {
                const auto EffectiveFaultCode = Result.FaultCode == Preview::Fault::Code::Success
                                                    ? FaultCode
                                                    : Result.FaultCode;
                const bool CarrierFailure = !Result.Carrier.Carrier.empty() &&
                                            Preview::Fault::Failed(EffectiveFaultCode);
                const auto DiagnosticStage = CarrierFailure ? std::string_view{"carrier_commit"} : Stage;
                const auto Status = CarrierFailure
                                        ? ClassifyCarrierFailure(EffectiveFaultCode,
                                                                 Result.NativeError)
                                        : Preview::Recognition::ToStringView(Result.Status);
                LogState->MarkStage(DiagnosticStage);
                Trace->SetStage(std::string(DiagnosticStage));
                Trace->SetStatus(std::string(Status));
                Trace->SetProtocol(
                    std::string(Preview::Recognition::ToStringView(Result.detected)));
                if (!Result.Carrier.Carrier.empty())
                {
                    Trace->SetCarrier(Result.Carrier.Carrier);
                }
                else if (!Result.scheme.empty() && Result.scheme != Result.CandidateName)
                {
                    Trace->SetCarrier(Result.scheme);
                }
                if (!Result.Carrier.Sni.empty())
                {
                    Trace->SetSni(Result.Carrier.Sni);
                }
                if (!Result.Carrier.Alpn.empty())
                {
                    Trace->SetAlpn(Result.Carrier.Alpn);
                }
                if (!Result.Carrier.TlsVersion.empty())
                {
                    Trace->SetTlsVersion(Result.Carrier.TlsVersion);
                }
                Trace->SetFaultCode(std::string(Preview::Fault::Describe(EffectiveFaultCode)));
                if (Result.NativeError)
                {
                    Trace->SetNativeError(Result.NativeError.message());
                }
                else if (Result.Error)
                {
                    Trace->SetNativeError(Result.Error.message());
                }
                try
                {
                    auto Message = FormatRecognitionLog(
                        DiagnosticStage, Result, EffectiveFaultCode, Identity);
                    Message.insert(
                        0,
                        "mode=" +
                            std::string(Profile ? Preview::Recognition::ToStringView(Profile->Mode())
                                                : "legacy") +
                            " ");
                    if (CarrierFailure)
                    {
                        Message.insert(0, "event=" + std::string(Status) + " ");
                    }
                    WriteLog(Level, Message);
                }
                catch (...)
                {
                }
            };

            (void)Control_->AddCancelHook(
                [Control = Control_, Active = Active_, LogState, Cancellation]
                {
                    CloseAndLog(Control, Active, LogState);
                    (void)Cancellation->try_send(boost::system::error_code{});
                });

            WriteLog(Preview::Diagnose::LogLevel::Info, "event=session_started");

            Preview::Recognition::RecognizeResult PreRecognition;
            if (Services_ && Services_->NativeTls && (!Profile || !Profile->HasTlsCandidate()))
            {
                WriteStage(Preview::Diagnose::LogLevel::Info, "carrier_probe", "started");
                const auto HandshakeDeadline = std::chrono::steady_clock::now() +
                                               Services_->HandshakeTimeout;
                auto ProbeResult = co_await Preview::Recognition::RawIngressProbe::Run(
                    Preview::Recognition::RawIngressProbeRequest{
                        Inbound, Services_->HandshakeTimeout});
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
                    Trace->SetStage("carrier_probe");
                    Trace->SetStatus(std::string(Outcome));
                    Trace->SetFaultCode(std::string(Preview::Fault::Describe(FailureCode)));
                    if (ProbeResult.NativeError)
                    {
                        Trace->SetNativeError(ProbeResult.NativeError.message());
                    }
                    WriteLog(Preview::Diagnose::LogLevel::Warn,
                             std::string("event=") + std::string(Outcome) +
                                 " stage=carrier_probe");
                    co_return FailureCode;
                }

                Inbound = std::move(ProbeResult.Transport);
                Active_->Inbound = Inbound;
                if (ProbeResult.Kind == Preview::Recognition::RawIngressKind::Cleartext)
                {
                    WriteStage(Preview::Diagnose::LogLevel::Info,
                               "carrier_probe", "cleartext");
                }
                else
                {
                    RecordClientHello(Trace, ProbeResult.ClientHello);
                    WriteStage(Preview::Diagnose::LogLevel::Info,
                               "carrier_commit", "started");
                    auto TlsResult = co_await Preview::Transport::UpgradeNativeTls(
                        Preview::Transport::NativeTlsRequest{
                            std::move(Inbound), Services_->NativeTls,
                            HandshakeDeadline - std::chrono::steady_clock::now()});
                    if (Preview::Fault::Failed(TlsResult.Code) || !TlsResult.Transport ||
                        !TlsResult.Attempted)
                    {
                        const auto FailureCode = TlsResult.Code == Preview::Fault::Code::Success
                                                     ? Preview::Fault::Code::ProtocolError
                                                     : TlsResult.Code;
                        const auto Outcome = ClassifyNativeTlsFailure(TlsResult);
                        Trace->SetStage("carrier_commit");
                        Trace->SetStatus(std::string(Outcome));
                        Trace->SetFaultCode(
                            std::string(Preview::Fault::Describe(FailureCode)));
                        if (TlsResult.NativeError)
                        {
                            Trace->SetNativeError(TlsResult.NativeError.message());
                        }
                        WriteLog(Preview::Diagnose::LogLevel::Warn,
                                 std::string("event=") + std::string(Outcome) +
                                     " stage=carrier_commit");
                        co_return FailureCode;
                    }
                    Inbound = std::move(TlsResult.Transport);
                    Active_->Inbound = Inbound;
                    RecordTlsNegotiation(Trace, Inbound);
                    WriteStage(Preview::Diagnose::LogLevel::Info,
                               "carrier_commit", "success");
                }
            }

            // 1. 协议识别（预读回注）
            Preview::Recognition::Pipeline Recognizer(Routes, Scheme);
            if (Profile)
            {
                Recognizer = Preview::Recognition::Pipeline(Profile);
            }
            Preview::Recognition::RecognitionControl RecognitionControl;
            RecognitionControl.Cancelled = [Control = Control_]
            {
                return Control->IsCancelled();
            };
            RecognitionControl.Wait = [Cancellation]()
                -> Net::awaitable<Preview::Recognition::RecognitionControlEvent>
            {
                co_await Cancellation->async_receive(Net::use_awaitable);
                co_return Preview::Recognition::RecognitionControlEvent::Cancelled;
            };
            RecognitionControl.CancelTransport = [Active = Active_]
            {
                CloseActive(Active);
            };
            RecognitionControl.WaitCancellationSafe = true;
            Preview::Recognition::ProbeBuffer Probe(
                Profile ? Profile->Budget().MaxProbeBytes
                        : Preview::Recognition::MaxTlsClientHelloBytes);
            auto Res = co_await Recognizer.Recognize(
                std::move(Inbound), Probe, std::move(RecognitionControl));
            Active_->Inbound = Res.transport ? Res.transport : Active_->Inbound;
            if (Res.Cancelled || Control_->IsCancelled())
            {
                WriteRecognition(Preview::Diagnose::LogLevel::Info, "recognition", Res,
                                 Preview::Fault::Code::Canceled);
                co_return Preview::Fault::Code::Canceled;
            }
            if (Profile)
            {
                auto Candidate = Res.Candidate;
                if (Candidate == Preview::Recognition::InvalidCandidate)
                {
                    Candidate = Profile->ConfiguredCandidate();
                }
                if (Candidate == Preview::Recognition::InvalidCandidate &&
                    Profile->CandidateCount() != 0U)
                {
                    Candidate = Profile->CandidateIdAt(0);
                }
                if (Res.CandidateName.empty())
                {
                    Res.CandidateName = Profile->CandidateName(Candidate);
                }
                if (Res.detected == Preview::Recognition::ProtocolType::Unknown)
                {
                    Res.detected = Profile->CandidateProtocol(Candidate);
                }
                const auto Handle = Profile->FindCandidate(Candidate);
                if (Handle.IsValid())
                {
                    Res.Candidate = Candidate;
                }
                Res.Candidate = Candidate;
            }
            if (Res.success && !Res.Carrier.Carrier.empty())
            {
                RecordTlsNegotiation(Trace, Res.transport);
            }
            WriteRecognition(Res.success ? Preview::Diagnose::LogLevel::Info
                                         : Preview::Diagnose::LogLevel::Warn,
                             "recognition", Res,
                             Res.success ? Preview::Fault::Code::Success : Preview::Fault::Code::ProtocolError);
            SessionOptions::ProtocolAcceptFn Acceptor;
            if (Profile)
            {
                if (!Res.success || Res.Status != Preview::Recognition::RecognitionStatus::Accepted ||
                    Res.Candidate == Preview::Recognition::InvalidCandidate)
                {
                    const auto FailureCode = Res.FaultCode == Preview::Fault::Code::Success
                                                 ? Preview::Fault::Code::ProtocolError
                                                 : Res.FaultCode;
                    if (Res.Carrier.Carrier.empty())
                    {
                        WriteRecognition(Preview::Diagnose::LogLevel::Warn, "accept", Res,
                                         FailureCode);
                    }
                    co_return FailureCode;
                }
                SessionOptions::ResolveCandidateFn CandidateResolver;
                if (ResolveCandidate)
                {
                    CandidateResolver = ResolveCandidate;
                }
                else
                {
                    CandidateResolver = ResolverAlias;
                }
                if (CandidateResolver)
                {
                    Acceptor = CandidateResolver(Res.Candidate);
                }
                if (!Acceptor)
                {
                    WriteRecognition(Preview::Diagnose::LogLevel::Warn, "accept", Res,
                                     Preview::Fault::Code::ProtocolError);
                    co_return Preview::Fault::Code::ProtocolError;
                }
            }
            else
            {
                // 协议专用 listener：已配置 AcceptProtocol 时，recognition 仅负责预读回注，
                // 是否识别成功交给 AcceptProtocol 决定（Trojan/SS2022 等首字节不可识别）。
                if (!AcceptProtocol &&
                    (!Res.success || Res.detected == Preview::Recognition::ProtocolType::Unknown))
                {
                    WriteRecognition(Preview::Diagnose::LogLevel::Warn, "accept", Res,
                                     Preview::Fault::Code::ProtocolError);
                    co_return Preview::Fault::Code::ProtocolError;
                }
                Acceptor = AcceptProtocol;
            }

            // 2. 上下文装配
            Preview::Middleware::Context ctx;
            ctx.detected = static_cast<std::uint16_t>(Res.detected);
            ctx.Inbound = std::move(Res.transport);
            ctx.TaskIdentity = Control_->CurrentIdentity();
            ctx.Control = Control_;
            Active_->Inbound = ctx.Inbound;
            ctx.traffic = Traffic;
            ctx.pad = Pad;
            if (Acceptor)
            {
                const auto Ec = co_await Acceptor(ctx.Inbound, ctx);
                Active_->Inbound = ctx.Inbound;
                if (Preview::Fault::Failed(Ec))
                {
                    WriteRecognition(Preview::Diagnose::LogLevel::Warn, "accept", Res, Ec);
                    co_return Ec;
                }
            }
            WriteStage(Preview::Diagnose::LogLevel::Info, "accept", "success");
            if (Prepare)
            {
                const auto Ec = co_await Prepare(Res, ctx);
                if (Preview::Fault::Failed(Ec))
                {
                    Active_->Inbound = ctx.Inbound;
                    WriteRecognition(Preview::Diagnose::LogLevel::Warn, "prepare", Res, Ec);
                    co_return Ec;
                }
            }

            // 3. 将旧入口一次性物化为 typed 根数据面；后续流程不读取旧标志。
            auto DatagramService = UdpService;
            ctx.MaterializeDataPlane(std::move(DatagramService));

            if (ctx.DataPlane.IsMux())
            {
                if (!Mux)
                {
                    Active_->Inbound = ctx.Inbound;
                    WriteRecognition(Preview::Diagnose::LogLevel::Warn, "mux", Res,
                                     Preview::Fault::Code::NotSupported);
                    co_return Preview::Fault::Code::NotSupported;
                }
                WriteStage(Preview::Diagnose::LogLevel::Info, "mux", "started");
                const auto Accepted = co_await Mux(ctx.Inbound, ctx);
                Active_->Inbound = ctx.Inbound;
                ctx.SynchronizeDataPlane();
                if (!Accepted)
                {
                    WriteRecognition(Preview::Diagnose::LogLevel::Warn, "mux", Res,
                                     Preview::Fault::Code::BadGateway);
                    co_return Preview::Fault::Code::BadGateway;
                }
                WriteStage(Preview::Diagnose::LogLevel::Info, "mux", "success");
                co_return Preview::Fault::Code::Success;
            }

            // 4. Datagram 会话（替代 Dial/relay 编排）
            if (const auto *Datagram = ctx.DataPlane.Datagram())
            {
                if (!Datagram->Service)
                {
                    Active_->Inbound = ctx.Inbound;
                    WriteRecognition(Preview::Diagnose::LogLevel::Warn, "relay", Res,
                                     Preview::Fault::Code::NotSupported);
                    co_return Preview::Fault::Code::NotSupported;
                }
                WriteStage(Preview::Diagnose::LogLevel::Info, "relay", "started");
                const auto DatagramEc = co_await Datagram->Service(ctx);
                if (Preview::Fault::Failed(DatagramEc))
                {
                    WriteRecognition(Preview::Diagnose::LogLevel::Warn, "relay", Res, DatagramEc);
                }
                else
                {
                    WriteStage(Preview::Diagnose::LogLevel::Info, "relay", "success");
                }
                co_return DatagramEc;
            }

            // 5. 认证 + 多路复用 + 拨号（不含 relay）
            if (!Profile && AcceptProtocol && Auth && !ctx.ProtocolAuthenticated)
            {
                // 未完成协议认证的 legacy adapter 仍需提供 RawIdentity/RawSecret，
                // 否则通用 Auth 中间件会拒绝该会话。
                Preview::Diagnose::Warn("AcceptProtocol 与 Auth 中间件同时配置："
                                        "未认证 adapter 必须回填 RawIdentity/RawSecret");
            }
            // 协议 handler 已完成凭据校验时，协议认证是本会话的权威认证结果；
            // 只有未提供协议认证的入口才执行通用 Auth，避免二次认证清空 identity/lease。
            if (Auth && !ctx.ProtocolAuthenticated)
            {
                WriteStage(Preview::Diagnose::LogLevel::Info, "auth", "started");
                Preview::Middleware::Builtin::AuthMiddleware AuthMiddleware(Auth);
                const auto AuthEc = co_await AuthMiddleware.Handle(ctx.Inbound, ctx);
                if (Preview::Fault::Failed(AuthEc))
                {
                    Active_->Inbound = ctx.Inbound;
                    if (ctx.PostDial)
                    {
                        co_await ctx.PostDial(AuthEc);
                    }
                    WriteRecognition(Preview::Diagnose::LogLevel::Warn, "auth", Res, AuthEc);
                    co_return AuthEc;
                }
                WriteStage(Preview::Diagnose::LogLevel::Info, "auth", "success");
            }
            else
            {
                WriteStage(Preview::Diagnose::LogLevel::Info, "auth", "skipped");
            }

            Preview::Middleware::Pipeline DecorationPipeline;
            DecorationPipeline.Add(std::make_shared<Preview::Middleware::Builtin::MuxMiddleware>(Mux));
            DecorationPipeline.Add(std::make_shared<Preview::Middleware::Builtin::PadMiddleware>());
            const auto DecorationEc = co_await DecorationPipeline.Run(ctx.Inbound, ctx);
            if (Preview::Fault::Failed(DecorationEc))
            {
                Active_->Inbound = ctx.Inbound;
                if (ctx.PostDial)
                {
                    co_await ctx.PostDial(DecorationEc);
                }
                WriteRecognition(Preview::Diagnose::LogLevel::Warn, "middleware", Res, DecorationEc);
                co_return DecorationEc;
            }

            WriteStage(Preview::Diagnose::LogLevel::Info, "dial", "started");
            Preview::Middleware::Pipeline DialPipeline;
            DialPipeline.Add(std::make_shared<Preview::Middleware::Builtin::DialMiddleware>(Dial));
            const auto DialEc = co_await DialPipeline.Run(ctx.Inbound, ctx);
            Active_->Inbound = ctx.Inbound;
            Active_->Outbound = ctx.Outbound;
            if (Preview::Fault::Failed(DialEc))
            {
                if (ctx.PostDial)
                {
                    co_await ctx.PostDial(DialEc);
                }
                WriteRecognition(Preview::Diagnose::LogLevel::Warn, "dial", Res, DialEc);
                co_return DialEc;
            }
            WriteStage(Preview::Diagnose::LogLevel::Info, "dial", "success");
            // 6. 拨号成功后发送协议级应答（如 SOCKS5 CONNECT success）
            if (ctx.PostDial)
            {
                co_await ctx.PostDial(Preview::Fault::Code::Success);
            }
            // 7. 双向转发
            Preview::Middleware::Builtin::RelayMiddleware relay(
                nullptr, RelayIdleTimeout);
            WriteStage(Preview::Diagnose::LogLevel::Info, "relay", "started");
            const auto RelayEc = co_await relay.Handle(ctx.Inbound, ctx);
            if (Preview::Fault::Failed(RelayEc))
            {
                WriteRecognition(Preview::Diagnose::LogLevel::Warn, "relay", Res, RelayEc);
            }
            else
            {
                WriteStage(Preview::Diagnose::LogLevel::Info, "relay", "success");
            }
            co_return RelayEc;
        }

    private:
        static auto ClassifyCarrierFailure(
            const Preview::Fault::Code Code,
            const boost::system::error_code &NativeError) -> std::string_view
        {
            if (Code == Preview::Fault::Code::Timeout)
            {
                return "tls_handshake_timeout";
            }
            if (Code == Preview::Fault::Code::Canceled)
            {
                return "cancelled";
            }
            if (Code == Preview::Fault::Code::Verifyfail || Code == Preview::Fault::Code::Certfail)
            {
                return "certificate_error";
            }
            if (Code == Preview::Fault::Code::AuthFailed)
            {
                return "carrier_auth_failed";
            }
            if (Code == Preview::Fault::Code::NotSupported)
            {
                return "wire_unavailable";
            }
            if (Code == Preview::Fault::Code::TlsHsfail)
            {
                return "tls_alert";
            }
            if (&NativeError.category() != &Net::error::get_ssl_category())
            {
                return "carrier_commit_failed";
            }

            const auto Message = NativeError.message();
            if (Message.find("certificate") != std::string::npos ||
                Message.find("Certificate") != std::string::npos ||
                Message.find("CERTIFICATE") != std::string::npos ||
                Message.find("unknown ca") != std::string::npos ||
                Message.find("UNKNOWN_CA") != std::string::npos)
            {
                return "certificate_error";
            }
            return "tls_alert";
        }

        static auto ClassifyNativeTlsFailure(
            const Preview::Transport::NativeTlsResult &Result) -> std::string_view
        {
            return ClassifyCarrierFailure(Result.Code, Result.NativeError);
        }

        static auto RecordClientHello(
            const std::shared_ptr<Preview::Diagnose::TraceContext> &Trace,
            const Preview::Recognition::ClientHelloFeatures &Features) -> void
        {
            if (!Trace)
            {
                return;
            }
            Trace->SetCarrier("native");
            if (!Features.ServerName.empty())
            {
                Trace->SetSni(Features.ServerName);
            }
        }

        static auto RecordTlsNegotiation(
            const std::shared_ptr<Preview::Diagnose::TraceContext> &Trace,
            const Preview::SharedTransmission &Transport) -> void
        {
            auto *Encrypted = Transport
                                  ? dynamic_cast<Preview::Transport::Encrypted *>(Transport.get())
                                  : nullptr;
            if (!Trace || !Encrypted)
            {
                return;
            }
            auto *Ssl = Encrypted->Stream().native_handle();
            if (!Ssl)
            {
                return;
            }
            if (const auto *Version = SSL_get_version(Ssl); Version != nullptr)
            {
                Trace->SetTlsVersion(Version);
            }
            const unsigned char *Alpn = nullptr;
            unsigned int AlpnLength = 0;
            SSL_get0_alpn_selected(Ssl, &Alpn, &AlpnLength);
            if (Alpn != nullptr && AlpnLength != 0U)
            {
                Trace->SetAlpn(std::string(
                    reinterpret_cast<const char *>(Alpn), AlpnLength));
            }
        }

        static auto CloseAndLog(const std::shared_ptr<SessionControl> &Control,
                                const std::shared_ptr<ActiveTransports> &Active,
                                const std::shared_ptr<SessionLogState> &LogState) noexcept -> void
        {
            if (!Control)
            {
                return;
            }
            const auto CloseDelivered = std::make_shared<std::atomic<bool>>(false);
            const auto First = Control->CloseOnce(
                [Active, CloseDelivered]
                {
                    if (!CloseDelivered->exchange(true, std::memory_order_acq_rel))
                    {
                        CloseActive(Active);
                    }
                });
            if (First)
            {
                if (!CloseDelivered->exchange(true, std::memory_order_acq_rel))
                {
                    CloseActive(Active);
                }
                if (LogState)
                {
                    LogState->LogClose();
                }
            }
        }

        static auto FormatStageLog(const std::string_view Stage, const std::string_view Outcome)
            -> std::string
        {
            std::string Message;
            Message.reserve(32 + Stage.size() + Outcome.size());
            Message.append("stage=");
            Message.append(Stage);
            Message.append(" outcome=");
            Message.append(Outcome);
            return Message;
        }

        template <typename Id>
        static auto AppendId(std::string &Message, const std::string_view Name, const Id &Value) -> void
        {
            Message.append(Name);
            Message.append("=");
            Message.append(std::to_string(Value.Value()));
        }

        static auto FormatCandidateId(const Preview::Recognition::CandidateId Id) -> std::string
        {
            if (Id == Preview::Recognition::InvalidCandidate)
            {
                return "invalid";
            }
            return std::to_string(Id);
        }

        static auto SanitizeCandidateName(const std::string_view Value) -> std::string
        {
            constexpr std::size_t MaxLength = 64;
            std::string Result;
            Result.reserve((std::min)(Value.size(), MaxLength));
            for (const auto Character : Value)
            {
                if (Result.size() >= MaxLength)
                {
                    break;
                }
                const auto Byte = static_cast<unsigned char>(Character);
                if (Byte >= 0x21U && Byte <= 0x7EU && Character != '=' && Character != '[' &&
                    Character != ']' && Character != ';')
                {
                    Result.push_back(Character);
                }
                else
                {
                    Result.push_back('_');
                }
            }
            if (Result.empty())
            {
                return "none";
            }
            return Result;
        }

        static auto FormatErrorCode(const std::error_code &Error) -> std::string
        {
            if (!Error)
            {
                return "none";
            }
            std::string Result(Error.category().name());
            Result.push_back(':');
            Result.append(std::to_string(Error.value()));
            return Result;
        }

        static auto FormatFirstByte(const Preview::Recognition::RecognizeResult &Result) -> std::string
        {
            if (Result.preread.empty())
            {
                return "none";
            }
            constexpr char Hex[] = "0123456789ABCDEF";
            const auto Byte = std::to_integer<unsigned int>(Result.preread.front());
            std::string Value("0x00");
            Value[2] = Hex[(Byte >> 4U) & 0x0FU];
            Value[3] = Hex[Byte & 0x0FU];
            return Value;
        }

        static auto FormatRecognitionLog(
            const std::string_view Stage,
            const Preview::Recognition::RecognizeResult &Result,
            const Preview::Fault::Code FaultCode,
            const Preview::Lifecycle::TaskIdentity &Identity) -> std::string
        {
            const auto ProbeLength = Result.ProbeBytes == 0U ? Result.preread.size() : Result.ProbeBytes;
            std::string Message;
            Message.reserve(256 + Result.CandidateName.size());
            Message.append("stage=");
            Message.append(Stage);
            Message.append(" status=");
            Message.append(Preview::Recognition::ToStringView(Result.Status));
            Message.append(" candidate_id=");
            Message.append(FormatCandidateId(Result.Candidate));
            Message.append(" candidate_name=");
            Message.append(SanitizeCandidateName(Result.CandidateName));
            Message.append(" detected=");
            Message.append(Preview::Recognition::ToStringView(Result.detected));
            Message.append(" probe_bytes=");
            Message.append(std::to_string(Result.ProbeBytes));
            Message.append(" crypto_trials=");
            Message.append(std::to_string(Result.CryptoTrials));
            Message.append(" probe_first_byte=");
            Message.append(FormatFirstByte(Result));
            Message.append(" probe_length=");
            Message.append(std::to_string(ProbeLength));
            Message.append(" error_code=");
            Message.append(FormatErrorCode(Result.Error));
            Message.append(" fault_code=");
            Message.append(Preview::Fault::Describe(FaultCode));
            Message.push_back(' ');
            AppendId(Message, "worker_id", Identity.WorkerId);
            Message.push_back(' ');
            AppendId(Message, "session_id", Identity.SessionId);
            Message.push_back(' ');
            AppendId(Message, "correlation_id", Identity.TaskId);
            Message.push_back(' ');
            AppendId(Message, "generation_id", Identity.Generation);
            return Message;
        }

        static auto CloseActive(const std::shared_ptr<ActiveTransports> &Active) -> void
        {
            if (!Active)
            {
                return;
            }
            const auto Inbound = Active->Inbound;
            const auto Outbound = Active->Outbound;
            CloseTransport(Inbound);
            if (Outbound && Outbound != Inbound)
            {
                CloseTransport(Outbound);
            }
        }

        static auto CloseTransport(Preview::SharedTransmission Transport) -> void
        {
            if (Transport)
            {
                Transport->Cancel();
                Transport->Close();
            }
        }

        SessionOptions Opts_; ///< 编排选项
        SharedSessionServices Services_; ///< owner-held 服务上下文
        std::shared_ptr<SessionControl> Control_; ///< owner-held 生命周期控制
        std::shared_ptr<ActiveTransports> Active_; ///< 当前传输所有权
    };

} // namespace Preview::Runtime
