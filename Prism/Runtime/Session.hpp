/**
 * @file Session.hpp
 * @brief 会话编排（T4-2）
 * @details 按 compiled Profile 识别候选，或直接消费显式工厂：
 *          1. StreamFactory 完成协议握手与认证，移交唯一正式数据面
 *          2. Session 按根类型运行数据报、Mux，或 Dial → relay
 *          - 识别失败 / 未知协议 → protocol_error
 *          - 认证失败 → auth_failed（管线终止）
 *          - relay 结束点自动上报流量（traffic sink）
 * @note 协议工厂拥有认证；数据报的取消、drain 与最终关闭归协议 owner。
 */

#pragma once

#include <Prism/Contract/Ingress/StreamFactory.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <chrono>
#include <cstdint>
#include <format>
#include <functional>
#include <memory>
#include <new>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Runtime/Middleware/Builtin/Dial.hpp>
#include <Prism/Runtime/Middleware/Builtin/Pad.hpp>
#include <Prism/Runtime/Middleware/Builtin/Relay.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Runtime/Middleware/Pipeline.hpp>
#include <Prism/Runtime/Recognition/Recognition.hpp>
#include <Prism/Runtime/ActiveTransports.hpp>
#include <Prism/Runtime/SessionControl.hpp>
#include <Prism/Runtime/SessionServices.hpp>
#include <Prism/Runtime/SessionTraceRing.hpp>
#include <Prism/Runtime/Session/ClosePolicy.hpp>
#include <Prism/Runtime/Session/DataPlaneRelay.hpp>
#include <Prism/Runtime/Session/RecognitionLogging.hpp>
#include <Prism/Runtime/Session/RecognitionAdmission.hpp>
#include <Prism/Runtime/Session/RunContext.hpp>
#include <Prism/Runtime/Session/RecognitionLatencyScope.hpp>
#include <Prism/Lifecycle/TaskState.hpp>
#include <Prism/Transport/NativeTls.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Runtime
{

    namespace Net = boost::asio;

    /**
     * @struct SessionOptions
     * @brief 会话编排选项
     */
    struct SessionOptions
    {
        /// 明确拥有所有会话依赖；不支持裸服务回退字段。
        SharedSessionServices Services{std::make_shared<SessionServices>()};
        std::shared_ptr<SessionControl> Control{};
        std::string SourceIp;
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
        using SessionLogState = SessionSupport::SessionLogState;

    public:
        /**
         * @brief 构造
         * @param Options 编排选项
         */
        explicit Session(SessionOptions Options)
            : Opts_(std::move(Options)), Services_(Opts_.Services),
              Control_(Opts_.Control),
              Active_(std::make_shared<ActiveTransports>())
        {
            if (!Control_) Control_ = std::make_shared<SessionControl>();
        }

        ~Session()
        {
            if (!Drained_.load(std::memory_order_acquire) && DeferredCleanup_)
            {
                DeferredCleanup_->RequestRetirement();
            }
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
         * @brief 接管该 admission 从所选 generation 取得的唯一活动预约。
         * @details 只能在 worker tracked start 前调用一次；成功后 Session 独占租约，
         *          直到最终关闭交付、传输 Activity 与子 TaskRegistry 均真实 drain。
         *          此同步移动不投递 executor；失败时输入租约仍由调用方持有。
         */
        [[nodiscard]] auto SetGenerationUseLease(
            Prism::Foundation::GenerationUseLease Value) noexcept -> bool
        {
            if (!Value || GenerationUse_)
            {
                return false;
            }
            GenerationUse_ = std::move(Value);
            return true;
        }

        /** @brief 绑定提交前已存在的 admission cleanup owner，覆盖未启动任务的析构路径。 */
        auto SetDeferredCleanup(std::shared_ptr<Prism::Executor::ClosingResource> Value) -> void
        {
            DeferredCleanup_ = std::move(Value);
        }

        /**
         * @brief 在 tracked start 前移交唯一注册 token。
         * @details Session owner 持有 token 至最终传输关闭和 listener 错误投递结束；
         *          RunContext 只在当前 Run 内借用，不能提前退休 registry/hooks。
         */
        auto SetRegistration(SessionRegistry::Registration Value) -> void
        {
            Registration_ = std::move(Value);
        }

        /** @brief 在 tracked start 前绑定 worker-local 有界生命周期轨迹 writer。 */
        auto SetTraceWriter(std::shared_ptr<SessionTraceWriter> Value) noexcept -> void
        {
            TraceWriter_ = std::move(Value);
        }

        /**
         * @brief 请求会话取消
         */
        auto Cancel() -> std::expected<void, Prism::Fault::Failure>
        {
            return Control_->Cancel();
        }

        /**
         * @brief exactly-once 关闭当前会话传输
         */
        [[nodiscard]] auto Close() -> std::expected<void, Prism::Fault::Failure>
        {
            return Control_->CloseOnce();
        }

        /**
         * @brief 运行会话
         * @param Inbound 入站传输
         * @return 最终 typed failure；success 表示隧道正常结束。
         */
        [[nodiscard]] auto Run(
            Prism::SharedTransmission Inbound) -> Net::awaitable<Prism::Fault::Failure>
        {
            Drained_.store(false, std::memory_order_release);
            if (TraceWriter_)
            {
                TraceWriter_->SetTaskIdentity(Control_->CurrentIdentity());
                TraceWriter_->Record(SessionTraceStage::SessionStarted);
            }
            co_await Net::this_coro::throw_if_cancelled(false);
            const auto LogState = std::make_shared<SessionLogState>();
            Prism::Fault::Failure Result;
            auto CancellationReasonAtRunCompletion = SessionCancellationReason::None;
            try
            {
                Result = co_await RunCore(std::move(Inbound), LogState);
                CancellationReasonAtRunCompletion = Control_->CancellationReason();
            }
            catch (const boost::system::system_error &Error)
            {
                Result = Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error.code()));
                CancellationReasonAtRunCompletion = Control_->CancellationReason();
            }
            catch (const std::system_error &Error)
            {
                Result = Prism::Fault::FromNative(Error.code());
                CancellationReasonAtRunCompletion = Control_->CancellationReason();
            }
            catch (const std::bad_alloc &)
            {
                Result = Prism::Fault::Failure{
                    Prism::Fault::Code::ResourceUnavailable,
                    std::make_error_code(std::errc::not_enough_memory)};
                CancellationReasonAtRunCompletion = Control_->CancellationReason();
            }
            catch (...)
            {
                Result = Prism::Fault::Failure{Prism::Fault::Code::GenericError};
                CancellationReasonAtRunCompletion = Control_->CancellationReason();
            }
            LogState->FinalCode = Result.Code;
            const auto Closed = SessionClosePolicy::CloseAndLog({Control_, Active_, LogState});
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            const auto Delivered = co_await Control_->AwaitDelivery();
            const auto Retired = co_await Active_->Finalize();
            if (!Closed)
            {
                RecordClosed(Closed.error());
                co_return Closed.error();
            }
            if (!Delivered)
            {
                RecordClosed(Delivered.error());
                co_return Delivered.error();
            }
            if (!Retired)
            {
                RecordClosed(Retired.error());
                co_return Retired.error();
            }
            const auto ChildTasksDrained = co_await Control_->Drain();
            if (!ChildTasksDrained)
            {
                RecordClosed(ChildTasksDrained.error());
                co_return ChildTasksDrained.error();
            }
            Drained_.store(true, std::memory_order_release);
            const auto FinalCancellationReason=Control_->CancellationReason();
            // 只把已在 shutdown 期间观察到的取消视作正常终态，且须通过完整 drain。
            const auto FinalResult = Result.Code == Prism::Fault::Code::Canceled &&
                CancellationReasonAtRunCompletion == SessionCancellationReason::Shutdown &&
                FinalCancellationReason == SessionCancellationReason::Shutdown
                    ? Prism::Fault::Failure{}
                    : Result;
            RecordClosed(FinalResult);
            co_return FinalResult;
        }

        /** @brief 唯一表达关闭交付与 Activity 真实排空均已成功的会话事实。 */
        [[nodiscard]] auto IsDrained() const noexcept -> bool
        {
            return Drained_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto RunCore(
            Prism::SharedTransmission Inbound,
            const std::shared_ptr<SessionLogState> &LogState) -> Net::awaitable<Prism::Fault::Failure>
        {
            Net::any_io_executor SessionExecutor;
            if (Inbound) SessionExecutor = Inbound->Executor();
            if (Inbound)
            {
                // tracked task 可能由 worker executor 启动；会话状态先回到入站 executor。
                co_await Net::dispatch(SessionExecutor, Net::use_awaitable);
                (void)Control_->Bind(SessionExecutor);
            }
            if (!Inbound)
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument};
            }
            const auto Domain = CarrierDomain::Create(Inbound->Executor(), Inbound->Activity());
            if (!Domain) co_return Domain.error();
            auto Stored = Active_->StoreInbound(std::move(Inbound), *Domain);
            if (!Stored) co_return Stored.error();
            Inbound = std::move(*Stored);

            if (!Services_)
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument};
            }
            const auto RelayIdleTimeout = Services_->RelayIdleTimeout;
            const auto AcceptProtocol = Services_->AcceptProtocol;
            const auto Profile = Services_->Profile;
            const auto ResolveCandidate = Services_->ResolveCandidate;
            auto *Pad = Services_->Pad.get();
            const auto Dial = Services_->Dial;
            const auto Traffic = Services_->Traffic;
            const auto RecognitionLatency = Services_->RecognitionLatency;

            auto Trace = Services_->ProcessContext;
            const auto Identity = Control_->CurrentIdentity();
            if (TraceWriter_) TraceWriter_->SetTaskIdentity(Identity);
            if (Identity.WorkerId)
            {
                Trace = Trace.With(Prism::Diagnose::Fields::Worker, Identity.WorkerId);
            }
            if (Identity.SessionId)
            {
                Trace = Trace.With(Prism::Diagnose::Fields::Session, Identity.SessionId);
            }
            if (Identity.TaskId &&
                (!Identity.SessionId ||
                 Identity.TaskId.Value() != Identity.SessionId.Value()))
            {
                Trace = Trace.With(Prism::Diagnose::Fields::Task, Identity.TaskId);
            }
            if (Identity.Generation && Identity.Generation.Value() > 1U)
            {
                Trace = Trace.With(Prism::Diagnose::Fields::Generation, Identity.Generation);
            }
            LogState->Trace = Trace;

            auto Cancellation = std::make_shared<SessionCancellationChannel>(
                SessionExecutor, 1);
            SessionRunContext Run;
            Run.Services = Services_;
            Run.Registration = &Registration_;
            Run.Control = Control_;
            Run.TraceWriter = TraceWriter_;
            Run.Active = Active_;
            Run.LogState = LogState;
            Run.Cancellation = Cancellation;
            Run.Executor = SessionExecutor;
            Run.RelayIdleTimeout = RelayIdleTimeout;
            Run.AcceptProtocol = AcceptProtocol;
            Run.Profile = Profile;
            Run.ResolveCandidate = ResolveCandidate;
            Run.Pad = Pad;
            Run.Dial = Dial;
            Run.Traffic = Traffic;
            Run.RecognitionLatency = RecognitionLatency;
            Run.SourceIp = Opts_.SourceIp;
            Run.Inbound = std::move(Inbound);
            Run.Logger = SessionSupport::SessionLogWriter{LogState, Profile};
            Run.Context.FirstTransfer = TraceWriter_;

            const auto Installed = SessionClosePolicy::InstallCancelHook(
                SessionCancellationRequest{
                    Control_, Active_, LogState, Cancellation, SessionExecutor});
            if (!Installed) co_return Installed.error();

            Prism::Fault::Failure AdmissionEc;
            {
                Detail::RecognitionLatencyScope Measure(
                    Run.RecognitionLatency,
                    Prism::Foundation::RecognitionLatencySample{
                        .Generation = Identity.Generation,
                        .Worker = Identity.WorkerId,
                        .Session = Identity.SessionId});
                AdmissionEc = co_await SessionRecognitionAdmission::Run(Run);
            }
            if (AdmissionEc.Failed())
            {
                Run.ReleaseCarrierViews();
                (void)co_await Run.DrainAdmissionOwner();
                co_return Prism::Fault::Failure{AdmissionEc};
            }
            const auto RelayFailure = co_await SessionDataPlaneRelay::Run(Run);
            Run.ReleaseCarrierViews();
            const auto AdmissionRetirement = co_await Run.DrainAdmissionOwner();
            if (AdmissionRetirement.Failed() && !RelayFailure.Failed())
            {
                co_return AdmissionRetirement;
            }
            co_return RelayFailure;
        }


    private:
        auto RecordClosed(const Prism::Fault::Failure &Failure) noexcept -> void
        {
            if (TraceWriter_)
            {
                TraceWriter_->Record(SessionTraceStage::SessionClosed, Failure.Code);
            }
        }

        SessionOptions Opts_; ///< 编排选项
        SharedSessionServices Services_; ///< owner-held 服务上下文
        SessionRegistry::Registration Registration_; ///< owner-held registry token
        Prism::Foundation::GenerationUseLease GenerationUse_; ///< admission 到完整 Session drain 的唯一代次预约
        std::shared_ptr<SessionControl> Control_; ///< owner-held 生命周期控制
        std::shared_ptr<SessionTraceWriter> TraceWriter_; ///< worker-local 有界生命周期轨迹 writer
        std::shared_ptr<ActiveTransports> Active_; ///< 当前传输所有权
        std::atomic<bool> Drained_{false}; ///< Close、Control delivery、Activity Finalize 全部成功
        std::shared_ptr<Prism::Executor::ClosingResource> DeferredCleanup_;
    };

} // namespace Prism::Runtime
