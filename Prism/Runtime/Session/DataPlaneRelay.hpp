/**
 * @file DataPlaneRelay.hpp
 * @brief typed data-plane、认证、拨号与双向中继 owner
 * @details admission 完成后，本 owner 只消费已经装配好的 Context；它负责
 *          mux/datagram 快路径和 stream 的 Auth/Pad/Dial/Relay 生命周期。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <memory>
#include <new>
#include <utility>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Runtime/Middleware/Builtin/Dial.hpp>
#include <Prism/Runtime/Middleware/Builtin/Pad.hpp>
#include <Prism/Runtime/Middleware/Builtin/Relay.hpp>
#include <Prism/Runtime/Middleware/Pipeline.hpp>
#include <Prism/Runtime/Session/ClosePolicy.hpp>
#include <Prism/Runtime/Session/CarrierInstallation.hpp>
#include <Prism/Runtime/Session/RunContext.hpp>

namespace Prism::Runtime
{

    namespace Net = boost::asio;

    /**
     * @class SessionDataPlaneRelay
     * @brief Session typed data-plane 执行 owner
     */
    class SessionDataPlaneRelay final
    {
    public:
        /**
         * @brief 执行 mux、datagram 或 stream 数据面
         * @param Run 已完成 admission 的会话上下文
         * @return 数据面最终 typed failure；code-only 内部服务在本层显式投影。
         */
        [[nodiscard]] static auto Run(SessionRunContext &Run)
            -> Net::awaitable<Prism::Fault::Failure>
        {
            auto &Context = Run.Context;
            const auto *InitialStreamData = Context.DataPlane.Stream();
            Run.HasOutboundDecorator =
                InitialStreamData && static_cast<bool>(InitialStreamData->OutboundDecorator);
            if (Context.DataPlane.IsMux())
            {
                co_return co_await RunMux(Run);
            }
            if (Context.DataPlane.Datagram())
            {
                co_return co_await RunDatagram(Run);
            }
            co_return co_await RunStream(Run);
        }

    private:
        [[nodiscard]] static auto RunMux(SessionRunContext &Run)
            -> Net::awaitable<Prism::Fault::Failure>
        {
            if (!Run.Services || !Run.Services->GenerationUseState)
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::Blocked};
            }
            auto* Plane = Run.Context.DataPlane.Mux();
            if (!Plane || !Plane->Session)
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::NotSupported};
            }
            const auto Owner = Plane->Session;
            Run.LogState->MarkStage("Relay");
            Prism::Contract::MuxRootRequest Request;
            Request.Lease = std::move(Run.Context.AccountLease());
            Request.GenerationUseState = Run.Services->GenerationUseState;
            Request.Metadata.TaskIdentity = Run.Context.TaskIdentity;
            Request.Metadata.SourceIp = Run.Context.SourceIp;
            if (Run.Services) Request.Metadata.Trace = Run.Services->ProcessContext;
            if (Run.Control)
            {
                try
                {
                    auto Catalog = std::make_shared<Prism::Contract::Ingress::StreamCatalog>();
                    if (Run.Control->AttachStreamCatalog(Catalog))
                    {
                        Request.StreamCatalogOwner = std::move(Catalog);
                    }
                }
                catch (const std::bad_alloc &)
                {
                    // 查询目录是可选观察能力；分配失败不改变已经接受的 mux 数据面。
                }
            }
            const auto MuxResult = co_await Owner->Run(std::move(Request));
            Owner->Close();
            if (!MuxResult)
            {
                co_return MuxResult.error();
            }
            co_return Prism::Fault::Failure{};
        }

        [[nodiscard]] static auto RunDatagram(SessionRunContext &Run)
            -> Net::awaitable<Prism::Fault::Failure>
        {
            auto *Datagram = Run.Context.DataPlane.Datagram();
            if (!Datagram || !Datagram->Session)
            {
                Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                    Prism::Diagnose::LogLevel::Warn, "relay", Run.Recognition,
                    Prism::Fault::Code::NotSupported, Run.Context.ProtocolNameForLog});
                co_return Prism::Fault::Failure{Prism::Fault::Code::NotSupported};
            }
            Run.LogState->MarkStage("Relay");
            const auto DatagramEc = co_await Datagram->Session->Run();
            Datagram->Session->Close();
            if (!DatagramEc)
            {
                Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                    Prism::Diagnose::LogLevel::Warn, "relay", Run.Recognition,
                    DatagramEc.error().Code,
                    Run.Context.ProtocolNameForLog});
            }
            if (!DatagramEc) co_return DatagramEc.error();
            co_return Prism::Fault::Failure{};
        }

        [[nodiscard]] static auto RunStream(SessionRunContext &Run)
            -> Net::awaitable<Prism::Fault::Failure>
        {
            auto &Context = Run.Context;
            Run.LogState->MarkStage("Authentication");

            Prism::Middleware::Builtin::PadMiddleware Decoration;
            const auto DecorationFailure = co_await Decoration.Handle(Context.Inbound(), Context);
            if (DecorationFailure.Failed())
            {
                const auto Stored = SessionCarrierInstallation::Inbound(*Run.Active, Context.Inbound());
                if (!Stored)
                {
                    ReportCarrierInstallationFailure(Run, Stored.error());
                    Context.PostDial() = {};
                }
                else
                {
                    const auto ReplyFailure = co_await InvokePostDial(Context, DecorationFailure);
                    if (ReplyFailure.Failed())
                    {
                        Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                            Prism::Diagnose::LogLevel::Warn, "response", Run.Recognition, ReplyFailure.Code,
                            Context.ProtocolNameForLog});
                    }
                }
                Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                    Prism::Diagnose::LogLevel::Warn, "middleware", Run.Recognition, DecorationFailure.Code,
                    Context.ProtocolNameForLog});
                co_return DecorationFailure;
            }
            Run.Logger.WriteRequestInfo(Context);
            Run.LogState->MarkStage("Dial");
            co_return co_await RunDialAndRelay(Run);
        }

        [[nodiscard]] static auto RunDialAndRelay(SessionRunContext &Run)
            -> Net::awaitable<Prism::Fault::Failure>
        {
            auto &Context = Run.Context;
            Prism::Middleware::Builtin::DialMiddleware Dial(Run.Dial);
            if (Run.TraceWriter)
            {
                Run.TraceWriter->Record(SessionTraceStage::OutboundResolveDialStarted);
            }
            const auto DialFailure = co_await Dial.Handle(Context.Inbound(), Context);
            if (Run.TraceWriter)
            {
                Run.TraceWriter->Record(SessionTraceStage::OutboundResolveDialCompleted,
                                        DialFailure.Code);
            }
            const auto InboundStored = SessionCarrierInstallation::Inbound(*Run.Active, Context.Inbound());
            if (!InboundStored) ReportCarrierInstallationFailure(Run, InboundStored.error());
            if (DialFailure.Failed())
            {
                const auto OutboundStored = SessionCarrierInstallation::Outbound(*Run.Active, Context.Outbound);
                if (!OutboundStored) ReportCarrierInstallationFailure(Run, OutboundStored.error());
                if (!InboundStored || !OutboundStored)
                {
                    Context.PostDial() = {};
                }
                else
                {
                    const auto ReplyFailure = co_await InvokePostDial(Context, DialFailure);
                    if (ReplyFailure.Failed())
                    {
                        Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                            Prism::Diagnose::LogLevel::Warn, "response", Run.Recognition, ReplyFailure.Code,
                            Context.ProtocolNameForLog});
                    }
                }
                Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                    Prism::Diagnose::LogLevel::Warn, "dial", Run.Recognition, DialFailure.Code,
                    Context.ProtocolNameForLog});
                co_return DialFailure;
            }
            if (!InboundStored)
            {
                const auto OutboundStored = SessionCarrierInstallation::Outbound(*Run.Active, Context.Outbound);
                if (!OutboundStored) ReportCarrierInstallationFailure(Run, OutboundStored.error());
                Context.PostDial() = {};
                co_return InboundStored.error();
            }

            if (Run.HasOutboundDecorator && !ApplyOutboundDecorator(Run))
            {
                const auto Stored = SessionCarrierInstallation::Outbound(*Run.Active, Context.Outbound);
                const Prism::Fault::Failure DecoratorFailure{Prism::Fault::Code::IoError};
                if (!Stored)
                {
                    ReportCarrierInstallationFailure(Run, Stored.error());
                    Context.PostDial() = {};
                }
                else
                {
                    const auto ReplyFailure = co_await InvokePostDial(Context, DecoratorFailure);
                    if (ReplyFailure.Failed())
                    {
                        Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                            Prism::Diagnose::LogLevel::Warn, "response", Run.Recognition, ReplyFailure.Code,
                            Context.ProtocolNameForLog});
                    }
                }
                Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                    Prism::Diagnose::LogLevel::Warn, "response", Run.Recognition,
                    Prism::Fault::Code::IoError, Context.ProtocolNameForLog});
                co_return DecoratorFailure;
            }
            const auto Stored = SessionCarrierInstallation::Outbound(*Run.Active, Context.Outbound);
            if (!Stored)
            {
                ReportCarrierInstallationFailure(Run, Stored.error());
                Context.PostDial() = {};
                co_return Stored.error();
            }
            const auto ReplyFailure = co_await InvokePostDial(Context, Prism::Fault::Failure{});
            if (ReplyFailure.Failed())
            {
                Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                    Prism::Diagnose::LogLevel::Warn, "response", Run.Recognition, ReplyFailure.Code,
                    Context.ProtocolNameForLog});
                SessionClosePolicy::CloseActive(Run.Active);
                co_return ReplyFailure;
            }

            Prism::Middleware::Builtin::RelayMiddleware Relay(nullptr, Run.RelayIdleTimeout);
            Run.LogState->MarkStage("Relay");
            if (Run.TraceWriter)
            {
                Run.TraceWriter->Record(SessionTraceStage::RelayStarted);
            }
            const auto RelayFailure = co_await Relay.Handle(Context.Inbound(), Context);
            if (Run.TraceWriter)
            {
                Run.TraceWriter->Record(SessionTraceStage::RelayCompleted, RelayFailure.Code);
            }
            if (RelayFailure.Failed())
            {
                Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                    Prism::Diagnose::LogLevel::Warn, "relay", Run.Recognition, RelayFailure.Code,
                    Context.ProtocolNameForLog});
            }
            co_return RelayFailure;
        }

        [[nodiscard]] static auto ApplyOutboundDecorator(SessionRunContext &Run) -> bool
        {
            auto &Context = Run.Context;
            const auto RawOutbound = Context.Outbound;
            const auto *CurrentStreamData = Context.DataPlane.Stream();
            if (CurrentStreamData && CurrentStreamData->OutboundDecorator)
            {
                const auto &Decorator = CurrentStreamData->OutboundDecorator;
                Context.Outbound = Decorator(std::move(Context.Outbound));
                if (Context.Outbound)
                {
                    return true;
                }
            }
            if (RawOutbound)
            {
                Context.Outbound = RawOutbound;
            }
            return false;
        }

        static auto ReportCarrierInstallationFailure(
            SessionRunContext &Run,
            const Prism::Fault::Failure &Failure) -> void
        {
            Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                Prism::Diagnose::LogLevel::Warn, "carrier", Run.Recognition, Failure.Code,
                Run.Context.ProtocolNameForLog});
        }

        [[nodiscard]] static auto InvokePostDial(
            Prism::Middleware::Context &Context,
            Prism::Fault::Failure Status) -> Net::awaitable<Prism::Fault::Failure>
        {
            auto Callback = std::move(Context.PostDial());
            Context.PostDial() = {};
            if (!Callback)
            {
                co_return Prism::Fault::Failure{};
            }
            co_return co_await Callback(Status);
        }
    };

} // namespace Prism::Runtime
