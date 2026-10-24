/** @file SessionDataPlaneRelay.cpp @brief Session 类型化数据面生命周期实现。 */
#include <Prism/Runtime/Session/DataPlaneRelay.hpp>

#include <Prism/Runtime/Middleware/Builtin/Dial.hpp>
#include <Prism/Runtime/Middleware/Builtin/Pad.hpp>
#include <Prism/Runtime/Middleware/Builtin/Relay.hpp>
#include <Prism/Runtime/Session/CarrierInstallation.hpp>
#include <Prism/Runtime/Session/ClosePolicy.hpp>
#include <Prism/Runtime/Session/RunContext.hpp>

#include <memory>
#include <new>
#include <utility>

namespace Prism::Runtime
{
    auto SessionDataPlaneRelay::Run(SessionRunContext& Run)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        auto& Context = Run.Context;
        const auto* InitialStreamData = Context.DataPlane.Stream();
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

    auto SessionDataPlaneRelay::RunMux(SessionRunContext& Run)
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
            catch (const std::bad_alloc&)
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

    auto SessionDataPlaneRelay::RunDatagram(SessionRunContext& Run)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        auto* Datagram = Run.Context.DataPlane.Datagram();
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
                DatagramEc.error().Code, Run.Context.ProtocolNameForLog});
        }
        if (!DatagramEc) co_return DatagramEc.error();
        co_return Prism::Fault::Failure{};
    }

    auto SessionDataPlaneRelay::RunStream(SessionRunContext& Run)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        auto& Context = Run.Context;
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
                        Prism::Diagnose::LogLevel::Warn, "response", Run.Recognition,
                        ReplyFailure.Code, Context.ProtocolNameForLog});
                }
            }
            Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                Prism::Diagnose::LogLevel::Warn, "middleware", Run.Recognition,
                DecorationFailure.Code, Context.ProtocolNameForLog});
            co_return DecorationFailure;
        }
        Run.Logger.WriteRequestInfo(Context);
        Run.LogState->MarkStage("Dial");
        co_return co_await RunDialAndRelay(Run);
    }

    auto SessionDataPlaneRelay::RunDialAndRelay(SessionRunContext& Run)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        auto& Context = Run.Context;
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
                        Prism::Diagnose::LogLevel::Warn, "response", Run.Recognition,
                        ReplyFailure.Code, Context.ProtocolNameForLog});
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
                        Prism::Diagnose::LogLevel::Warn, "response", Run.Recognition,
                        ReplyFailure.Code, Context.ProtocolNameForLog});
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
                Prism::Diagnose::LogLevel::Warn, "response", Run.Recognition,
                ReplyFailure.Code, Context.ProtocolNameForLog});
            const auto Closed = SessionClosePolicy::CloseActive(Run.Active);
            if (!Closed && Closed.error().Code != ReplyFailure.Code)
            {
                Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
                    Prism::Diagnose::LogLevel::Warn, "close", Run.Recognition,
                    Closed.error().Code, Context.ProtocolNameForLog});
            }
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
                Prism::Diagnose::LogLevel::Warn, "relay", Run.Recognition,
                RelayFailure.Code, Context.ProtocolNameForLog});
        }
        co_return RelayFailure;
    }

    auto SessionDataPlaneRelay::ApplyOutboundDecorator(SessionRunContext& Run) -> bool
    {
        auto& Context = Run.Context;
        const auto RawOutbound = Context.Outbound;
        const auto* CurrentStreamData = Context.DataPlane.Stream();
        if (CurrentStreamData && CurrentStreamData->OutboundDecorator)
        {
            const auto& Decorator = CurrentStreamData->OutboundDecorator;
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

    auto SessionDataPlaneRelay::ReportCarrierInstallationFailure(
        SessionRunContext& Run,
        const Prism::Fault::Failure& Failure) -> void
    {
        Run.Logger.WriteRecognition(SessionSupport::RecognitionLogRequest{
            Prism::Diagnose::LogLevel::Warn, "carrier", Run.Recognition, Failure.Code,
            Run.Context.ProtocolNameForLog});
    }

    auto SessionDataPlaneRelay::InvokePostDial(
        Prism::Middleware::Context& Context,
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
}
