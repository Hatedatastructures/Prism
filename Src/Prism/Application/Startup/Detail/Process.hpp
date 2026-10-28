/**
 * @file Process.hpp
 * @brief Prism 启动阶段的独立资源装配责任。
 */
#pragma once
#include <Prism/Application/Application.hpp>
#include <Prism/Foundation/Utility/Text/TraceSelection.hpp>
#include <Prism/Application/Assembly/Dns.hpp>
#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Application/Shutdown/Detail/Shutdown.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>
#include <Prism/Application/Startup/Detail/Generation.hpp>
#include <algorithm>
namespace Prism::Application::Startup::ProcessServices
{
    namespace Net = boost::asio;
    namespace Assembly = Prism::Application::Assembly;
    namespace Provider = Prism::Composition::Provider;
    /** @brief 控制线程借用 generation 配置并在 runtime 中拥有日志、DNS 和会话服务；失败由事务关闭。 */
    inline auto Build(const std::shared_ptr<Application::RuntimeState>& Runtime,
        const GenerationPhase::Result& Phase) -> std::expected<void, StartupError>
    {
        const auto &ConfiguredProtocols = Runtime->Generation->Configuration().Protocols;
        Runtime->QuicConfigured = std::any_of(ConfiguredProtocols.begin(), ConfiguredProtocols.end(),
            [](const auto &Protocol) { return Protocol.Quic.has_value(); });
        Runtime->Diagnose = std::make_unique<DiagnoseRuntime>();
        DiagnoseRuntimeConfiguration DiagnoseConfiguration;
        DiagnoseConfiguration.Logging.Level = *Phase.ConfiguredLogLevel;
        DiagnoseConfiguration.Mode = *Phase.ConfiguredRenderMode;
        DiagnoseConfiguration.Logging.Directory = Runtime->Generation->Configuration().Logging.Directory;
        DiagnoseConfiguration.Logging.FileName = Runtime->Generation->Configuration().Logging.FileName;
        DiagnoseConfiguration.Logging.Console = Runtime->Generation->Configuration().Logging.Console;
        DiagnoseConfiguration.Logging.RotateBytes = Runtime->Generation->Configuration().Logging.RotateBytes;
        DiagnoseConfiguration.Logging.RotateFiles = Runtime->Generation->Configuration().Logging.RotateFiles;
        DiagnoseConfiguration.FlushIntervalMs = Runtime->Generation->Configuration().Logging.FlushIntervalMs;
        DiagnoseConfiguration.GenerationId = Runtime->Generation->Id().Value();
        DiagnoseConfiguration.TraceSelection =
            Prism::Text::TraceSelection{Runtime->Generation->Configuration().Trace.IncludeCorrelation,
                Runtime->Generation->Configuration().Trace.IncludeWorker,
                Runtime->Generation->Configuration().Trace.IncludeSession,
                Runtime->Generation->Configuration().Trace.IncludeStream};
        if (const auto Installed = Runtime->Diagnose->Install(DiagnoseConfiguration); !Installed)
        {
            return std::unexpected(
                Startup::MakeStartupError(StartupErrorCode::Runtime, "Logging", Installed.error().Message));
        }
        Runtime->DiagnoseFlushInterval = std::chrono::milliseconds{DiagnoseConfiguration.FlushIntervalMs};
        Shutdown::ArmDiagnoseFlush(Runtime);
        Runtime->RootContext = Prism::Diagnose::ContextState::Empty().WithRenderEpoch(
            Runtime->Diagnose->CurrentEpoch()).With(
            Prism::Diagnose::Fields::Process, Runtime->Process->Id());
        const auto RuntimeGeneration = Runtime->Generation->Id();
        if (RuntimeGeneration.Value() > 1U)
        {
            Runtime->RootContext =
                Runtime->RootContext.With(Prism::Diagnose::Fields::Generation, RuntimeGeneration);
        }
        Runtime->WorkerContexts.reserve(Runtime->Process->Workers().Size());
        for (std::size_t Index = 0; Index < Runtime->Process->Workers().Size(); ++Index)
        {
            Runtime->WorkerContexts.push_back(Runtime->RootContext.With(Prism::Diagnose::Fields::Worker,
                Prism::WorkerId{static_cast<std::uint64_t>(Index + 1U)}));
        }
        Runtime->Services = std::make_shared<Prism::Runtime::SessionServices>();
        Runtime->Services->ProcessContext = Runtime->RootContext;
        Runtime->Services->Bytes = Runtime->Process->Resources().Bytes;
        const auto& Statistics = Runtime->Generation->Configuration().Statistics;
        if (Statistics.Enabled)
        {
            Runtime->Traffic = std::make_shared<Prism::Runtime::TrafficCounter>(
                Prism::Runtime::TrafficCounter::Options{
                    .Process = Runtime->Process->Id(),
                    .Generation = Runtime->Generation->Id(),
                    .Publication = Runtime->GenerationPublisher,
                    .Workers = Runtime->Process->Workers().Size()},
                Runtime->Io.get_executor());
            const auto RuntimeBound = Runtime->Tasks->BindTrafficSink(Runtime->Traffic);
            if (!RuntimeBound)
            {
                return std::unexpected(Startup::MakeStartupError(
                    StartupErrorCode::Runtime, "Statistics", "进程任务统计绑定失败"));
            }
            for (std::size_t Index = 0; Index < Runtime->Process->Workers().Size(); ++Index)
            {
                const auto WorkerId = Prism::WorkerId{static_cast<std::uint64_t>(Index + 1U)};
                auto *Worker = Runtime->Process->Workers().Find(WorkerId);
                if (!Worker)
                {
                    return std::unexpected(Startup::MakeStartupError(
                        StartupErrorCode::Runtime, "Statistics", "统计绑定时缺少 worker"));
                }
                const auto WorkerBound = Worker->TaskRegistry().BindTrafficSink(Runtime->Traffic);
                if (!WorkerBound)
                {
                    return std::unexpected(Startup::MakeStartupError(
                        StartupErrorCode::Runtime, "Statistics", "worker 任务统计绑定失败"));
                }
            }
            Runtime->Services->Traffic = Runtime->Traffic;
            Runtime->Services->RecognitionLatency = Runtime->Traffic;
            Runtime->StatisticsFlushInterval = std::chrono::milliseconds{Statistics.Interval};
            Shutdown::ArmStatisticsFlush(Runtime);
        }
        Runtime->DnsResolver = std::make_shared<Prism::Network::Dns::Resolver>(Runtime->Io.get_executor(),
            Assembly::MakeDnsConfig(Runtime->Generation->Configuration().Dns));
        return {};
    }
} // namespace Prism::Application::Startup::ProcessServices
