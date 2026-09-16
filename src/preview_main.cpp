/**
 * @file preview_main.cpp
 * @brief PrismPreview 独立启动入口
 * @details Preview 配置与生命周期 wrapper 负责启动策略；当前数据面
 *          明确使用 production fallback，Preview protocol adapters 未激活。
 */

#include <boost/asio/signal_set.hpp>

#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#endif

#include <prism/diagnose/diagnose.hpp>
#include <prism/foundation/memory/pool.hpp>
#include <prism/handshake/registry.hpp>
#include <prism/preview/Configuration.hpp>
#include <prism/preview/ProductionWorkerServices.hpp>
#include <prism/resource/process.hpp>
#include <prism/runtime/front/balancer.hpp>
#include <prism/runtime/front/listener.hpp>
#include <prism/runtime/front/quic_gateway.hpp>
#include <prism/runtime/worker/tls.hpp>
#include <prism/runtime/worker/worker.hpp>
#include <prism/settings/loader/load.hpp>
#include <prism/settings/validator.hpp>
#include <prism/user/stats/runtime.hpp>

namespace
{

    [[nodiscard]] auto ModeName(const psm::preview::RuntimeMode Mode) -> const char *
    {
        if (Mode == psm::preview::RuntimeMode::ProductionFallback)
        {
            return "production_fallback";
        }
        return "hybrid";
    }

    [[nodiscard]] auto EffectiveModeName(const psm::preview::EffectiveRuntimeModes &Modes)
        -> const char *
    {
        if (Modes.Mode == psm::preview::RuntimeMode::HttpPreview)
        {
            return "http_preview";
        }
        if (Modes.Mode == psm::preview::RuntimeMode::Socks5Preview)
        {
            return "socks5_preview";
        }
        return ModeName(Modes.Mode);
    }

} // namespace

int main(int Argc, char *Argv[])
{
    try
    {
        psm::memory::system::enable_pooling();
        psm::handshake::register_schemes();

        const auto Executable = Argc > 0 ? std::filesystem::path(Argv[0]) : std::filesystem::path{};
        const auto DefaultPath = std::filesystem::absolute(
            Executable.empty() ? std::filesystem::path(psm::preview::DefaultConfigurationName())
                               : Executable.parent_path() / psm::preview::DefaultConfigurationName());
        const auto Command = psm::preview::ParseCommandLine(Argc, Argv, DefaultPath);
        if (!Command)
        {
            std::cerr << Command.error() << '\n';
            return 1;
        }

        auto Loaded = psm::preview::Configuration::LoadFile(Command->ConfigPath);
        if (!Loaded)
        {
            std::cerr << Loaded.error() << '\n';
            return 1;
        }
        auto PreviewConfig = std::move(*Loaded);
        if (!psm::preview::ApplyCommandLineOverrides(PreviewConfig, *Command))
        {
            std::cerr << "invalid command-line configuration override\n";
            return 1;
        }

        const auto Modes = PreviewConfig.EffectiveModes();
        if (!Modes.UseProductionFallback)
        {
            std::cerr << "Preview protocol adapters are unavailable and production fallback is disabled\n";
            return 1;
        }

        auto ProductionConfig = PreviewConfig.ToProduction();
        try
        {
            psm::settings_validator::validate_or_throw(ProductionConfig);
        }
        catch (const std::exception &Error)
        {
            std::cerr << "invalid production configuration: " << Error.what() << '\n';
            return 1;
        }

        psm::diagnose::init(ProductionConfig.trace);
        psm::diagnose::info(
            "PrismPreview mode={} preview_runtime={} production_fallback={} preview_protocol_adapters={}",
            EffectiveModeName(Modes), Modes.UsePreviewRuntime, Modes.UseProductionFallback,
            Modes.PreviewProtocolAdapters);

        auto Accounts = psm::loader::build_dir(ProductionConfig.instance.auth);
        auto SslContext = psm::runtime::worker::tls::make(ProductionConfig.instance);
        auto SharedConfig = std::make_shared<psm::settings>(std::move(ProductionConfig));

        psm::resource::process::options ProcessOptions;
        ProcessOptions.cfg = SharedConfig;
        ProcessOptions.ssl = SslContext;
        ProcessOptions.accounts = Accounts;
        auto GlobalResources = std::make_shared<psm::resource::process>(std::move(ProcessOptions));

        const auto HardwareThreads = std::thread::hardware_concurrency();
        if (HardwareThreads == 0)
        {
            throw std::runtime_error("cannot determine hardware concurrency");
        }
        const auto WorkerCount = HardwareThreads > 1U ? HardwareThreads - 1U : 1U;

        using Worker = psm::runtime::worker::worker;
        const auto Launcher = Modes.Mode == psm::preview::RuntimeMode::HttpPreview
                                  ? psm::preview::ProductionWorkerServices::HttpPreviewConnectionLauncher()
                                  : Modes.Mode == psm::preview::RuntimeMode::Socks5Preview
                                        ? psm::preview::ProductionWorkerServices::Socks5PreviewConnectionLauncher()
                                        : psm::preview::ProductionWorkerServices::DefaultConnectionLauncher();
        psm::memory::vector<std::unique_ptr<Worker>> Workers;
        Workers.reserve(WorkerCount);
        for (std::uint32_t Index = 0; Index < WorkerCount; ++Index)
        {
            Workers.emplace_back(std::make_unique<Worker>(GlobalResources, Launcher));
        }

        psm::stats::runtime::system_state::instance().mark_started(WorkerCount);

        psm::memory::vector<psm::runtime::front::balancer::worker_binding> Bindings;
        Bindings.reserve(Workers.size());
        for (const auto &WorkerObject : Workers)
        {
            Worker *WorkerRef = WorkerObject.get();
            Bindings.emplace_back(
                [WorkerRef](boost::asio::ip::tcp::socket Socket)
                { WorkerRef->dispatch_socket(std::move(Socket)); },
                [WorkerRef] { return WorkerRef->load_snapshot(); },
                [WorkerRef] { return WorkerRef->alive(); });
        }

        psm::runtime::front::balancer Dispatcher(std::move(Bindings));
        psm::runtime::front::listener TcpListener(*SharedConfig, Dispatcher);

        std::shared_ptr<psm::runtime::front::quic_gateway> QuicGateway;
        if (Modes.EnableQuic &&
            (SharedConfig->stealth.hysteria2.enabled() || SharedConfig->stealth.tuic.enabled()))
        {
            psm::memory::vector<std::shared_ptr<psm::resource::worker>> Resources;
            Resources.reserve(Workers.size());
            for (const auto &WorkerObject : Workers)
            {
                Resources.push_back(WorkerObject->resources());
            }
            QuicGateway = std::make_shared<psm::runtime::front::quic_gateway>(
                *SharedConfig, Dispatcher, std::move(Resources));
            QuicGateway->start();
        }

        psm::memory::vector<std::jthread> Threads;
        Threads.reserve(Workers.size() + 1U);
        for (const auto &WorkerObject : Workers)
        {
            Worker *WorkerRef = WorkerObject.get();
            Threads.emplace_back([WorkerRef]
                                 {
                                     try
                                     {
                                         WorkerRef->run();
                                     }
                                     catch (const std::exception &Error)
                                     {
                                         psm::diagnose::error("worker exception: {}", Error.what());
                                     }
                                 });
        }
        Threads.emplace_back([&TcpListener]
                             {
                                 try
                                 {
                                     TcpListener.listen();
                                 }
                                 catch (const std::exception &Error)
                                 {
                                     psm::diagnose::error("listen exception: {}", Error.what());
                                 }
                             });

        boost::asio::io_context SignalContext;
        boost::asio::signal_set Signals(SignalContext, SIGINT, SIGTERM);
        Signals.async_wait(
            [&Workers, &TcpListener, &QuicGateway, &Threads, &SignalContext](
                const boost::system::error_code &, int)
            {
                psm::diagnose::info("PrismPreview shutdown requested");
                TcpListener.stop();
                if (QuicGateway)
                {
                    QuicGateway->stop();
                }
                for (const auto &WorkerObject : Workers)
                {
                    WorkerObject->stop();
                }
                SignalContext.stop();
            });

        std::jthread SignalThread([&SignalContext] { SignalContext.run(); });
        SignalThread.join();

        // signal callback 只发出停止请求；所有拥有资源的线程/对象在主线程收口。
        Threads.clear();
        QuicGateway.reset();
        Workers.clear();
        psm::diagnose::shutdown();
        return 0;
    }
    catch (const std::exception &Error)
    {
        std::cerr << Error.what() << '\n';
    }
    catch (...)
    {
        std::cerr << "unknown exception\n";
    }
    return 1;
}
