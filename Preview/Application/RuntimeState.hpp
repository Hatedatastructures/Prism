/**
 * @file RuntimeState.hpp
 * @brief Preview 应用进程级运行时状态及 worker owner。
 */

#pragma once

#include <Preview/Account/Account.hpp>
#include <Preview/Application/Account/Catalog.hpp>
#include <Preview/Application/Definition.hpp>
#include <Preview/Application/Configuration/Configuration.hpp>
#include <Preview/Application/RuntimeGenerationSnapshot.hpp>
#include <Preview/Application/DiagnoseRuntime.hpp>
#include <Preview/Boundary/Contract/BoundaryDispatcher.hpp>
#include <Preview/Boundary/Datagram/DatagramClassifier.hpp>
#include <Preview/Boundary/Datagram/DatagramListener.hpp>
#include <Preview/Boundary/Quic/QuicConnectionRegistry.hpp>
#include <Preview/Boundary/Quic/QuicPacketGateway.hpp>
#include <Preview/Composition/Provider/ProviderCatalog.hpp>
#include <Preview/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Lifecycle/TaskRegistry.hpp>
#include <Preview/Net/Dns/Config.hpp>
#include <Preview/Net/Dns/Resolver.hpp>
#include <Preview/Operations/Controller.hpp>

#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/Process.hpp>
#include <Preview/Runtime/GenerationPublication.hpp>
#include <Preview/Runtime/SessionServices.hpp>
#include <Preview/Runtime/Statistics.hpp>
#include <Preview/Statistics/EventRing.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace Preview::Application
{

    namespace Net = boost::asio;
    namespace Configuration = Preview::Application::Configuration;

    enum class RuntimePhase : std::uint8_t
    {
        Created,
        Ready,
        Stopping,
        Stopped,
        Failed,
    };

    /** @brief 可重复关闭阶段的单 owner 进度；Running 竞争者不得开始第二次 drain。 */
    enum class ShutdownStage : std::uint8_t
    {
        NotStarted,
        Running,
        Completed,
        Failed,
    };

    /** @brief 单一 shutdown 终态回执的发布进度；读取和写入只在 coordinator strand。 */
    enum class ShutdownResultStage : std::uint8_t
    {
        NotPublished,
        Publishing,
        Published,
    };

    /** @brief 已回收代次仍需保留的首个历史 Drain cause。 */
    struct GenerationRetirementFailure final
    {
        Preview::GenerationId Generation{};
        Preview::Fault::Failure Cause;
    };

    /** @brief 持有 Preview 进程级资源、listener、worker 和停机状态。 */
    struct Application::RuntimeState final : std::enable_shared_from_this<Application::RuntimeState>
    {
        /**
         * @brief 保留失败运行时的显式进程终态 owner；只由 ProcessStorage 持有至进程退出。
         * @details Pending 可见地计入整个 RuntimeState，因而同时保留 Process、Worker、
         *          ContextOwner 和尚未完成的 listener/协议 owner。它永不报告 IsRetired。
         */
        struct FailedShutdownOwner final : Preview::Executor::ClosingResource
        {
            auto Bind(std::shared_ptr<RuntimeState> Value) noexcept -> void
            {
                State = std::move(Value);
            }

            auto RequestRetirement() -> void override {}

            [[nodiscard]] auto IsRetired() const noexcept -> bool override
            {
                return false;
            }

            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
            {
                return true;
            }

            std::shared_ptr<RuntimeState> State;
        };

        explicit RuntimeState(const std::size_t WorkerCount, const Preview::GenerationId GenerationValue,
            Preview::Network::Dns::Config DnsConfig)
            : FailedOwner(std::make_shared<FailedShutdownOwner>()),
              Signals(Io), DiagnoseFlushTimer(Io), StatisticsFlushTimer(Io),
              GenerationReaperSignal(Io),
              ShutdownCoordinator(Net::make_strand(Io.get_executor())),
              ShutdownResultTimer(ShutdownCoordinator),
              ShutdownObserversRetiredTimer(ShutdownCoordinator),
              Tasks(std::make_shared<Preview::Lifecycle::TaskRegistry>(Io.get_executor()))
        {
            ShutdownResultTimer.expires_at(Net::steady_timer::time_point::max());
            ShutdownObserversRetiredTimer.expires_at(Net::steady_timer::time_point::max());
            GenerationReaperSignal.expires_at(Net::steady_timer::time_point::max());
            Process = std::make_unique<Preview::Runtime::Process>(Preview::Runtime::Process::Options{
                Preview::ProcessId{1}, GenerationValue, WorkerCount, 64, std::move(DnsConfig),
                GenerationPublisher});
            Events = std::make_shared<Preview::Statistics::EventRing>();
        }

        ~RuntimeState() noexcept
        {
            StopWorkers();
        }

        auto StartWorkers(const std::size_t WorkerCount) -> void
        {
            if (!Process || WorkerCount != Process->Workers().Size() ||
                WorkerThreads.size() > WorkerCount)
            {
                throw std::runtime_error("Preview worker thread count is inconsistent");
            }
            WorkerThreads.reserve(WorkerCount);
            for (std::size_t Index = WorkerThreads.size(); Index < WorkerCount; ++Index)
            {
                auto* WorkerValue =
                    Process->Workers().Find(Preview::WorkerId{static_cast<std::uint64_t>(Index + 1)});
                if (!WorkerValue)
                {
                    throw std::runtime_error("Preview worker is missing");
                }
                WorkerThreads.emplace_back([this, WorkerValue] { RunWorkerEntry(*WorkerValue); });
            }
            WorkersStarted = Process && WorkerThreads.size() == Process->Workers().Size();
        }

        /** @brief 线程入口唯一致命异常边界；不把第三方运行时失败变为业务成功。
         * @details worker 退出后记录不可恢复状态，关闭存储继续保活尚未退栈的资源。
         * 控制线程负责后续停止接入、排空与 join；本入口不执行跨 executor 析构。
         */
        auto RunWorkerEntry(Preview::Runtime::Worker& Worker) noexcept -> void
        {
            try { Worker.Run(); }
            catch (...)
            {
                Worker.Resources().Execution->Fatal->Publish(std::current_exception());
            }
            if (Worker.Resources().Execution->Fatal->HasFailure())
                WorkerFatal.store(true, std::memory_order_release);
        }

        /** @brief 不可恢复异常已由入口接管，只停止真实调度域并join，不伪造Drain或清空实体。 */
        auto StopForFatal() -> void
        {
            ExitCode = 1;
            Phase.store(RuntimePhase::Failed, std::memory_order_release);
            ShutdownDrainFailed.store(true, std::memory_order_release);
            StopRequested.store(true, std::memory_order_release);
            RetainFailedShutdown();
            Io.stop();
            StopWorkers();
        }

        /** @brief 物理已回收的旧代次仍保留其最早历史 Drain cause。 */
        auto RecordGenerationRetirementFailure(
            const Preview::GenerationId Id,
            const Preview::Fault::Failure Cause) noexcept -> void
        {
            if (!FirstGenerationRetirementFailure)
            {
                FirstGenerationRetirementFailure = GenerationRetirementFailure{Id, Cause};
            }
        }

        /** @brief 将失败运行时交给有 Pending 事实的进程终态存储。 */
        auto RetainFailedShutdown() noexcept -> void
        {
            bool Expected = false;
            if (!FailedOwnerRetained.compare_exchange_strong(Expected, true, std::memory_order_acq_rel)) return;
            auto Owner = std::exchange(FailedOwner, std::shared_ptr<FailedShutdownOwner>{});
            if (!Owner)
            {
                FailedOwnerRetained.store(false, std::memory_order_release);
                return;
            }
            Owner->Bind(shared_from_this());
            ClosingResources->Retain(std::move(Owner));
        }

        /** @brief 保留应用关闭的首个 typed cause 并登记完整失败运行时。 */
        auto RecordShutdownFailure(const Preview::Fault::Failure Cause) noexcept
            -> Preview::Fault::Failure
        {
            if (!ShutdownFailure)
            {
                ShutdownFailure = Cause;
            }
            ShutdownDrainFailed.store(true, std::memory_order_release);
            ExitCode = 1;
            Phase.store(RuntimePhase::Failed, std::memory_order_release);
            RetainFailedShutdown();
            return *ShutdownFailure;
        }

        auto StopWorkers() noexcept -> void
        {
            if (Process)
            {
                Process->Stop();
            }
            for (auto& WorkerThread : WorkerThreads)
            {
                if (WorkerThread.joinable())
                {
                    WorkerThread.join();
                }
            }
        }

        [[nodiscard]] auto ActiveGenerationSnapshot() const noexcept
            -> SharedRuntimeGenerationSnapshot
        {
            if (!GenerationPublisher)
            {
                return {};
            }
            const auto Active = GenerationPublisher->Current();
            if (!Active)
            {
                return {};
            }
            return std::static_pointer_cast<const RuntimeGenerationSnapshot>(Active);
        }

        /** @brief 释放只供启动装配使用的 root/worker 初始 epoch 强引用。 */
        auto ReleaseInitialContextPins() noexcept -> void
        {
            bool Expected = false;
            if (!InitialContextPinsReleased.compare_exchange_strong(
                Expected, true, std::memory_order_acq_rel))
            {
                return;
            }
            RootContext = Preview::Diagnose::ContextState::Empty();
            WorkerContexts.clear();
        }

        /** @brief 读取唯一已发布代次的进程日志上下文；启动发布前使用初始 pin。 */
        [[nodiscard]] auto CurrentProcessContext() const noexcept
            -> Preview::Diagnose::ContextState
        {
            const auto Snapshot = ActiveGenerationSnapshot();
            return Snapshot && Snapshot->Services.Session
                ? Snapshot->Services.Session->ProcessContext
                : RootContext;
        }

        std::shared_ptr<Preview::Executor::ClosingStorage> ClosingResources{
            Preview::Executor::ClosingStorage::ProcessStorage()};
        std::shared_ptr<FailedShutdownOwner> FailedOwner;
        std::shared_ptr<Preview::Executor::ContextOwner> ControlContext{
            Preview::Executor::ContextOwner::Create(ClosingResources)};
        std::shared_ptr<Preview::Executor::ClosingFailureObserver> ClosingObserver;
        Net::io_context& Io{ControlContext->Io};
        Net::signal_set Signals;
        Net::steady_timer DiagnoseFlushTimer;
        std::chrono::milliseconds DiagnoseFlushInterval{250};
        Net::steady_timer StatisticsFlushTimer;
        Net::steady_timer GenerationReaperSignal;
        /** @brief 当前真实已 arm timer 的周期回执；未 arm 或已完成时为零。 */
        std::atomic<std::int64_t> StatisticsFlushArmedIntervalMilliseconds{0};
        std::chrono::milliseconds StatisticsFlushInterval{1000};
        Net::strand<Net::any_io_executor> ShutdownCoordinator;
        Net::steady_timer ShutdownResultTimer;
        Net::steady_timer ShutdownObserversRetiredTimer;
        std::atomic<ShutdownResultStage> ShutdownResultStatus{ShutdownResultStage::NotPublished};
        std::optional<std::expected<void, Preview::Fault::Failure>> ShutdownResult;
        std::optional<GenerationRetirementFailure> FirstGenerationRetirementFailure;
        std::atomic<std::size_t> ShutdownObserverCount{0}; ///< observer reservation 与 coordinator retirement fence。
        bool ShutdownObserverCancellationFailed{false}; ///< coordinator timer 广播失败时禁止伪造回执。
        std::shared_ptr<Preview::Runtime::TrafficCounter> Traffic;
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Tasks;
        AccountCatalog Accounts;
        Configuration::SharedConfigurationGeneration Generation;
        std::shared_ptr<Preview::Statistics::EventRing> Events;
        /** @brief 由 ControlContext executor 持有；ShutdownRuntime 在 Io.stop 前停止其维护循环。 */
        std::shared_ptr<Preview::Network::Dns::Resolver> DnsResolver;
        /** @brief 进程关闭链路保留的唯一首个 typed cause。 */
        std::optional<Preview::Fault::Failure> ShutdownFailure;
        std::atomic<ShutdownStage> DataPlaneShutdown{ShutdownStage::NotStarted};
        std::atomic<ShutdownStage> OperationsShutdown{ShutdownStage::NotStarted};
        std::shared_ptr<Preview::Boundary::DatagramClassifier> DatagramClassifier;
        std::shared_ptr<Preview::Boundary::QuicPacketGateway> QuicPacketGateway;
        std::shared_ptr<Preview::Boundary::QuicConnectionRegistry> QuicConnectionRegistry;

        std::shared_ptr<Preview::Boundary::BoundaryDispatcher> BoundaryDispatcher;
        std::unique_ptr<DiagnoseRuntime> Diagnose{};
        Preview::Diagnose::ContextState RootContext{Preview::Diagnose::ContextState::Empty()};
        std::atomic<bool> InitialContextPinsReleased{false};
        std::vector<Preview::Diagnose::ContextState> WorkerContexts{};
        Preview::Runtime::SharedSessionServices Services;
        std::shared_ptr<Preview::Runtime::GenerationPublication> GenerationPublisher{
            std::make_shared<Preview::Runtime::GenerationPublication>()};
        std::filesystem::path ConfigurationPath;
        std::filesystem::path OperationsWebDirectory;
        std::unique_ptr<Preview::Runtime::Process> Process;
        std::unique_ptr<Preview::Runtime::TcpListener> Listener;
        std::unique_ptr<Preview::Boundary::DatagramListener> DatagramListener;
        std::shared_ptr<Preview::Composition::Provider::BoundCatalog> ProviderBindings;
        /** @brief 由发布器退休、仍须等待 generation pin 归零后 Drain 的快照 owner。 */
        std::vector<SharedRuntimeGenerationSnapshot> RetiredGenerationSnapshots;
        std::atomic<bool> GenerationReaperRunning{false};
        bool QuicConfigured{false};
        std::shared_ptr<Preview::Operations::Controller> ManagementController;
        std::vector<std::thread> WorkerThreads;
        bool WorkersStarted{false}; ///< 只有整组线程建立后才允许走异步 worker Drain。
        std::atomic<bool> WorkerShutdownSucceeded{false}; ///< 已完成每个 worker scope 的 Drain 与 retirement fence。
        std::atomic<bool> FailedOwnerRetained{false}; ///< 进程终态 owner 已发布且 Pending 可见。
        std::atomic<RuntimePhase> Phase{RuntimePhase::Created};
        std::atomic<bool> StopRequested{false};
        std::atomic<bool> StopCompleted{false};
        std::atomic<bool> ShutdownScheduled{false};
        std::atomic<bool> ConfigurationPersistenceActive{false}; ///< 同一时刻只允许一个持久化 Reload。
        std::atomic<bool> Running{false};
        std::atomic<bool> SignalsArmed{false};
        std::atomic<bool> ResourcesFinalized{false};
        std::atomic<bool> ShutdownDrainFailed{false}; ///< Drain 或 executor fence 未获证时保持失败。
        std::atomic<bool> ProtocolDrainFailed{false};
        std::atomic<bool> WorkerFatal{false}; ///< 仅线程入口写入的不可恢复运行时失败。

        std::atomic<std::uint64_t> ObservationFailures{0}; ///< 观察设施失败，独立于业务退出结果。
        std::chrono::milliseconds ShutdownTimeout{5000};
        int ExitCode{0};
        Readiness Ready{};
    };

} // namespace Preview::Application
