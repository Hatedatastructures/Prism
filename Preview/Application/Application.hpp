/** @file Application.hpp @brief 应用控制线程的启动、运行、停机及查询行为。 */
#pragma once
#include <Preview/Application/Definition.hpp>

#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Application/Shutdown.hpp>
#include <Preview/Foundation/Executor/RunContext.hpp>
#include <Preview/Foundation/Memory/Container.hpp>

#include <exception>

namespace Preview::Application
{

    inline Application::Application(Options OptionsValue) : Options_(std::move(OptionsValue))
    {
    }

    inline Application::Application(std::filesystem::path ConfigurationPath)
        : Application(Options{std::move(ConfigurationPath), nullptr})
    {
    }

    inline Application::~Application() noexcept
    {
        if (State_ && (State_->ControlContext->Fatal->HasFailure() || State_->WorkerFatal.load()))
            return;
        Stop();
        if (State_ && !State_->Running.load(std::memory_order_acquire) &&
            !State_->StopCompleted.load(std::memory_order_acquire))
        {
            State_->Io.restart();
            {
                Preview::Memory::ResourceScope Scope(State_->Process
                    ? State_->Process->Resources().MemoryResource : nullptr);
                while (!State_->StopCompleted.load(std::memory_order_acquire))
                {
                    if (State_->Io.run_one() == 0U) State_->Io.restart();
                }
            }
        }
        if (State_)
        {
            (void)Shutdown::CheckPublishedShutdownOutcome(State_);
            Shutdown::FinalizeRuntimeResources(State_);
        }
    }

    inline auto Application::Run() -> int
    {
        if (!State_ || State_->Phase.load(std::memory_order_acquire) == RuntimePhase::Ready)
        {
            const auto Started = Start();
            if (!Started)
            {
                std::cerr << "PrismPreview startup failed code="
                          << static_cast<unsigned int>(Started.error().Code);
                if (!Started.error().Path.empty())
                {
                    std::cerr << " path=" << Started.error().Path;
                }
                std::cerr << " message=" << Started.error().Message << '\n';
                return 1;
            }
        }
        if (!State_ || IsStopped())
        {
            return State_ ? State_->ExitCode : 0;
        }

        State_->Running.store(true, std::memory_order_release);
        std::exception_ptr Fatal;
        {
            Preview::Memory::ResourceScope Scope(State_->Process
                ? State_->Process->Resources().MemoryResource : nullptr);
            Fatal = Preview::Executor::RunContext(State_->Io);
        }
        State_->Running.store(false, std::memory_order_release);
        if (Fatal || State_->WorkerFatal.load() || Preview::Executor::FatalState::ProcessPending())
        {
            if (Fatal)
            {
                (void)State_->RecordShutdownFailure(
                    Shutdown::ShutdownOperation::FailureFromException(Fatal));
            }
            else
            {
                (void)State_->RecordShutdownFailure(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            State_->StopForFatal();
        }
        else if (!State_->StopCompleted.load(std::memory_order_acquire))
        {
            Stop();
            State_->Io.restart();
            std::exception_ptr CleanupFatal;
            {
                Preview::Memory::ResourceScope Scope(State_->Process
                    ? State_->Process->Resources().MemoryResource : nullptr);
                CleanupFatal = Preview::Executor::RunContext(State_->Io);
            }
            if (CleanupFatal)
            {
                (void)State_->RecordShutdownFailure(
                    Shutdown::ShutdownOperation::FailureFromException(CleanupFatal));
                State_->StopForFatal();
            }
        }
        const auto ShutdownOutcome = Shutdown::CheckPublishedShutdownOutcome(State_);
        if (!ShutdownOutcome)
        {
            const auto &Failure = ShutdownOutcome.error();
            std::cerr << "PrismPreview shutdown failed code="
                      << static_cast<unsigned int>(Failure.Code);
            if (Failure.Native)
            {
                std::cerr << " native=" << Failure.Native.category().name()
                          << ':' << Failure.Native.value();
            }
            std::cerr << '\n';
            (void)State_->RecordShutdownFailure(ShutdownOutcome.error());
        }
        Shutdown::FinalizeRuntimeResources(State_);
        return State_->ExitCode;
    }

    inline auto Application::Stop() noexcept -> void
    {
        if (!State_ || State_->StopRequested.exchange(true, std::memory_order_acq_rel))
        {
            return;
        }
        if (State_->Phase.load(std::memory_order_acquire) != RuntimePhase::Failed)
        {
            State_->Phase.store(RuntimePhase::Stopping, std::memory_order_release);
        }
        Shutdown::ScheduleShutdown(State_);
    }

    inline auto Application::IsReady() const noexcept -> bool
    {
        return State_ && State_->Phase.load(std::memory_order_acquire) == RuntimePhase::Ready;
    }

    inline auto Application::IsStopping() const noexcept -> bool
    {
        if (!State_)
        {
            return false;
        }
        return State_->Phase.load(std::memory_order_acquire) == RuntimePhase::Stopping;
    }

    inline auto Application::IsStopped() const noexcept -> bool
    {
        return State_ && State_->ResourcesFinalized.load(std::memory_order_acquire);
    }

    inline auto Application::LastError() const noexcept -> const std::optional<StartupError>&
    {
        return LastError_;
    }

} // namespace Preview::Application
