/**
 * @file Diagnose.cpp
 * @brief 应用级诊断后端与 facade 提交目标生命周期实现。
 */
#include <Prism/Application/Startup/Detail/Diagnose.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace Prism::Application
{
    DiagnoseRuntime::DiagnoseRuntime() = default;

    DiagnoseRuntime::~DiagnoseRuntime() noexcept
    {
        (void)Shutdown();
    }

    [[nodiscard]] auto DiagnoseRuntime::Install(const DiagnoseRuntimeConfiguration &Configuration)
        -> std::expected<void, DiagnoseRuntimeError>
    {
        const auto Installed = Lifecycle_.Install(Prism::Diagnose::Detail::BackendSettings{
            Configuration.Logging,
            Configuration.Mode,
            Configuration.TraceSelection,
            Configuration.FlushIntervalMs, Configuration.GenerationId});
        if (!Installed)
        {
            return Installed;
        }
        const auto Bound = Prism::Diagnose::Detail::InstallSubmissionBackend(
            Prism::Diagnose::Detail::SubmissionBackendBinding{
                this, &SubmitFromFacade, &CaptureContextFromFacade, Configuration.Logging.Level});
        if (!Bound)
        {
            (void)Lifecycle_.Shutdown();
            if (Bound.error().Code == Prism::Fault::Code::ResourceUnavailable)
            {
                return std::unexpected(DiagnoseRuntimeError{DiagnoseRuntimeErrorCode::ResourceUnavailable,
                    Configuration.Logging.Directory.string(), "facade admission resource is unavailable"});
            }
            return std::unexpected(DiagnoseRuntimeError{
                DiagnoseRuntimeErrorCode::OwnerConflict,
                Configuration.Logging.Directory.string(),
                "another facade owner is installed in this process"});
        }
        Registration_.emplace(*Bound);
        return {};
    }

    [[nodiscard]] auto DiagnoseRuntime::PrepareEpoch(const DiagnoseRuntimeConfiguration &Configuration)
        -> std::expected<Prism::Diagnose::RenderEpochPin, DiagnoseRuntimeError>
    {
        return Lifecycle_.PrepareEpoch(Prism::Diagnose::Detail::BackendSettings{
            Configuration.Logging,
            Configuration.Mode,
            Configuration.TraceSelection,
            Configuration.FlushIntervalMs, Configuration.GenerationId});
    }

    auto DiagnoseRuntime::PublishEpoch(const Prism::Diagnose::RenderEpochPin &Epoch) noexcept -> bool
    {
        if (!Epoch || !Lifecycle_.PublishEpoch(Epoch))
        {
            return false;
        }
        const auto Active = Lifecycle_.CurrentEpoch();
        if (Active && &Active->Value() == &Epoch->Value() && Registration_ &&
            !Prism::Diagnose::Detail::UpdateSubmissionBackendLevel(
                *Registration_, Epoch->Value().Settings.Logging.Level))
        {
            return false;
        }
        return true;
    }

    [[nodiscard]] auto DiagnoseRuntime::CurrentEpoch() const noexcept -> Prism::Diagnose::RenderEpochPin
    {
        return Lifecycle_.CurrentEpoch();
    }

    [[nodiscard]] auto DiagnoseRuntime::Submit(const Prism::Diagnose::LogLevel Level,
                              const Prism::Diagnose::ContextState &Context,
                              std::string_view Message) noexcept
        -> Prism::Diagnose::SubmissionReceipt
    {
        DirectCallGuard Call(*this);
        if (!Lifecycle_.IsInstalled())
        {
            return {Prism::Diagnose::SubmissionStatus::Stopped, 0U};
        }
        Prism::Diagnose::Detail::SubmissionRequest Request{Level, &Context, Message, Prism::Diagnose::SubmissionKind::Ordinary};
        const auto Receipt = Lifecycle_.Submit(Request);
        return Receipt;
    }

    [[nodiscard]] auto DiagnoseRuntime::Audit(const Prism::Diagnose::ContextState &Context,
                             std::string_view Message) noexcept
        -> Prism::Diagnose::SubmissionReceipt
    {
        DirectCallGuard Call(*this);
        if (!Lifecycle_.IsInstalled())
        {
            return {Prism::Diagnose::SubmissionStatus::Stopped, 0U};
        }
        Prism::Diagnose::Detail::SubmissionRequest Request{
            Prism::Diagnose::LogLevel::Access,
            &Context,
            Message,
            Prism::Diagnose::SubmissionKind::Audit};
        const auto Receipt = Lifecycle_.Submit(Request);
        return Receipt;
    }

    auto DiagnoseRuntime::Flush() noexcept -> void
    {
        DirectCallGuard Call(*this);
        if (Lifecycle_.IsInstalled())
        {
            Lifecycle_.Flush();
        }
    }

    [[nodiscard]] auto DiagnoseRuntime::DrainOnControlThread(const std::chrono::milliseconds Timeout)
        -> Prism::Diagnose::SubmissionReceipt
    {
        DirectCallGuard Call(*this);
        if (!Lifecycle_.IsInstalled())
        {
            return {Prism::Diagnose::SubmissionStatus::Stopped, 0U};
        }
        const auto Receipt = Lifecycle_.DrainOnControlThread(Timeout);
        return Receipt;
    }

    auto DiagnoseRuntime::BeginShutdown() noexcept -> void
    {
        if (Registration_) { (void)Prism::Diagnose::Detail::DisableSubmissionBackend(*Registration_); }
        Lifecycle_.BeginShutdown();
    }

    [[nodiscard]] auto DiagnoseRuntime::FinalizeShutdown() noexcept
        -> Prism::Diagnose::SubmissionReceipt
    {
        BeginShutdown();
        if (Registration_)
        {
            Prism::Diagnose::Detail::RemoveSubmissionBackend(*Registration_);
            Registration_.reset();
        }
        for (auto Active = DirectCalls_.load(std::memory_order_acquire); Active != 0U;
             Active = DirectCalls_.load(std::memory_order_acquire))
        {
            DirectCalls_.wait(Active, std::memory_order_acquire);
        }
        return Lifecycle_.Shutdown();
    }

    [[nodiscard]] auto DiagnoseRuntime::Shutdown() noexcept -> Prism::Diagnose::SubmissionReceipt
    {
        return FinalizeShutdown();
    }

    [[nodiscard]] auto DiagnoseRuntime::IsInstalled() const noexcept -> bool
    {
        return Lifecycle_.IsInstalled();
    }

    [[nodiscard]] auto DiagnoseRuntime::Dropped(const Prism::Diagnose::LogLevel Level) const noexcept
        -> std::uint64_t
    {
        return Lifecycle_.Dropped(Level);
    }

    [[nodiscard]] auto DiagnoseRuntime::QueueHighWatermark() const noexcept -> std::size_t
    {
        return Lifecycle_.QueueHighWatermark();
    }

    [[nodiscard]] auto DiagnoseRuntime::DroppedAudits() const noexcept -> std::uint64_t
    {
        return Lifecycle_.TerminalFailures();
    }

    [[nodiscard]] auto DiagnoseRuntime::CaptureFailures() const noexcept -> std::uint64_t
    {
        return Lifecycle_.CaptureFailures();
    }

    [[nodiscard]] auto DiagnoseRuntime::SinkFailures() const noexcept -> std::uint64_t
    {
        return Lifecycle_.SinkFailures();
    }

    [[nodiscard]] auto DiagnoseRuntime::FormatFailures() const noexcept -> std::uint64_t
    {
        return Prism::Diagnose::Detail::FormatFailures();
    }

    [[nodiscard]] auto DiagnoseRuntime::AdmissionFailures() const noexcept -> std::uint64_t
    {
        return Prism::Diagnose::Detail::AdmissionFailures();
    }

    [[nodiscard]] auto DiagnoseRuntime::RenderFailures() const noexcept -> std::uint64_t
    { return Lifecycle_.RenderFailures(); }

    [[nodiscard]] auto DiagnoseRuntime::Written() const noexcept -> std::uint64_t
    { return Lifecycle_.Written(); }

    auto DiagnoseRuntime::ResetQueueHighWatermark() noexcept -> void
    {
        DirectCallGuard Call(*this);
        if (Lifecycle_.IsInstalled())
        {
            Lifecycle_.ResetQueueHighWatermark();
        }
    }

    DiagnoseRuntime::DirectCallGuard::DirectCallGuard(DiagnoseRuntime& Owner) noexcept : Owner_(Owner)
    {
        Owner_.DirectCalls_.fetch_add(1U, std::memory_order_acq_rel);
    }

    DiagnoseRuntime::DirectCallGuard::~DirectCallGuard()
    {
        Owner_.ReleaseDirectCall();
    }

    auto DiagnoseRuntime::ReleaseDirectCall() noexcept -> void
    {
        if (DirectCalls_.fetch_sub(1U, std::memory_order_acq_rel) == 1U)
        {
            DirectCalls_.notify_all();
        }
    }

    auto DiagnoseRuntime::SubmitFromFacade(
        void *Owner,
        const Prism::Diagnose::Detail::SubmissionRequest &Request) noexcept
        -> Prism::Diagnose::SubmissionReceipt
    {
        auto *Runtime = static_cast<DiagnoseRuntime *>(Owner);
        if (Runtime == nullptr)
        {
            return {Prism::Diagnose::SubmissionStatus::Stopped, 0U};
        }
        return Runtime->Lifecycle_.Submit(Request);
    }

    auto DiagnoseRuntime::CaptureContextFromFacade(void *Owner) noexcept
        -> Prism::Diagnose::ContextState
    {
        auto *Runtime = static_cast<DiagnoseRuntime *>(Owner);
        return Runtime
            ? Prism::Diagnose::ContextState::Empty().WithRenderEpoch(Runtime->CurrentEpoch())
            : Prism::Diagnose::ContextState::Empty();
    }
}
