/**
 * @file BackendLifecycle.cpp
 * @brief 后台提交桥接及公开生命周期接口的实现。
 */
#include <Prism/Foundation/Utility/Diagnose/BackendLifecycle.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/AsyncBackendState.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/BackendBridge.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/BackendLifecycleOwner.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Diagnose::Detail
{
    auto BackendBridge::Submit(const SubmissionRequest& Request, AsyncBackendState* State) noexcept
        -> SubmissionReceipt
    {
        if (!State || !Request.Context) { return {SubmissionStatus::Stopped, 0U}; }
        if (static_cast<std::uint8_t>(Request.Level) > static_cast<std::uint8_t>(LogLevel::Off))
        {
            return {SubmissionStatus::Failed, 0U, {Prism::Fault::Code::InvalidArgument}};
        }
        auto Epoch = Request.Context->RenderEpoch();
        if (!Epoch) { Epoch = State->ActiveEpoch_.load(std::memory_order_acquire); }
        if (!Epoch || Epoch->Value().Closed.load(std::memory_order_acquire))
        {
            return {SubmissionStatus::Stopped, 0U};
        }
        if (!AsyncSubmission::ShouldWrite(Epoch->Value().Settings.Logging.Level, Request.Level) &&
            Request.Kind != SubmissionKind::Audit && Request.Level != LogLevel::Critical)
        {
            return {SubmissionStatus::Filtered, 0U};
        }
        auto EpochRequest = Request;
        EpochRequest.Epoch = std::move(Epoch);
        return AsyncSubmission::Submit(*State, EpochRequest);
    }

    BackendLifecycle::BackendLifecycle() : Owner_(std::make_unique<BackendLifecycleOwner>())
    {
    }

    BackendLifecycle::~BackendLifecycle() noexcept = default;

    auto BackendLifecycle::Install(BackendSettings Settings) -> std::expected<void, BackendError>
    {
        return Owner_->Install(std::move(Settings));
    }

    auto BackendLifecycle::PrepareEpoch(BackendSettings Settings)
        -> std::expected<Prism::Diagnose::RenderEpochPin, BackendError>
    {
        return Owner_->PrepareEpoch(std::move(Settings));
    }

    auto BackendLifecycle::PublishEpoch(const Prism::Diagnose::RenderEpochPin& Epoch) noexcept -> bool
    {
        return Owner_->PublishEpoch(Epoch);
    }

    auto BackendLifecycle::CurrentEpoch() const noexcept -> Prism::Diagnose::RenderEpochPin
    {
        return Owner_->CurrentEpoch();
    }

    auto BackendLifecycle::Submit(const SubmissionRequest& Request) noexcept -> SubmissionReceipt
    {
        return Owner_->Submit(Request);
    }

    auto BackendLifecycle::BeginShutdown() noexcept -> void
    {
        Owner_->BeginShutdown();
    }

    auto BackendLifecycle::Flush() noexcept -> void
    {
        Owner_->Flush();
    }

    auto BackendLifecycle::DrainOnControlThread(const std::chrono::milliseconds Timeout) const
        -> SubmissionReceipt
    {
        return Owner_->DrainOnControlThread(Timeout);
    }

    auto BackendLifecycle::Shutdown() noexcept -> SubmissionReceipt
    {
        return Owner_->Shutdown();
    }

    auto BackendLifecycle::IsInstalled() const noexcept -> bool
    {
        return Owner_->IsInstalled();
    }

    auto BackendLifecycle::Dropped(const LogLevel Level) const noexcept -> std::uint64_t
    {
        return Owner_->Dropped(Level);
    }

    auto BackendLifecycle::QueueHighWatermark() const noexcept -> std::size_t
    {
        return Owner_->QueueHighWatermark();
    }

    auto BackendLifecycle::TerminalFailures() const noexcept -> std::uint64_t
    {
        return Owner_->TerminalFailures();
    }

    auto BackendLifecycle::CaptureFailures() const noexcept -> std::uint64_t
    {
        return Owner_->CaptureFailures();
    }

    auto BackendLifecycle::RenderFailures() const noexcept -> std::uint64_t
    {
        return Owner_->RenderFailures();
    }

    auto BackendLifecycle::SinkFailures() const noexcept -> std::uint64_t
    {
        return Owner_->SinkFailures();
    }

    auto BackendLifecycle::Written() const noexcept -> std::uint64_t
    {
        return Owner_->Written();
    }

    auto BackendLifecycle::ResetQueueHighWatermark() noexcept -> void
    {
        Owner_->ResetQueueHighWatermark();
    }
}
