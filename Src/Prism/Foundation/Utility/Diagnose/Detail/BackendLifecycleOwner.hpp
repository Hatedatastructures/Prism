/** @file BackendLifecycleOwner.hpp
 * @brief 唯一日志记录队列、热 epoch 发布与最终输出退休。
 */
#pragma once

#include <Prism/Foundation/Utility/Diagnose/Detail/BackendBridge.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/BackendWorker.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <exception>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Diagnose::Detail
{
    /**
     * @brief process 日志资源的唯一控制 owner。
     * @details 热更新只 prepare/publish epoch；队列、worker、path owner 均保持唯一。
     */
    class BackendLifecycleOwner final
    {
        friend struct BackendLifecycleTestAccess;

    public:
        BackendLifecycleOwner() : OwnerId_(NextOwnerId()) {}
        BackendLifecycleOwner(const BackendLifecycleOwner&) = delete;
        auto operator=(const BackendLifecycleOwner&) -> BackendLifecycleOwner& = delete;
        ~BackendLifecycleOwner() noexcept
        {
            (void)Shutdown();
        }

        [[nodiscard]] auto Install(BackendSettings Settings) -> std::expected<void, BackendError>
        {
            if (const auto Existing = SnapshotState())
            {
                const auto Epoch = Existing->ActiveEpoch_.load(std::memory_order_acquire);
                if (Epoch && SameSettings(Epoch->Value().Settings, Settings))
                {
                    return {};
                }
                return std::unexpected(BackendError{
                    BackendErrorCode::ConfigurationConflict,
                    Settings.Logging.Directory.string(),
                    "Diagnose backend is already installed"});
            }
            if (const auto Invalid = Validate(Settings))
            {
                return std::unexpected(*Invalid);
            }
            const BackendLifecycleOwner* ExpectedOwner = nullptr;
            if (!OwnerSlot().compare_exchange_strong(
                ExpectedOwner, this, std::memory_order_acq_rel, std::memory_order_acquire))
            {
                return std::unexpected(BackendError{
                    BackendErrorCode::OwnerConflict,
                    Settings.Logging.Directory.string(),
                    "another Diagnose backend owner is active in this process"});
            }
            auto FailureStage = BackendErrorCode::FileOpen;
            try
            {
                auto State = std::make_shared<AsyncBackendState>(OwnerId_, Settings);
                const auto Initial = PrepareEpochForState(*State, Settings);
                if (!Initial)
                {
                    ReleaseOwner();
                    return std::unexpected(Initial.error());
                }
                State->ActiveEpoch_.store(*Initial, std::memory_order_release);
                (*Initial)->Value().Active.store(true, std::memory_order_release);
                FailureStage = BackendErrorCode::WorkerStart;
                BackendWorker::Start(*State);
                State_.store(std::move(State), std::memory_order_release);
                LastShutdown_.store(SubmissionStatus::Stopped, std::memory_order_release);
                return {};
            }
            catch (const std::bad_alloc&)
            {
                ReleaseOwner();
                throw;
            }
            catch (const std::exception& Error)
            {
                ReleaseOwner();
                return std::unexpected(BackendError{FailureStage, {}, Error.what()});
            }
        }

        [[nodiscard]] auto PrepareEpoch(BackendSettings Settings)
            -> std::expected<Prism::Diagnose::RenderEpochPin, BackendError>
        {
            const auto State = SnapshotState();
            if (!State || !State->Accepting_.load(std::memory_order_acquire))
            {
                return std::unexpected(BackendError{
                    BackendErrorCode::ResourceUnavailable, {}, "Diagnose backend is not accepting epochs"});
            }
            return PrepareEpochForState(*State, std::move(Settings));
        }

        auto PublishEpoch(const Prism::Diagnose::RenderEpochPin& Epoch) noexcept -> bool
        {
            const auto State = SnapshotState();
            if (!State || !Epoch || Epoch->Value().OwnerId != State->OwnerId_ ||
                Epoch->Value().Closed.load(std::memory_order_acquire))
            {
                return false;
            }
            auto Current = State->ActiveEpoch_.load(std::memory_order_acquire);
            for (;;)
            {
                if (!State->Accepting_.load(std::memory_order_acquire))
                {
                    return false;
                }
                if (Current)
                {
                    const auto& CandidateSettings = Epoch->Value().Settings;
                    const auto& CurrentSettings = Current->Value().Settings;
                    if (CandidateSettings.GenerationId < CurrentSettings.GenerationId ||
                        (CandidateSettings.GenerationId == CurrentSettings.GenerationId &&
                            Epoch->Value().Id <= Current->Value().Id))
                    {
                        return true;
                    }
                }
                if (State->ActiveEpoch_.compare_exchange_weak(
                    Current, Epoch, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    Epoch->Value().Active.store(true, std::memory_order_release);
                    if (Current && &Current->Value() != &Epoch->Value())
                    {
                        Current->Value().Active.store(false, std::memory_order_release);
                    }
                    BackendWorker::Wake(*State);
                    return true;
                }
            }
        }
        [[nodiscard]] auto CurrentEpoch() const noexcept -> Prism::Diagnose::RenderEpochPin
        {
            const auto State = SnapshotState();
            return State ? State->ActiveEpoch_.load(std::memory_order_acquire)
                         : Prism::Diagnose::RenderEpochPin{};
        }

        [[nodiscard]] auto Submit(const SubmissionRequest& Request) noexcept -> SubmissionReceipt
        {
            const auto State = SnapshotState();
            return BackendBridge::Submit(Request, State.get());
        }

        auto BeginShutdown() noexcept -> void
        {
            if (const auto State = SnapshotState())
            {
                AsyncSubmission::Stop(*State);
            }
        }

        auto Flush() noexcept -> void
        {
            if (const auto State = SnapshotState())
            {
                AsyncSubmission::Flush(*State);
            }
        }

        [[nodiscard]] auto DrainOnControlThread(const std::chrono::milliseconds Timeout) const
            -> SubmissionReceipt
        {
            const auto State = SnapshotState();
            if (!State)
            {
                return {SubmissionStatus::Stopped, 0U};
            }
            if (Timeout < std::chrono::milliseconds::zero())
            {
                return {SubmissionStatus::TimedOut, 0U, {Prism::Fault::Code::Timeout}};
            }
            const auto Now = std::chrono::steady_clock::now();
            const auto Remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::time_point::max() - Now);
            if (Timeout > Remaining)
            {
                return {SubmissionStatus::Failed, 0U, {Prism::Fault::Code::InvalidArgument}};
            }
            return AsyncSubmission::DrainOnControlThread(*State, Now + Timeout);
        }

        [[nodiscard]] static auto ShutdownState(AsyncBackendState& State) noexcept -> SubmissionReceipt
        {
            AsyncSubmission::Stop(State);
            while (State.EnqueueGate_.test_and_set(std::memory_order_acquire))
            {
                State.EnqueueGate_.wait(true, std::memory_order_acquire);
            }
            State.Stopping_.store(true, std::memory_order_release);
            State.EnqueueGate_.clear(std::memory_order_release);
            State.EnqueueGate_.notify_all();
            BackendWorker::Wake(State);
            if (State.Worker_.joinable())
            {
                State.Worker_.join();
            }
            const auto Closed = State.CloseOutputs();
            if (!Closed)
            {
                State.SinkFailures_.fetch_add(1U, std::memory_order_relaxed);
            }
            if (State.WorkerFailed_.load(std::memory_order_acquire) ||
                !State.FinalFlushSucceeded_.load(std::memory_order_acquire) ||
                !Closed ||
                !State.FinalCloseSucceeded_.load(std::memory_order_acquire) ||
                State.SinkFailures_.load(std::memory_order_relaxed) != 0U)
            {
                return {SubmissionStatus::Failed, 0U, {Prism::Fault::Code::IoError}};
            }
            return {
                SubmissionStatus::Closed,
                State.LastWrittenSequence_.load(std::memory_order_acquire)};
        }

        [[nodiscard]] auto Shutdown() noexcept -> SubmissionReceipt
        {
            BeginShutdown();
            const auto State = State_.exchange({}, std::memory_order_acq_rel);
            if (!State)
            {
                return {LastShutdown_.load(std::memory_order_acquire), 0U};
            }
            const auto Result = ShutdownState(*State);
            LastShutdown_.store(Result.Status, std::memory_order_release);
            ReleaseOwner();
            return Result;
        }

        [[nodiscard]] auto IsInstalled() const noexcept -> bool
        {
            const auto State = SnapshotState();
            return State && State->Accepting_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Dropped(const LogLevel Level) const noexcept -> std::uint64_t
        {
            const auto State = SnapshotState();
            return State ? State->Dropped(Level) : 0U;
        }

        [[nodiscard]] auto QueueHighWatermark() const noexcept -> std::size_t
        {
            const auto State = SnapshotState();
            return State ? State->QueueHighWatermark() : 0U;
        }

        [[nodiscard]] auto TerminalFailures() const noexcept -> std::uint64_t
        {
            const auto State = SnapshotState();
            return State ? State->TerminalFailures() : 0U;
        }

        [[nodiscard]] auto CaptureFailures() const noexcept -> std::uint64_t
        {
            const auto State = SnapshotState();
            return State ? State->CaptureFailures_.load(std::memory_order_relaxed) : 0U;
        }

        [[nodiscard]] auto RenderFailures() const noexcept -> std::uint64_t
        {
            const auto State = SnapshotState();
            return State ? State->RenderFailures_.load(std::memory_order_relaxed) : 0U;
        }

        [[nodiscard]] auto SinkFailures() const noexcept -> std::uint64_t
        {
            const auto State = SnapshotState();
            return State ? State->SinkFailures_.load(std::memory_order_relaxed) : 0U;
        }

        [[nodiscard]] auto Written() const noexcept -> std::uint64_t
        {
            const auto State = SnapshotState();
            return State ? State->Written_.load(std::memory_order_relaxed) : 0U;
        }

        auto ResetQueueHighWatermark() noexcept -> void
        {
            if (const auto State = SnapshotState())
            {
                State->ResetQueueHighWatermark();
            }
        }

    private:
        [[nodiscard]] static auto PrepareEpochForState(
            AsyncBackendState& State, BackendSettings Settings)
            -> std::expected<Prism::Diagnose::RenderEpochPin, BackendError>
        {
            if (const auto Invalid = Validate(Settings))
            {
                return std::unexpected(*Invalid);
            }
            if (Settings.Logging.QueueCapacity != State.Settings_.Logging.QueueCapacity ||
                Settings.Logging.QueueBytes != State.Settings_.Logging.QueueBytes)
            {
                return std::unexpected(BackendError{
                    BackendErrorCode::ConfigurationConflict,
                    Settings.Logging.Directory.string(),
                    "Diagnose epoch cannot resize the installed bounded queue"});
            }
            const auto Path = PathSinkOwner::ResolvePath(Settings);
            if (!Path)
            {
                return std::unexpected(Path.error());
            }
            Prism::Diagnose::Detail::EpochGateGuard Lock(State.EpochGate_);
            if (!Lock.Acquired())
            {
                return std::unexpected(BackendError{
                    BackendErrorCode::ResourceUnavailable, Path->string(), "Diagnose epoch registry is busy"});
            }
            if (!State.Accepting_.load(std::memory_order_acquire))
            {
                return std::unexpected(BackendError{
                    BackendErrorCode::ResourceUnavailable, Path->string(), "Diagnose backend is closing"});
            }
            if (State.Epochs_.size() >= AsyncBackendState::MaxRetainedEpochs ||
                State.NextEpochId_ == UINT64_MAX)
            {
                return std::unexpected(BackendError{
                    BackendErrorCode::ResourceUnavailable,
                    Path->string(),
                    "Diagnose retained epoch budget is exhausted"});
            }
            auto Owner = State.PathOwners_.find(*Path);
            const bool NewOwner = Owner == State.PathOwners_.end();
            if (NewOwner && State.PathOwners_.size() >= AsyncBackendState::MaxPathOwners)
            {
                return std::unexpected(BackendError{
                    BackendErrorCode::ResourceUnavailable,
                    Path->string(),
                    "Diagnose physical path owner budget is exhausted"});
            }
            std::shared_ptr<PathSinkOwner> PathOwner;
            if (NewOwner)
            {
                const auto Created = PathSinkOwner::Create(*Path, Settings.Mode);
                if (!Created)
                {
                    return std::unexpected(Created.error());
                }
                PathOwner = *Created;
            }
            else
            {
                PathOwner = Owner->second;
            }
            const auto Sinks = SinkSet::Create(PathOwner, Settings.Logging.Console);
            if (!Sinks)
            {
                return std::unexpected(Sinks.error());
            }
            if (State.NextEpochId_ == 0U)
            {
                return std::unexpected(BackendError{
                    BackendErrorCode::ResourceUnavailable, Path->string(), "Diagnose epoch id is exhausted"});
            }
            auto Epoch = std::make_shared<RenderEpoch>(
                RenderEpochIdentity{State.NextEpochId_, State.OwnerId_},
                std::move(Settings), *Sinks);
            Prism::Diagnose::RenderEpochPin Pin{
                new RenderEpochPin(Epoch, State.Wake_)};
            EpochRegistration Registration{Epoch, Epoch->CloseState, *Path};
            State.Epochs_.push_back(std::move(Registration));
            if (NewOwner)
            {
                State.PathOwners_.emplace(*Path, std::move(PathOwner));
            }
            ++State.NextEpochId_;
            return Pin;
        }

        [[nodiscard]] static auto Validate(const BackendSettings& Settings)
            -> std::optional<BackendError>
        {
            const auto& Options = Settings.Logging;
            if (!Options.Formatting.Valid() ||
                static_cast<std::uint8_t>(Options.Level) > static_cast<std::uint8_t>(LogLevel::Off) ||
                static_cast<std::uint8_t>(Settings.Mode) > static_cast<std::uint8_t>(RenderMode::Structured) ||
                Options.Directory.empty() || Options.FileName.empty() || Options.FileName == "." ||
                Options.FileName == ".." || Options.FileName.find_first_of("/\\:") != std::string::npos ||
                Options.QueueCapacity == 0U ||
                Options.QueueCapacity > Options.QueueBytes / sizeof(SubmissionSnapshot) ||
                Options.RotateBytes < 4096U || Options.RotateBytes > 1024ULL * 1024ULL * 1024ULL ||
                Options.RotateFiles == 0U || Options.RotateFiles > 64U ||
                Settings.FlushIntervalMs == 0U || Settings.FlushIntervalMs > 600000U)
            {
                return BackendError{
                    BackendErrorCode::InvalidOptions,
                    Options.Directory.string(),
                    "invalid Diagnose backend options"};
            }
            return {};
        }

        [[nodiscard]] static auto SameSettings(
            const BackendSettings& Left, const BackendSettings& Right) noexcept -> bool
        {
            const auto& A = Left.Logging;
            const auto& B = Right.Logging;
            return A.Level == B.Level && A.Directory == B.Directory && A.FileName == B.FileName &&
                A.Console == B.Console && A.QueueCapacity == B.QueueCapacity &&
                A.QueueBytes == B.QueueBytes && A.RotateBytes == B.RotateBytes &&
                A.RotateFiles == B.RotateFiles && Left.Mode == Right.Mode &&
                A.Formatting.MaximumWidth == B.Formatting.MaximumWidth &&
                A.Formatting.MaximumPrecision == B.Formatting.MaximumPrecision &&
                A.Formatting.WorkBytes == B.Formatting.WorkBytes &&
                Left.TraceSelection.IncludeCorrelation == Right.TraceSelection.IncludeCorrelation &&
                Left.TraceSelection.IncludeWorker == Right.TraceSelection.IncludeWorker &&
                Left.TraceSelection.IncludeSession == Right.TraceSelection.IncludeSession &&
                Left.TraceSelection.IncludeStream == Right.TraceSelection.IncludeStream &&
                Left.FlushIntervalMs == Right.FlushIntervalMs &&
                Left.GenerationId == Right.GenerationId;
        }

        static auto NextOwnerId() noexcept -> std::uint64_t
        {
            static std::atomic<std::uint64_t> Next{1U};
            return Next.fetch_add(1U, std::memory_order_relaxed);
        }

        static auto OwnerSlot() noexcept -> std::atomic<const BackendLifecycleOwner*>&
        {
            static std::atomic<const BackendLifecycleOwner*> Owner{nullptr};
            return Owner;
        }

        auto ReleaseOwner() noexcept -> void
        {
            const BackendLifecycleOwner* ExpectedOwner = this;
            (void)OwnerSlot().compare_exchange_strong(
                ExpectedOwner, nullptr, std::memory_order_acq_rel, std::memory_order_acquire);
        }

        [[nodiscard]] auto SnapshotState() const noexcept -> std::shared_ptr<AsyncBackendState>
        {
            return State_.load(std::memory_order_acquire);
        }

        const std::uint64_t OwnerId_;
        std::atomic<std::shared_ptr<AsyncBackendState>> State_{};
        std::atomic<SubmissionStatus> LastShutdown_{SubmissionStatus::Stopped};
    };
}
