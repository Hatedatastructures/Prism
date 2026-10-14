/** @file State.hpp @brief AnyTLS 唯一根与每条实际 StreamLease 的 protocol-owned 状态。 */
#pragma once
#include <Preview/Protocols/Anytls/Anytls.hpp>
#include <Preview/Protocols/Anytls/Detail/Session/Writer.hpp>
#include <Preview/Protocols/Anytls/Detail/Session/Retirement.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Contract/Ingress/MuxSession.hpp>
#include <Preview/Contract/Services/Stream.hpp>
#include <Preview/Lifecycle/DrainBarrier.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/system/system_error.hpp>
#include <unordered_map>
#include <exception>
#include <system_error>
#include <vector>

namespace Preview::Anytls::Detail
{
    [[nodiscard]] inline auto StateFailureFromException(std::exception_ptr Exception) noexcept
        -> Preview::Fault::Failure
    {
        try
        {
            if (Exception) std::rethrow_exception(Exception);
        }
        catch (const boost::system::system_error &Error)
        {
            return Preview::Fault::FromNative(static_cast<std::error_code>(Error.code()));
        }
        catch (const std::system_error &Error)
        {
            return Preview::Fault::FromNative(Error.code());
        }
        catch (...)
        {
            return {Preview::Fault::Code::IoError};
        }
        return {Preview::Fault::Code::IoError};
    }

    struct StreamState final
    {
        using DataChannel = Net::experimental::channel<void(boost::system::error_code, std::vector<std::byte>)>;
        StreamState(Net::any_io_executor Ex, std::shared_ptr<Preview::Lifecycle::TaskRegistry> Scope)
            : Data(std::make_shared<DataChannel>(Ex, 32)), Tasks(std::move(Scope)) {}
        auto Cancel() noexcept -> void
        {
            try { Cancellation.emit(Net::cancellation_type::all); }
            catch (...) { SaveCloseFailure(std::current_exception()); }
            try { Data->close(); }
            catch (...) { SaveCloseFailure(std::current_exception()); }
            if (Nested)
            {
                try { Nested->Cancel(); }
                catch (...) { SaveCloseFailure(std::current_exception()); }
            }
            if (Outbound)
            {
                try
                {
                    const auto Canceled = Outbound->Cancel();
                    if (!Canceled)
                    {
                        const auto Stored = ControlFailure.TrySet(Canceled.error());
                        (void)Stored;
                    }
                }
                catch (...) { SaveCloseFailure(std::current_exception()); }
            }
            try { (void)Tasks->Cancel(); }
            catch (...) { SaveCloseFailure(std::current_exception()); }
        }
        auto SaveCloseFailure(std::exception_ptr Error) noexcept -> void
        { if (!CloseFailure && Error) CloseFailure = std::move(Error); }
        std::uint32_t Id{0};
        Preview::Lifecycle::TaskIdentity Identity;
        Preview::Account::StreamLease Lease;
        std::shared_ptr<DataChannel> Data;
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Tasks;
        Preview::SharedTransmission Outbound;
        std::shared_ptr<TransportRetirement> Retirement;
        bool RetirementAttached{false};
        std::shared_ptr<Preview::Contract::MuxSession> Nested;
        Net::cancellation_signal Cancellation;
        std::exception_ptr CloseFailure;
        Preview::Fault::FailureState ControlFailure;
        bool PeerFin{false}, FinSent{false};
    };
    struct State final : std::enable_shared_from_this<State>
    {
        State(SharedConn Value, Preview::Contract::StreamServices ServicesValue,
            std::shared_ptr<Preview::Foundation::GenerationUseState> UseState)
            : Connection(std::move(Value)), Services(std::move(ServicesValue)),
              GenerationUseState(std::move(UseState)),
              Executor(Net::make_strand(Connection->Executor())),
              Loops(std::make_shared<Preview::Lifecycle::TaskRegistry>(Executor)),
              Children(std::make_shared<Preview::Lifecycle::TaskRegistry>(Executor)),
              Writes(std::make_shared<Preview::Lifecycle::TaskRegistry>(Executor)),
              Lifetime(Loops->Reclaimer()),
              Writer(std::make_shared<FrameWriter>(Connection, Writes)) {}
        auto Stop() noexcept -> void
        {
            if (Stopping.exchange(true)) return;
            const auto Self = shared_from_this();
            try { Net::dispatch(Executor, [Self] { Self->StopOnExecutor(); }); }
            catch (...) { RecordTerminalFailure(StateFailureFromException(std::current_exception())); }
        }
        auto StopOnExecutor() noexcept -> void
        {
            Stopping.store(true);
            const auto WriterClosed = Writer->Close();
            if (!WriterClosed) RecordTerminalFailure(WriterClosed.error());
            for (const auto& [Id, Stream] : Streams) { (void)Id; Stream->Cancel(); }
            (void)Loops->Cancel(); (void)Children->Cancel(); (void)Writes->Cancel();
        }
        struct ChildDrainProgress final
        {
            std::expected<void, Preview::Fault::Failure> FirstFailure;
            bool Incomplete{false};
        };
        auto RecordChildDrainFailure(ChildDrainProgress &Progress,
            Preview::Fault::Failure Failure) noexcept -> void
        {
            RecordTerminalFailure(Failure);
            if (Progress.FirstFailure)
                Progress.FirstFailure = std::unexpected(Failure);
        }
        auto DrainNestedStream(std::uint32_t Id,
            const std::shared_ptr<StreamState> &Stream, ChildDrainProgress &Progress)
            -> Net::awaitable<void>
        {
            const auto Nested = Stream->Nested;
            if (!Nested) co_return;
            Nested->Close();
            std::expected<void, Preview::Fault::Failure> Result;
            const auto Activity = Nested->Activity();
            if (!Activity)
                Result = std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            else
            {
                try { Result = co_await Activity->Drain(); }
                catch (...)
                {
                    Result = std::unexpected(
                        StateFailureFromException(std::current_exception()));
                }
            }
            co_await Net::dispatch(Executor, Net::use_awaitable);
            const auto Found = Streams.find(Id);
            if (Found == Streams.end() || Found->second != Stream || Stream->Nested != Nested)
                co_return;
            if (!Nested->IsRetired())
            {
                Progress.Incomplete = true;
                RecordChildDrainFailure(Progress, Result
                    ? Preview::Fault::Failure{Preview::Fault::Code::Blocked}
                    : Result.error());
                co_return;
            }
            if (!Result) RecordChildDrainFailure(Progress, Result.error());
            Stream->Nested.reset();
        }
        auto DrainOutbound(std::uint32_t Id,
            const std::shared_ptr<StreamState> &Stream, ChildDrainProgress &Progress)
            -> Net::awaitable<void>
        {
            const auto Found = Streams.find(Id);
            if (Found == Streams.end() || Found->second != Stream) co_return;
            if (Stream->Outbound)
            {
                if (!Stream->Retirement)
                {
                    Progress.Incomplete = true;
                    RecordChildDrainFailure(Progress,
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                    co_return;
                }
                if (!Stream->RetirementAttached)
                {
                    const auto Attached = Stream->Retirement->Attach(
                        std::move(Stream->Outbound), std::move(Stream->Lease));
                    if (!Attached)
                    {
                        Progress.Incomplete = true;
                        RecordChildDrainFailure(Progress, Attached.error());
                        co_return;
                    }
                    Stream->RetirementAttached = true;
                }
            }
            if (!Stream->RetirementAttached || !Stream->Retirement ||
                Stream->Retirement->IsRetired()) co_return;
            Stream->Retirement->RetainForRetry();
            std::expected<void, Preview::Fault::Failure> Result;
            try { Result = co_await Stream->Retirement->RetireAndDrain(); }
            catch (...)
            {
                Result = std::unexpected(StateFailureFromException(std::current_exception()));
                Stream->Retirement->RequestRetirement();
            }
            co_await Net::dispatch(Executor, Net::use_awaitable);
            const auto Current = Streams.find(Id);
            if (Current == Streams.end() || Current->second != Stream) co_return;
            if (!Result) RecordChildDrainFailure(Progress, Result.error());
            if (!Stream->Retirement->IsRetired())
            {
                Progress.Incomplete = true;
                if (Result)
                    RecordChildDrainFailure(Progress,
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                Stream->Retirement->RequestRetirement();
            }
        }
        auto DrainStreamTasks(const std::shared_ptr<StreamState> &Stream,
            ChildDrainProgress &Progress) -> Net::awaitable<void>
        {
            if (!Stream->Tasks) co_return;
            std::expected<void, Preview::Fault::Failure> Result;
            try { Result = co_await Stream->Tasks->Drain(); }
            catch (...)
            {
                Result = std::unexpected(StateFailureFromException(std::current_exception()));
            }
            if (!Result) RecordChildDrainFailure(Progress, Result.error());
            const auto Stats = Stream->Tasks->Stats();
            if (Stats.Active != 0U || Stats.DrainBlocked)
            {
                Progress.Incomplete = true;
                if (Result)
                    RecordChildDrainFailure(Progress,
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
        }
        auto RemoveRetiredStream(std::uint32_t Id,
            const std::shared_ptr<StreamState> &Stream) -> void
        {
            const auto Found = Streams.find(Id);
            if (Found == Streams.end() || Found->second != Stream) return;
            const auto Stats = Stream->Tasks ? Stream->Tasks->Stats()
                : Preview::Lifecycle::TaskStats{};
            const bool RetirementUnknown = Stream->RetirementAttached &&
                (!Stream->Retirement || !Stream->Retirement->IsRetired());
            if (Stream->Nested || Stream->Outbound || RetirementUnknown ||
                Stats.Active != 0U || Stats.DrainBlocked) return;
            if (Stream->Lease) Stream->Lease.Release();
            Stream->Retirement.reset();
            Streams.erase(Found);
        }
        [[nodiscard]] auto DrainChildren()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_await Net::dispatch(Executor, Net::use_awaitable);
            ChildDrainProgress Progress;
            std::vector<std::pair<std::uint32_t, std::shared_ptr<StreamState>>> Pending;
            Pending.reserve(Streams.size());
            for (const auto &[Id, Stream] : Streams)
                if (Stream) Pending.emplace_back(Id, Stream);
            for (const auto &[Id, Stream] : Pending)
            {
                const auto Found = Streams.find(Id);
                if (Found == Streams.end() || Found->second != Stream) continue;
                co_await DrainNestedStream(Id, Stream, Progress);
                co_await DrainOutbound(Id, Stream, Progress);
                co_await DrainStreamTasks(Stream, Progress);
                const auto ControlFailure = Stream->ControlFailure.Load();
                if (ControlFailure.Failed()) RecordChildDrainFailure(Progress, ControlFailure);
                if (Stream->CloseFailure)
                    RecordChildDrainFailure(Progress,
                        StateFailureFromException(Stream->CloseFailure));
                RemoveRetiredStream(Id, Stream);
            }
            ChildRetirementFailed = Progress.Incomplete;
            if (!Progress.FirstFailure)
                co_return std::unexpected(Progress.FirstFailure.error());
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
        auto ReleaseRetired() noexcept -> void
        {
            if (ResourcesRetired.load(std::memory_order_acquire)) return;
            Streams.clear();
            Admission = {};
            Lease.Release();
            Services = {};
            GenerationUseState.reset();
            Connection.reset();
            Writer.reset();
            GenerationLease = {};
            ParentStreamLease.Release();
            ResourcesRetired.store(true, std::memory_order_release);
        }
        SharedConn Connection;
        Preview::Contract::StreamServices Services;
        Net::strand<Net::any_io_executor> Executor;
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Loops, Children, Writes;
        Preview::Lifecycle::DrainBarrier Lifetime;
        std::shared_ptr<FrameWriter> Writer;
        Preview::Account::AccountLease Lease;
        Preview::Account::StreamLease ParentStreamLease;
        Preview::Account::StreamAdmission Admission;
        std::shared_ptr<Preview::Foundation::GenerationUseState> GenerationUseState;
        Preview::Foundation::GenerationUseLease GenerationLease;
        Preview::Contract::RequestMetadata Metadata;
        std::unordered_map<std::uint32_t, std::shared_ptr<StreamState>> Streams;
        std::atomic_bool Started{false}, Stopping{false};
        std::atomic_bool ResourcesRetired{false};
        bool ChildRetirementFailed{false};
        std::uint32_t LastStreamId{0}, PeerVersion{1};
        bool SettingsReceived{false};
        Preview::Fault::FailureState TerminalFailure;
        auto RecordTerminalFailure(const Preview::Fault::Failure &Failure) noexcept -> void
        {
            if (Failure.Succeeded()) return;
            const auto Stored = TerminalFailure.TrySet(Failure);
            (void)Stored;
        }
    };
}
