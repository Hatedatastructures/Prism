/**
 * @file AdmissionLifecycle.cpp
 * @brief Hysteria2 admission 关闭与子任务退休实现。
 */
#include <Prism/Protocols/Hysteria2/Admission.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Protocols/Hysteria2/Datagram/Session.hpp>
#include <Prism/Protocols/Hysteria2/Detail/Admission.hpp>
#include <Prism/Protocols/Hysteria2/StreamSession.hpp>

#include <cassert>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <new>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Hysteria2
{
    auto CloseStream(const Prism::Quic::SharedStreamProvider &Provider) noexcept
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Provider)
        {
            return {};
        }
        try
        {
            return Provider->Close();
        }
        catch (...)
        {
            return std::unexpected(Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception()));
        }
    }

    auto CloseDatagram(const Prism::Quic::SharedDatagramProvider &Provider) noexcept
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Provider)
        {
            return {};
        }
        try
        {
            Provider->Cancel();
            Provider->Close();
            return {};
        }
        catch (...)
        {
            return std::unexpected(Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception()));
        }
    }

    auto ConnectionAdmission::Create(AdmissionOptions Options, AdmissionServices Services)
        -> std::expected<std::shared_ptr<ConnectionAdmission>, Prism::Fault::Failure>
    {
        if (!Options.Executor || !Options.AuthSession)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto StreamLimit = std::vector<Prism::Quic::SharedStreamProvider>{}.max_size();
        if (Options.MaxPendingBidiStreams > StreamLimit)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::value_too_large)});
        }
        ConnectionAdmission *Admission = nullptr;
        try
        {
            Admission = new ConnectionAdmission(std::move(Options), std::move(Services));
        }
        catch (const std::bad_alloc &)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::not_enough_memory)});
        }
        const auto Executor = Admission->Executor_;
        try
        {
            return std::shared_ptr<ConnectionAdmission>(Admission,
                [Executor](ConnectionAdmission *Value)
                {
                    Net::dispatch(Executor, [Value] { delete Value; });
                });
        }
        catch (const std::bad_alloc &)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::not_enough_memory)});
        }
    }

    ConnectionAdmission::ConnectionAdmission(
        AdmissionOptions Options,
        AdmissionServices Services)
        : Executor_(Net::make_strand(Options.Executor)),
          Options_(std::move(Options)),
          Services_(std::move(Services)),
          Fatal_(Prism::Executor::FatalState::For(Executor_)),
          AuthSession_(Options_.AuthSession),
          Children_(std::make_shared<Prism::Executor::ExecutorReclaimer>(Executor_))
    {
        PendingStreams_.reserve(Options_.MaxPendingBidiStreams);
    }

    ConnectionAdmission::~ConnectionAdmission() noexcept
    {
        assert(Executor_.running_in_this_thread() || Closed_);
        if (Executor_.running_in_this_thread())
        {
            CloseOnExecutor();
        }
    }

    auto ConnectionAdmission::HandleEvent(Prism::Http3::ServerEvent Event)
        -> Net::awaitable<Prism::Http3::SessionAction>
    {
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        if (Failure_.Load().Failed())
        {
            if (auto *Raw = std::get_if<Prism::Http3::RawStreamEvent>(&Event))
            {
                const auto Closed = CloseStream(Raw->Provider);
                if (!Closed) RecordFailure(Closed.error());
            }
            co_return Prism::Http3::SessionAction{};
        }
        if (Closed_)
        {
            LastError_ = AdmissionError::Closed;
            co_return Prism::Http3::SessionAction{};
        }
        if (auto *Request = std::get_if<Prism::Http3::RequestEvent>(&Event))
        {
            const auto StreamId = Request->StreamId;
            auto Result = AuthSession_->HandleRequest(std::move(*Request));
            if (!Result)
            {
                LastError_ = MapAuthError(Result.error());
                if (Result.error() == AuthError::Closed)
                {
                    co_return Prism::Http3::SessionAction{};
                }
                co_return Prism::Http3::SessionAction(
                    BuildAuthFailureResponse(StreamId, Result.error()));
            }
            Authenticated_ = true;
            LastError_.reset();
            RemovePendingStream(Request->StreamId);
            StartPendingChildren();
            co_return Prism::Http3::SessionAction(std::move(*Result));
        }
        if (auto *Raw = std::get_if<Prism::Http3::RawStreamEvent>(&Event))
        {
            if (!Authenticated_)
            {
                if (PendingStreams_.size() >= Options_.MaxPendingBidiStreams)
                {
                    const auto Closed = CloseStream(Raw->Provider);
                    if (!Closed) RecordFailure(Closed.error());
                    LastError_ = AdmissionError::StreamQuota;
                }
                else
                {
                    PendingStreams_.push_back(Raw->Provider);
                }
                co_return Prism::Http3::SessionAction{};
            }
            StartStream(Raw->Provider);
            co_return Prism::Http3::SessionAction{Prism::Http3::StreamMode::Opaque};
        }
        co_return Prism::Http3::SessionAction{};
    }

    auto ConnectionAdmission::OnDatagram(Prism::Quic::SharedDatagramProvider Provider)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Provider) return {};
        const auto ExistingFailure = Failure_.Load();
        if (ExistingFailure.Failed()) return std::unexpected(ExistingFailure);
        auto Identity = DatagramIdentity_.load(std::memory_order_acquire);
        if (Identity == Provider) return {};
        if (Identity || !DatagramIdentity_.compare_exchange_strong(
                Identity, Provider, std::memory_order_acq_rel))
        {
            if (Identity == Provider) return {};
            RecordFailure({Prism::Fault::Code::ResourceUnavailable});
            return std::unexpected(Failure_.Load());
        }
        DatagramIngress_.store(Provider, std::memory_order_release);
        auto Self = shared_from_this();
        try
        {
            Net::dispatch(Executor_, [Self] { Self->AdmitPendingDatagram(); });
        }
        catch (...)
        {
            RecordFatal(std::current_exception());
            return std::unexpected(Failure_.Load());
        }
        return {};
    }

    auto ConnectionAdmission::AdmitPendingDatagram() -> void
    {
        try
        {
            auto Provider = DatagramIngress_.exchange({}, std::memory_order_acq_rel);
            if (Provider) AdmitDatagram(std::move(Provider));
        }
        catch (...)
        {
            RecordFatal(std::current_exception());
        }
    }

    auto ConnectionAdmission::AdmitDatagram(
        Prism::Quic::SharedDatagramProvider Provider) -> void
    {
        if (Failure_.Load().Failed())
        {
            FailedDatagramProvider_ = Provider;
            return;
        }
        if (Closed_ || !Provider)
        {
            const auto Closed = CloseDatagram(Provider);
            if (!Closed) RecordFailure(Closed.error());
            return;
        }
        if (!Authenticated_)
        {
            if (PendingDatagram_ ||
                PendingDatagrams_ >= Options_.MaxPendingDatagrams)
            {
                const auto Closed = CloseDatagram(Provider);
                if (!Closed) RecordFailure(Closed.error());
                LastError_ = AdmissionError::DatagramQuota;
                return;
            }
            PendingDatagram_ = std::move(Provider);
            ++PendingDatagrams_;
            return;
        }
        StartDatagram(std::move(Provider));
    }

    auto ConnectionAdmission::Close() -> void
    {
        if (CloseQueued_.exchange(true, std::memory_order_acq_rel)) return;
        auto Self = shared_from_this();
        try
        {
            Net::dispatch(Executor_, [Self] { Self->CloseOnExecutor(); });
        }
        catch (...)
        {
            RecordFatal(std::current_exception());
        }
    }

    auto ConnectionAdmission::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Self = shared_from_this();
        (void)Self;
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        if (OwnerCloseFailure_) RetryOwnerClose_ = true;
        AdmitPendingDatagram();
        CloseOnExecutor();
        const auto Drained = co_await Children_.Drain();
        MaybeFinishClose();
        const auto Failure = Failure_.Load();
        if (Failure.Failed()) co_return std::unexpected(Failure);
        if (OwnerCloseFailure_)
        {
            co_return std::unexpected(*OwnerCloseFailure_);
        }
        if (!Drained) co_return std::unexpected(Drained.error());
        if (!ActiveStreams_.empty() || ActiveDatagram_ || FailedStreamProvider_ ||
            FailedStreamOwner_ || FailedDatagramProvider_ || FailedDatagramOwner_)
        {
            RecordFailure({Prism::Fault::Code::Blocked});
            co_return std::unexpected(Failure_.Load());
        }
        DatagramIngress_.store({}, std::memory_order_release);
        DatagramIdentity_.store({}, std::memory_order_release);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto ConnectionAdmission::OnClosed() -> void
    {
        Close();
    }

    auto ConnectionAdmission::Authenticated() const noexcept -> bool
    {
        return Authenticated_ && AuthSession_->Authenticated();
    }

    auto ConnectionAdmission::Closed() const noexcept -> bool
    {
        return Closed_;
    }

    auto ConnectionAdmission::LastError() const noexcept
        -> std::optional<AdmissionError>
    {
        return LastError_;
    }

    auto ConnectionAdmission::FinishStream(
        const std::uint64_t Id,
        const Prism::Fault::Code Status) noexcept -> void
    {
        if (Status == Prism::Fault::Code::GenericError)
        {
            RecordFailure({Status});
        }
        ActiveStreams_.erase(Id);
        Children_.Leave();
        MaybeFinishClose();
    }

    auto ConnectionAdmission::FinishDatagram(std::exception_ptr Error) noexcept -> void
    {
        if (Error) RecordFatal(std::move(Error));
        ActiveDatagram_.reset();
        Children_.Leave();
        MaybeFinishClose();
    }

    auto ConnectionAdmission::MaybeFinishClose() noexcept -> void
    {
        if (!Closed_ || !ActiveStreams_.empty() || ActiveDatagram_)
        {
            return;
        }
        AuthSession_->Close();
        const auto CloseResult = RequestOwnerClose();
        if (!CloseResult) return;
    }

    auto ConnectionAdmission::CloseOnExecutor() noexcept -> void
    {
        if (Closed_)
        {
            MaybeFinishClose();
            return;
        }
        Closed_ = true;
        Children_.Seal();
        for (auto &Provider : PendingStreams_)
        {
            const auto Closed = CloseStream(Provider);
            if (!Closed) RecordFailure(Closed.error());
        }
        PendingStreams_.clear();
        const auto PendingDatagramClosed = CloseDatagram(PendingDatagram_);
        if (!PendingDatagramClosed) RecordFailure(PendingDatagramClosed.error());
        PendingDatagram_.reset();
        PendingDatagrams_ = 0;
        for (auto &[Id, Child] : ActiveStreams_)
        {
            (void)Id;
            Child->Close();
        }
        if (ActiveDatagram_)
        {
            ActiveDatagram_->Close();
        }
        if (FailedStreamOwner_) FailedStreamOwner_->Close();
        else
        {
            const auto Closed = CloseStream(FailedStreamProvider_);
            if (!Closed) RecordFailure(Closed.error());
        }
        if (FailedDatagramOwner_) FailedDatagramOwner_->Close();
        else
        {
            const auto Closed = CloseDatagram(FailedDatagramProvider_);
            if (!Closed) RecordFailure(Closed.error());
        }
        MaybeFinishClose();
    }

    auto ConnectionAdmission::RecordFailure(Prism::Fault::Failure Failure) noexcept -> void
    {
        if (Failure.Succeeded()) Failure = {Prism::Fault::Code::Blocked};
        if (!Failure_.TrySet(Failure)) return;
        Children_.Block();
        if (Executor_.running_in_this_thread())
        {
            const auto CloseResult = RequestOwnerClose();
            if (!CloseResult) return;
        }
        else
        {
            Close();
        }
    }

    auto ConnectionAdmission::RecordFatal(std::exception_ptr Error) noexcept -> void
    {
        Fatal_->Publish(std::move(Error));
        RecordFailure({Prism::Fault::Code::Blocked});
    }

    auto ConnectionAdmission::RequestOwnerClose() noexcept
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (CloseOwnerAccepted_) return {};
        if (OwnerCloseFailure_)
        {
            if (!RetryOwnerClose_) return std::unexpected(*OwnerCloseFailure_);
            RetryOwnerClose_ = false;
        }
        if (!Options_.CloseOwner)
        {
            CloseOwnerAccepted_ = true;
            OwnerCloseFailure_.reset();
            return {};
        }
        try
        {
            const auto Result = Options_.CloseOwner();
            if (!Result)
            {
                if (!OwnerCloseFailure_) OwnerCloseFailure_ = Result.error();
                return std::unexpected(*OwnerCloseFailure_);
            }
            CloseOwnerAccepted_ = true;
            OwnerCloseFailure_.reset();
            return {};
        }
        catch (...)
        {
            Fatal_->Publish(std::current_exception());
            const Prism::Fault::Failure Failure{Prism::Fault::Code::Blocked};
            if (!OwnerCloseFailure_) OwnerCloseFailure_ = Failure;
            return std::unexpected(*OwnerCloseFailure_);
        }
    }
}
