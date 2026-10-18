/** @file AdmissionLifecycle.hpp @brief Hysteria2 输入准入、关闭请求与 child 退栈状态 owner。 */
#pragma once

#include <Prism/Protocols/Hysteria2/Admission.hpp>
#include <Prism/Protocols/Hysteria2/DatagramSession.hpp>
#include <Prism/Protocols/Hysteria2/StreamSession.hpp>
#include <new>
#include <system_error>

/** @brief 服务与 admission 声明完整后再引入 child owner，避免契约循环。 */

namespace Prism::Hysteria2
{
    namespace
    {

        auto CloseStream(const Prism::Quic::SharedStreamProvider &Provider) noexcept -> void
        {
            if (Provider)
            {
                try
                {
                    Provider->Close();
                }
                catch (...)
                {
                }
            }
        }

        auto CloseDatagram(const Prism::Quic::SharedDatagramProvider &Provider) noexcept -> void
        {
            if (Provider)
            {
                try
                {
                    Provider->Cancel();
                    Provider->Close();
                }
                catch (...)
                {
                }
            }
        }

    } // namespace

    inline auto ConnectionAdmission::Create(AdmissionOptions Options, AdmissionServices Services)
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

    inline ConnectionAdmission::ConnectionAdmission(
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

    inline ConnectionAdmission::~ConnectionAdmission() noexcept
    {
        assert(Executor_.running_in_this_thread() || Closed_);
        if (Executor_.running_in_this_thread())
        {
            CloseOnExecutor();
        }
    }

    inline auto ConnectionAdmission::HandleEvent(Prism::Http3::ServerEvent Event)
        -> Net::awaitable<Prism::Http3::SessionAction>
    {
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        if (Failure_.Load().Failed())
        {
            if (auto *Raw = std::get_if<Prism::Http3::RawStreamEvent>(&Event))
            {
                CloseStream(Raw->Provider);
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
                    CloseStream(Raw->Provider);
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

    inline auto ConnectionAdmission::OnDatagram(Prism::Quic::SharedDatagramProvider Provider)
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

    inline auto ConnectionAdmission::AdmitPendingDatagram() -> void
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
    inline auto ConnectionAdmission::AdmitDatagram(Prism::Quic::SharedDatagramProvider Provider)->void
    {
            if (Failure_.Load().Failed())
            {
                FailedDatagramProvider_ = Provider;
                return;
            }
            if (Closed_ || !Provider)
            {
                CloseDatagram(Provider);
                return;
            }
            if (!Authenticated_)
            {
                if (PendingDatagram_ ||
                    PendingDatagrams_ >= Options_.MaxPendingDatagrams)
                {
                    CloseDatagram(Provider);
                    LastError_ = AdmissionError::DatagramQuota;
                    return;
                }
                PendingDatagram_ = std::move(Provider);
                ++PendingDatagrams_;
                return;
            }
            StartDatagram(std::move(Provider));
        
    }

    inline auto ConnectionAdmission::Close() -> void
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

    inline auto ConnectionAdmission::Drain()
        ->Net::awaitable<std::expected<void,Prism::Fault::Failure>>
    {
        const auto Self=shared_from_this();
        (void)Self;
        co_await Net::dispatch(Executor_,Net::use_awaitable);
        if(OwnerCloseFailure_)RetryOwnerClose_=true;
        AdmitPendingDatagram();
        CloseOnExecutor();
        const auto Drained=co_await Children_.Drain();
        MaybeFinishClose();
        const auto Failure = Failure_.Load();
        if(Failure.Failed())co_return std::unexpected(Failure);
        if(OwnerCloseFailure_)
        {
            co_return std::unexpected(*OwnerCloseFailure_);
        }
        if(!Drained)co_return std::unexpected(Drained.error());
        if(!ActiveStreams_.empty() || ActiveDatagram_ || FailedStreamProvider_ ||
            FailedStreamOwner_ || FailedDatagramProvider_ || FailedDatagramOwner_)
        {
            RecordFailure({Prism::Fault::Code::Blocked});
            co_return std::unexpected(Failure_.Load());
        }
        DatagramIngress_.store({}, std::memory_order_release);
        DatagramIdentity_.store({}, std::memory_order_release);
        co_return std::expected<void,Prism::Fault::Failure>{};
    }

    inline auto ConnectionAdmission::OnClosed() -> void
    {
        Close();
    }

    inline auto ConnectionAdmission::Authenticated() const noexcept -> bool
    {
        return Authenticated_ && AuthSession_->Authenticated();
    }

    inline auto ConnectionAdmission::Closed() const noexcept -> bool
    {
        return Closed_;
    }

    inline auto ConnectionAdmission::LastError() const noexcept
        -> std::optional<AdmissionError>
    {
        return LastError_;
    }


    inline auto ConnectionAdmission::FinishStream(
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

    inline auto ConnectionAdmission::FinishDatagram(std::exception_ptr Error) noexcept -> void
    {
        if (Error) RecordFatal(std::move(Error));
        ActiveDatagram_.reset();
        Children_.Leave();
        MaybeFinishClose();
    }

    inline auto ConnectionAdmission::MaybeFinishClose() noexcept -> void
    {
        if (!Closed_ || !ActiveStreams_.empty() || ActiveDatagram_)
        {
            return;
        }
        AuthSession_->Close();
        const auto CloseResult=RequestOwnerClose();
        if(!CloseResult)return;
    }

    inline auto ConnectionAdmission::CloseOnExecutor() noexcept -> void
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
            CloseStream(Provider);
        }
        PendingStreams_.clear();
        CloseDatagram(PendingDatagram_);
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
        else CloseStream(FailedStreamProvider_);
        if (FailedDatagramOwner_) FailedDatagramOwner_->Close();
        else CloseDatagram(FailedDatagramProvider_);
        MaybeFinishClose();
    }

    inline auto ConnectionAdmission::RecordFailure(Prism::Fault::Failure Failure) noexcept -> void
    {
        if (Failure.Succeeded()) Failure = {Prism::Fault::Code::Blocked};
        if (!Failure_.TrySet(Failure)) return;
        Children_.Block();
        if(Executor_.running_in_this_thread())
        {
            const auto CloseResult=RequestOwnerClose();
            if(!CloseResult)return;
        }
        else
        {
            Close();
        }
    }

    inline auto ConnectionAdmission::RecordFatal(std::exception_ptr Error) noexcept -> void
    {
        Fatal_->Publish(std::move(Error));
        RecordFailure({Prism::Fault::Code::Blocked});
    }


    inline auto ConnectionAdmission::RequestOwnerClose() noexcept
        -> std::expected<void, Prism::Fault::Failure>
    {
        if(CloseOwnerAccepted_)return {};
        if(OwnerCloseFailure_)
        {
            if(!RetryOwnerClose_)return std::unexpected(*OwnerCloseFailure_);
            RetryOwnerClose_=false;
        }
        if(!Options_.CloseOwner)
        {
            CloseOwnerAccepted_=true;
            OwnerCloseFailure_.reset();
            return {};
        }
        try
        {
            const auto Result=Options_.CloseOwner();
            if(!Result)
            {
                if(!OwnerCloseFailure_)OwnerCloseFailure_=Result.error();
                return std::unexpected(*OwnerCloseFailure_);
            }
            CloseOwnerAccepted_=true;
            OwnerCloseFailure_.reset();
            return {};
        }
        catch (...)
        {
            Fatal_->Publish(std::current_exception());
            const Prism::Fault::Failure Failure{Prism::Fault::Code::Blocked};
            if(!OwnerCloseFailure_)OwnerCloseFailure_=Failure;
            return std::unexpected(*OwnerCloseFailure_);
        }
    }


} // namespace Prism::Hysteria2

#include <Prism/Protocols/Hysteria2/AdmissionRuntime.hpp>
