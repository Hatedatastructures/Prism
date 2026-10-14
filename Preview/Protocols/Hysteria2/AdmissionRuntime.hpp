/** @file AdmissionRuntime.hpp @brief Hysteria2 身份认证、stream 与 datagram 子任务执行 owner。 */
#pragma once

#include <Preview/Protocols/Hysteria2/Admission.hpp>
#include <Preview/Protocols/Hysteria2/DatagramSession.hpp>
#include <Preview/Protocols/Hysteria2/StreamSession.hpp>
#include <new>
#include <system_error>

namespace Preview::Hysteria2
{
    inline auto ConnectionAdmission::StartPendingChildren() -> void
    {
        while (!PendingStreams_.empty() && !Failure_.Load().Failed())
        {
            auto Provider = std::move(PendingStreams_.front());
            PendingStreams_.erase(PendingStreams_.begin());
            StartStream(std::move(Provider));
        }
        if (PendingDatagram_ && !Failure_.Load().Failed())
        {
            auto Provider = std::move(PendingDatagram_);
            PendingDatagrams_ = 0;
            StartDatagram(std::move(Provider));
        }
    }

    inline auto ConnectionAdmission::RemovePendingStream(const std::int64_t StreamId) -> void
    {
        for (auto It = PendingStreams_.begin(); It != PendingStreams_.end();)
        {
            if (*It && (*It)->StreamId() == StreamId)
            {
                It = PendingStreams_.erase(It);
            }
            else
            {
                ++It;
            }
        }
    }

    inline auto ConnectionAdmission::StartStream(
        Preview::Quic::SharedStreamProvider Provider) -> void
    {
        if (Failure_.Load().Failed())
        {
            FailedStreamProvider_ = Provider;
            return;
        }
        if (Closed_ || !Authenticated_ || !Provider)
        {
            CloseStream(Provider);
            return;
        }
        auto Lease = AuthSession_->AcquireStream();
        if (!Lease)
        {
            CloseStream(Provider);
            LastError_ = MapAuthError(Lease.error());
            return;
        }
        const auto RetainedProvider = Provider;
        if (!Children_.Enter())
        {
            FailedStreamProvider_ = RetainedProvider;
            RecordFailure({Preview::Fault::Code::Blocked});
            return;
        }
        const auto Id = NextChildId_++;
        auto Self = shared_from_this();
        std::shared_ptr<StreamSession> Child;
        try
        {
            Child = StreamSession::Create(StreamSession::Options{
                Executor_, Id, std::move(Provider), AuthSession_->AccountId(),
                std::string(AuthSession_->Identity()), std::move(*Lease), Services_,
                [Weak = std::weak_ptr<ConnectionAdmission>(Self)](
                    const std::uint64_t ChildId, const Preview::Fault::Code Status)
                {
                    if (auto Owner = Weak.lock()) Owner->FinishStream(ChildId, Status);
                }, Options_.Metadata});
        }
        catch (const std::bad_alloc &)
        {
            Children_.Leave();
            FailedStreamProvider_ = RetainedProvider;
            RecordFailure({Preview::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::not_enough_memory)});
            return;
        }
        catch (...)
        {
            Children_.Leave();
            FailedStreamProvider_ = RetainedProvider;
            RecordFatal(std::current_exception());
            return;
        }
        if (!Child)
        {
            Children_.Leave();
            FailedStreamProvider_ = RetainedProvider;
            RecordFailure({Preview::Fault::Code::ResourceUnavailable});
            return;
        }
        try
        {
            ActiveStreams_.emplace(Id, Child);
        }
        catch (const std::bad_alloc &)
        {
            Children_.Leave();
            FailedStreamProvider_ = RetainedProvider;
            FailedStreamOwner_ = std::move(Child);
            RecordFailure({Preview::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::not_enough_memory)});
            return;
        }
        catch (...)
        {
            Children_.Leave();
            FailedStreamProvider_ = RetainedProvider;
            FailedStreamOwner_ = std::move(Child);
            RecordFatal(std::current_exception());
            return;
        }
        try
        {
            Child->Start();
        }
        catch (...)
        {
            FailedStreamOwner_ = std::move(Child);
            RecordFatal(std::current_exception());
        }
    }

    inline auto ConnectionAdmission::StartDatagram(
        Preview::Quic::SharedDatagramProvider Provider) -> void
    {
        if (Failure_.Load().Failed())
        {
            FailedDatagramProvider_ = Provider;
            return;
        }
        if (Closed_ || !Authenticated_ || !Provider || ActiveDatagram_)
        {
            CloseDatagram(Provider);
            return;
        }
        auto Lease = AuthSession_->AcquireStream();
        if (!Lease)
        {
            CloseDatagram(Provider);
            LastError_ = AdmissionError::DatagramQuota;
            return;
        }
        const auto RetainedProvider = Provider;
        if (!Children_.Enter())
        {
            FailedDatagramProvider_ = RetainedProvider;
            RecordFailure({Preview::Fault::Code::Blocked});
            return;
        }
        auto Self = shared_from_this();
        std::shared_ptr<DatagramSession> Child;
        try
        {
            Child = DatagramSession::Create(DatagramSession::Options{
                Executor_, std::move(Provider), std::move(*Lease), AuthSession_->AccountId(), Services_,
                [Weak = std::weak_ptr<ConnectionAdmission>(Self)](std::exception_ptr Error)
                {
                    if (auto Owner = Weak.lock()) Owner->FinishDatagram(Error);
                }, Options_.Metadata});
        }
        catch (const std::bad_alloc &)
        {
            Children_.Leave();
            FailedDatagramProvider_ = RetainedProvider;
            RecordFailure({Preview::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::not_enough_memory)});
            return;
        }
        catch (...)
        {
            Children_.Leave();
            FailedDatagramProvider_ = RetainedProvider;
            RecordFatal(std::current_exception());
            return;
        }
        if (!Child)
        {
            Children_.Leave();
            FailedDatagramProvider_ = RetainedProvider;
            RecordFailure({Preview::Fault::Code::ResourceUnavailable});
            return;
        }
        ActiveDatagram_ = Child;
        try
        {
            Child->Start();
        }
        catch (...)
        {
            FailedDatagramOwner_ = Child;
            RecordFatal(std::current_exception());
        }
    }


    inline auto ConnectionAdmission::MapAuthError(const AuthError Error) noexcept -> AdmissionError
    {
        switch (Error)
        {
        case AuthError::StreamQuota: return AdmissionError::StreamQuota;
        case AuthError::Closed: return AdmissionError::Closed;
        case AuthError::InvalidRequest: return AdmissionError::InvalidRequest;
        default: return AdmissionError::AuthenticationRequired;
        }
    }


} // namespace Preview::Hysteria2
