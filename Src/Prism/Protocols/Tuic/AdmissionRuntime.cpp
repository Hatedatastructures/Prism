/**
 * @file AdmissionRuntime.cpp
 * @brief TUIC admission 认证、stream 与 datagram 运行实现。
 */
#include <Prism/Protocols/Tuic/Admission.hpp>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Protocols/Tuic/Conn.hpp>
#include <Prism/Protocols/Tuic/Dgram.hpp>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Tuic
{
    namespace
    {
        /** @brief 在 connection strand 上删除 admission，并交付一次最终化通知。 */
        auto FinalizeAdmission(
            Net::any_io_executor Executor,
            ConnectionAdmission *Value,
            std::function<void()> Finalized) noexcept -> void
        {
            try
            {
                Net::post(Executor,
                    [Value, Finalized = std::move(Finalized)]() mutable
                    {
                        delete Value;
                        if (Finalized) Finalized();
                    });
            }
            catch (...)
            {
                delete Value;
                if (Finalized) Finalized();
            }
        }
    }

    auto ConnectionAdmission::CloseAndDrainAuthenticationConnection(
        std::shared_ptr<Conn<>> Connection)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        auto FirstFailure = std::expected<void, Prism::Fault::Failure>{};
        if (!Connection)
        {
            FirstFailure = std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        else
        {
            const auto Closed = Connection->Close();
            const auto Activity = Connection->Activity();
            if (!Closed && !(Closed.error().Code == Prism::Fault::Code::Canceled &&
                Activity && Activity->IsRetired()))
                FirstFailure = std::unexpected(Closed.error());
            if (!Activity)
            {
                if (!FirstFailure) FirstFailure = std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            else
            {
                Activity->Seal();
                const auto Drained = co_await Activity->Drain();
                if (!Drained && !FirstFailure &&
                    !(Drained.error().Code == Prism::Fault::Code::Canceled &&
                        Activity->IsRetired()))
                    FirstFailure = std::unexpected(Drained.error());
            }
        }
        const auto AuthStreamDrained = co_await DrainTransmission(AuthStream_);
        if (!AuthStreamDrained && !FirstFailure)
            FirstFailure = std::unexpected(AuthStreamDrained.error());
        if (!FirstFailure) co_return std::unexpected(FirstFailure.error());
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto ConnectionAdmission::Create(AdmissionOptions Options, AdmissionServices Services)
        -> std::expected<std::shared_ptr<ConnectionAdmission>, Prism::Fault::Failure>
    {
        const auto HasAuthenticator = static_cast<bool>(Options.AuthenticatorOwner);
        if (!Options.Executor || !HasAuthenticator || !Options.Credential ||
            !Options.Credential->IsValid())
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto InputEventLimit = std::vector<InputEvent>{}.max_size();
        if (InputEventLimit < MaxPendingInputs + 4U ||
            Options.MaxPendingBidiStreams > InputEventLimit - MaxPendingInputs - 4U ||
            Options.MaxPendingBidiStreams > std::vector<Prism::SharedTransmission>{}.max_size())
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
        auto Executor = Admission->Executor_;
        auto Finalized = std::move(Admission->Options_.OnFinalized);
        try
        {
            return std::shared_ptr<ConnectionAdmission>(Admission,
                [Executor = std::move(Executor), Finalized = std::move(Finalized)](
                    ConnectionAdmission *Value) mutable
                {
                    FinalizeAdmission(
                        std::move(Executor), Value, std::move(Finalized));
                });
        }
        catch (const std::bad_alloc &)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::not_enough_memory)});
        }
    }

    ConnectionAdmission::ConnectionAdmission(AdmissionOptions Options, AdmissionServices Services)
        : Executor_(Net::make_strand(Options.Executor)),
          Options_(std::move(Options)),
          Services_(std::move(Services)),
          Fatal_(Prism::Executor::FatalState::For(Executor_)),
          Storage_(Prism::Executor::ContextOwner::Storage(Executor_)),
          Reclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(Executor_)),
          Inputs_(std::make_shared<Prism::Executor::ExecutorReclaimer>(Executor_)),
          Children_(std::make_shared<Prism::Executor::ExecutorReclaimer>(Executor_))
    {
        FailedInputCapacity_ = Options_.MaxPendingBidiStreams + MaxPendingInputs + 3U;
        FailedInputs_ = std::make_unique<InputEvent[]>(FailedInputCapacity_);
        PendingStreams_.reserve(Options_.MaxPendingBidiStreams);
    }

    ConnectionAdmission::~ConnectionAdmission() noexcept
    {
        assert(Executor_.running_in_this_thread());
        Finalizing_ = true;
        CloseOnExecutor();
        if (CloseOwnerAccepted_ && Inputs_.Active() == 0 && Children_.Active() == 0 &&
            ActiveStreams_.empty() && !ActiveDatagram_)
            ReleaseRetirement();
    }

    auto ConnectionAdmission::StartAuthentication() -> void
    {
        if (Closed_ || AuthenticationStarted_ || !AuthStream_ || !ExporterReady_)
        {
            return;
        }
        AuthenticationStarted_ = true;
        auto Self = shared_from_this();
        if (!Children_.Enter())
        {
            RecordFailure({Prism::Fault::Code::Blocked});
            Children_.Block();
            CloseOnExecutor();
            return;
        }
        try
        {
            Net::co_spawn(Executor_, Self->Authenticate(),
                [Self](const std::exception_ptr &Error)
                {
                    Self->FinishAuthentication(Error);
                });
        }
        catch (...)
        {
            RecordFatal(std::current_exception());
            Children_.Block();
            CloseOnExecutor();
        }
    }

    auto ConnectionAdmission::FinishAuthentication(std::exception_ptr Error) noexcept -> void
    {
        if (Error)
        {
            RecordFatal(std::move(Error));
            Children_.Block();
            CloseOnExecutor();
            return;
        }
        Children_.Leave();
        MaybeFinishClose();
    }

    auto ConnectionAdmission::Authenticate() -> Net::awaitable<void>
    {
        auto AuthenticationConnection = std::make_shared<Conn<>>(
            AuthStream_, Options_.Uuid,
            Options_.AuthenticatorOwner);
        ServerAuthenticationMaterial Material{
            .Exporter = Exporter_,
            .ExporterContext = Options_.ExporterContext,
            .Credential = Options_.Credential};
        const auto Authentication = co_await AuthenticationConnection->ReadAuthentication(
            AuthStream_, std::move(Material));
        if (Authentication.Terminal &&
            (Authentication.Status == Error::UnexpectedEof ||
             Authentication.Terminal->Code != Prism::Fault::Code::Eof))
        {
            if (!(Closed_ &&
                Authentication.Terminal->Code == Prism::Fault::Code::Canceled))
                RecordFailure(*Authentication.Terminal);
        }
        const auto Status = Authentication.EffectiveStatus();
        if (Closed_)
        {
            const auto Drained = co_await CloseAndDrainAuthenticationConnection(
                AuthenticationConnection);
            if (!Drained && Drained.error().Code != Prism::Fault::Code::Canceled)
                RecordFailure(Drained.error());
            co_return;
        }
        if (Status != Error::None)
        {
            const auto Drained = co_await CloseAndDrainAuthenticationConnection(
                AuthenticationConnection);
            if (!Drained) RecordFailure(Drained.error());
            CloseOnExecutor();
            co_return;
        }

        AccountId_ = AuthenticationConnection->AccountId();
        Identity_ = std::string(AuthenticationConnection->Identity());
        AccountLease_ = AuthenticationConnection->TakeAuthLease();
        const auto Drained = co_await CloseAndDrainAuthenticationConnection(
            AuthenticationConnection);
        if (!Drained)
        {
            if (Drained.error().Code != Prism::Fault::Code::Canceled)
            {
                RecordFailure(Drained.error());
                CloseOnExecutor();
                co_return;
            }
        }
        if (Closed_)
        {
            co_return;
        }
        if (!AccountLease_)
        {
            CloseOnExecutor();
            co_return;
        }

        Authenticated_ = true;
        for (auto &Stream : PendingStreams_)
        {
            if (Failure_.Load().Failed()) RetainFailedCarrier(std::move(Stream));
            else StartStream(std::move(Stream), std::nullopt);
        }
        PendingStreams_.clear();
        if (PendingDatagram_ && !Failure_.Load().Failed())
        {
            StartDatagram(PendingDatagram_, PendingDatagramTransport_);
        }
    }

    auto ConnectionAdmission::StartStream(
        Prism::SharedTransmission Stream,
        std::optional<InputReservation> Input) -> void
    {
        if (!Stream) return;
        if (Closed_ || !Authenticated_)
        {
            if (Input) QueueRejectedTransmission(std::move(Stream), std::move(*Input));
            else QueueRejectedTransmission(std::move(Stream));
            return;
        }
        auto StreamLease = AccountLease_.TryAcquireStream();
        if (!StreamLease)
        {
            if (Input) QueueRejectedTransmission(std::move(Stream), std::move(*Input));
            else QueueRejectedTransmission(std::move(Stream));
            return;
        }
        const auto Id = NextStreamId_++;
        SharedConn Connection;
        std::shared_ptr<Net::cancellation_signal> Cancellation;
        try
        {
            Connection = std::make_shared<Conn<>>(Stream, Options_.Uuid);
            Connection->MarkAuthenticated(AccountId_, {}, Identity_);
            Cancellation = std::make_shared<Net::cancellation_signal>();
            ActiveStreams_.emplace(Id, ActiveStream{Connection, {}, Cancellation});
        }
        catch (...)
        {
            const auto Failure = std::current_exception();
            RecordFatal(Failure);
            if (Input)
            {
                InputEvent Event;
                Event.Carrier = std::move(Stream);
                Event.Reservation.emplace(std::move(*Input));
                StoreFailedInput(std::move(Event));
            }
            else RetainFailedCarrier(std::move(Stream));
            return;
        }
        if (!Children_.Enter())
        {
            if (!Closed_)
            {
                RecordFailure({Prism::Fault::Code::Blocked});
                Children_.Block();
            }
            (void)CloseTransmission(Connection);
            ActiveStreams_.erase(Id);
            MaybeFinishClose();
            return;
        }

        auto Self = shared_from_this();
        try
        {
            Net::co_spawn(Executor_, Self->ServeStream(Id, Connection, std::move(*StreamLease)),
                [Self, Id, Cancellation](std::exception_ptr Error, StreamTaskResult Result)
                {
                    (void)Cancellation;
                    Self->FinishStream(Id, std::move(Error), std::move(Result));
                });
        }
        catch (...)
        {
            RecordFatal(std::current_exception());
            Children_.Block();
        }
    }

    auto ConnectionAdmission::StartDatagram(
        Prism::Quic::SharedDatagramProvider Provider,
        Prism::SharedTransmission Transport) -> void
    {
        if (!Provider) return;
        if (!Transport) Transport = std::make_shared<Prism::Quic::DatagramAdapter>(Provider);
        if (Closed_ || !Authenticated_ || ActiveDatagram_)
        {
            QueueRejectedTransmission(std::move(Transport));
            return;
        }
        if (!Children_.Enter())
        {
            RecordFailure({Prism::Fault::Code::Blocked});
            InputEvent Event;
            Event.Provider = Provider;
            Event.Carrier = std::move(Transport);
            StoreFailedInput(std::move(Event));
            Children_.Block();
            return;
        }
        ActiveDatagram_ = Provider;
        ActiveDatagramTransport_ = Transport;
        PendingDatagram_.reset();
        PendingDatagramTransport_.reset();
        auto Cancellation = std::make_shared<Net::cancellation_signal>();
        DatagramCancellation_ = Cancellation;
        auto Self = shared_from_this();
        try
        {
            Net::co_spawn(Executor_, Self->ServeDatagrams(Provider, Transport, Cancellation),
                [Self, Provider](std::exception_ptr Error,
                    std::expected<void, Prism::Fault::Failure> Result)
                {
                    Self->CompleteDatagram(Provider, std::move(Error), std::move(Result));
                });
        }
        catch (...)
        {
            RecordFatal(std::current_exception());
            Children_.Block();
        }
    }

    auto ConnectionAdmission::CompleteDatagram(
        Prism::Quic::SharedDatagramProvider Provider,
        std::exception_ptr Error,
        std::expected<void, Prism::Fault::Failure> Result) noexcept -> void
    {
        if (Error)
        {
            RecordFatal(std::move(Error));
            Children_.Block();
            return;
        }
        FinishDatagram(Provider, {}, std::move(Result));
    }

    auto ConnectionAdmission::RunStream(
        std::uint64_t Id,
        SharedConn Connection,
        Prism::Account::StreamLease &StreamLease)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Active = ActiveStreams_.find(Id);
        if (Active == ActiveStreams_.end() || !Active->second.Cancellation)
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        const auto Cancellation = Active->second.Cancellation;
        if (Closed_)
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        const auto [HandshakeStatus, Request] = co_await Connection->ReadHandshake();
        if (Closed_ || HandshakeStatus != Error::None)
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        if (!Services_.Dial)
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        auto Dialed = co_await Net::co_spawn(Executor_,
            Services_.Dial(DialRequest{Request.dst}),
            Net::bind_cancellation_slot(Cancellation->slot(), Net::use_awaitable));
        if (!Dialed)
        {
            if (Closed_ && Dialed.error().Code == Prism::Fault::Code::Canceled)
                co_return std::expected<void, Prism::Fault::Failure>{};
            co_return std::unexpected(Dialed.error());
        }
        if (auto It = ActiveStreams_.find(Id); It != ActiveStreams_.end())
        {
            It->second.Outbound = *Dialed;
        }
        if (Closed_)
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        if (!Services_.RelayStream)
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        StreamRelayRequest RelayRequest{
            .Request = Request,
            .Inbound = Connection,
            .Outbound = *Dialed,
            .AccountId = AccountId_,
            .Identity = Identity_,
            .Lease = std::move(StreamLease),
            .Metadata = Options_.Metadata};
        const auto Relayed = co_await Net::co_spawn(Executor_,
            Services_.RelayStream(std::move(RelayRequest)),
            Net::bind_cancellation_slot(Cancellation->slot(), Net::use_awaitable));
        if (!Relayed && Closed_ && Relayed.error().Code == Prism::Fault::Code::Canceled)
            co_return std::expected<void, Prism::Fault::Failure>{};
        co_return Relayed;
    }

    namespace
    {
        auto ReportDatagramBytes(
            const AdmissionServices &Services,
            DatagramSessionReport Report) noexcept -> void
        {
            if ((!Report.UploadedBytes && !Report.DownloadedBytes) ||
                !Services.ReportDatagramSession)
            {
                return;
            }
            Report.Kind = Prism::Foundation::TrafficEventKind::Bytes;
            try
            {
                Services.ReportDatagramSession(std::move(Report));
            }
            catch (...)
            {
            }
        }
    }

    auto ConnectionAdmission::RunDatagrams(Prism::SharedTransmission Transport)
        -> Net::awaitable<void>
    {
        const auto SessionAccountId = AccountId_;
        auto Datagram = std::make_shared<Dgram<>>(std::move(Transport));
        std::uint64_t DatagramCount = 0;
        std::uint64_t UploadedBytes = 0;
        std::uint64_t DownloadedBytes = 0;
        while (!Closed_)
        {
            Address Target;
            std::vector<std::uint8_t> Payload;
            const auto ReceiveStatus = co_await Datagram->AsyncReceiveFrom(Target, Payload);
            if (Closed_ || ReceiveStatus != Error::None)
            {
                break;
            }
            ++DatagramCount;
            if (!Services_.Resolve || !Services_.ExchangeDatagram)
            {
                continue;
            }

            auto Resolution = co_await Services_.Resolve(ResolveRequest{Target});
            if (Closed_ || Resolution.Status != Error::None || Resolution.Endpoints.empty())
            {
                continue;
            }
            auto Exchange = co_await Services_.ExchangeDatagram(DatagramRequest{
                .Target = Resolution.Endpoints.front(),
                .Payload = std::move(Payload),
                .AccountId = SessionAccountId});
            UploadedBytes += Exchange.UploadedBytes;
            ReportDatagramBytes(Services_, DatagramSessionReport{
                .AccountId = SessionAccountId,
                .UploadedBytes = Exchange.UploadedBytes,
                .Metadata = Options_.Metadata});
            if (Closed_) break;
            if (Exchange.Status != Error::None) continue;
            const auto SendStatus = co_await Datagram->AsyncSendTo(
                Exchange.Source, std::span<const std::uint8_t>(Exchange.Payload));
            if (SendStatus != Error::None) break;
            DownloadedBytes += Exchange.DownloadedBytes;
            ReportDatagramBytes(Services_, DatagramSessionReport{
                .AccountId = SessionAccountId,
                .DownloadedBytes = Exchange.DownloadedBytes,
                .Metadata = Options_.Metadata});
        }

        if (Services_.ReportDatagramSession)
        {
            try
            {
                Services_.ReportDatagramSession(DatagramSessionReport{
                    .AccountId = SessionAccountId,
                    .DatagramCount = DatagramCount,
                    .UploadedBytes = UploadedBytes,
                    .DownloadedBytes = DownloadedBytes,
                    .Metadata = Options_.Metadata,
                    .Kind = Prism::Foundation::TrafficEventKind::Completed});
            }
            catch (...)
            {
            }
        }
    }

    auto ConnectionAdmission::FinishStream(
        std::uint64_t Id,
        std::exception_ptr Exception,
        StreamTaskResult Result) noexcept -> void
    {
        if (Exception)
        {
            RecordFatal(std::move(Exception));
            Children_.Block();
            return;
        }
        const auto It = ActiveStreams_.find(Id);
        if (It == ActiveStreams_.end())
        {
            RecordFailure({Prism::Fault::Code::Blocked});
            Children_.Block();
            return;
        }
        if (Result.CleanupFailure)
            RecordFailure(*Result.CleanupFailure);
        if (Result.OperationFailure)
        {
            ObserveStreamFailure(StreamFailureReport{
                .ConnectionStreamId = Id,
                .TaskIdentity = Options_.Metadata.TaskIdentity,
                .Failure = *Result.OperationFailure});
        }
        if (Result.CleanupFailure)
        {
            It->second.RetainedLease = std::move(Result.RetainedLease);
            Children_.Block();
            return;
        }
        ActiveStreams_.erase(It);
        Children_.Leave();
        MaybeFinishClose();
    }

    auto ConnectionAdmission::ObserveStreamFailure(StreamFailureReport Report) noexcept -> void
    {
        if (!Services_.ReportStreamFailure) return;
        try
        {
            Services_.ReportStreamFailure(std::move(Report));
        }
        catch (...)
        {
            RecordFatal(std::current_exception());
            CloseOnExecutor();
        }
    }

    auto ConnectionAdmission::FinishDatagram(
        const Prism::Quic::SharedDatagramProvider &Provider,
        std::exception_ptr Exception,
        std::expected<void, Prism::Fault::Failure> Result) noexcept -> void
    {
        if (Exception)
        {
            RecordFatal(std::move(Exception));
            Children_.Block();
            return;
        }
        if (!Result)
        {
            if (!(Closed_ && Result.error().Code == Prism::Fault::Code::Canceled))
            {
                RecordFailure(Result.error());
                Children_.Block();
                return;
            }
        }
        if (ActiveDatagram_ != Provider)
        {
            RecordFailure({Prism::Fault::Code::Blocked});
            Children_.Block();
            return;
        }
        ActiveDatagram_.reset();
        ActiveDatagramTransport_.reset();
        DatagramCancellation_.reset();
        Children_.Leave();
        MaybeFinishClose();
    }
}
