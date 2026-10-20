/** @file UdpAssoc.cpp @brief SOCKS5 UDP 目标解析实现。 */
#include <Prism/Protocols/Socks5/UdpAssoc.hpp>

#include <boost/asio/multiple_exceptions.hpp>
#include <boost/asio/strand.hpp>

#include "Detail/Target.hpp"
#include "Detail/UdpAddress.hpp"

namespace Prism::Socks5
{

    auto UdpAssoc::ResolveTarget(const Address& Target)
        -> Net::awaitable<std::expected<Net::ip::udp::endpoint, Prism::Fault::Failure>>
    {
        if (Opts_.Resolve)
        {
            co_return co_await Opts_.Resolve(Target);
        }
        const auto Value = Detail::ToNetworkTarget(Target);
        if (!Value)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        const auto Ip = Prism::Network::IpAddress(Value->Host);
        if (!Ip)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        co_return Net::ip::udp::endpoint(*Ip, Target.Port);
    }


    UdpAssoc::UdpAssoc(Net::any_io_executor Executor, std::shared_ptr<Conn<>> Tcp,
              UdpAssocOptions Options)
        : Ex_(Net::make_strand(std::move(Executor))),
          Retirement_(std::make_shared<UdpAssocRetirement>(Ex_, std::move(Tcp))),
          BindGate_(std::make_shared<UdpAssocBindGate>(Ex_, Retirement_)),
          Opts_(std::move(Options))
    {
        Observation_.Sink = std::move(Opts_.Traffic);
        Observation_.Owner = Prism::Foundation::TrafficEvent{
            .Generation = Opts_.TaskIdentity.Generation,
            .Worker = Opts_.TaskIdentity.WorkerId,
            .Session = Opts_.TaskIdentity.SessionId,
            .Stream = Opts_.TaskIdentity.StreamId,
            .Task = Opts_.TaskIdentity.TaskId,
            .Account = Opts_.AccountId};
    }

    [[nodiscard]] auto UdpAssoc::BindAndReply() -> Net::awaitable<ReplyResult<std::size_t>>
    {
        [[maybe_unused]] const auto Self = shared_from_this();
        co_return co_await BindGate_->Run();
    }

    [[nodiscard]] auto UdpAssoc::Run()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        auto Self = shared_from_this();
        co_await Net::dispatch(Ex_, Net::use_awaitable);
        auto Admission = Retirement_->BeginRun();
        if (!Admission)
        {
            const auto Failure = Admission.error();
            if (Failure.Code == Prism::Fault::Code::InvalidArgument)
                co_return std::unexpected(Failure);
            const auto CloseWasRequested = Retirement_->IsCloseRequested();
            RequestRetirement();
            const auto Drain = co_await Retirement_->RunDrain();
            if (!Drain) co_return std::unexpected(Drain.error());
            if (!Retirement_->IsCancelled() && CloseWasRequested &&
                Failure.Code == Prism::Fault::Code::Canceled)
            {
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        auto Reservation = std::move(*Admission);
        auto Result = Prism::Fault::Code::Success;
        try
        {
            Result = co_await Net::co_spawn(Ex_, Self->Execute(),
                Net::bind_cancellation_slot(
                    Retirement_->CancellationSlot(), Net::use_awaitable));
        }
        catch (const boost::system::system_error &ErrorValue)
        {
            Result = Prism::Fault::ToCode(ErrorValue.code());
            if (Result != Prism::Fault::Code::Canceled)
                (void)Retirement_->RecordException(std::current_exception());
        }
        catch (...)
        {
            (void)Retirement_->RecordException(std::current_exception());
            Result = Prism::Fault::Code::IoError;
        }
        /** @brief 先让 Execute completion handler 退栈，再归还 Run 预约并退休 socket。 */
        co_await Net::post(Ex_, Net::use_awaitable);
        if (Result == Prism::Fault::Code::Canceled &&
            !Retirement_->IsCloseRequested())
        {
            RequestCancellationRetirement();
        }
        const auto CloseWasRequested = Retirement_->IsCloseRequested();
        Reservation.Complete();
        RequestRetirement();
        const auto Drain = co_await Retirement_->RunDrain();
        if (!Drain) co_return std::unexpected(Drain.error());
        if (Retirement_->IsCancelled())
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        if (CloseWasRequested && Result == Prism::Fault::Code::Canceled)
            co_return std::expected<void, Prism::Fault::Failure>{};
        if (Prism::Fault::Failed(Result))
            co_return std::unexpected(Prism::Fault::Failure{Result});
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    [[nodiscard]] auto UdpAssoc::Activity() const
        -> std::shared_ptr<Prism::Contract::CarrierActivity>
    {
        PinRetirementOwner();
        return Retirement_;
    }

    auto UdpAssoc::Cancel() noexcept -> void
    { RequestRetirement(true); }

    auto UdpAssoc::Execute() -> Net::awaitable<Prism::Fault::Code>
    {
        const auto Reply = co_await BindAndReply();
        if (!Reply)
        {
            if (Reply.error().Transport.Failed())
                co_return Reply.error().Transport.Code;
            co_return Prism::Fault::ToCode(
                Prism::make_error_code(Reply.error().Protocol));
        }
        co_return co_await RunCore();
    }

    [[nodiscard]] auto UdpAssoc::RunCore() -> Net::awaitable<Prism::Fault::Code>
    {
        using boost::asio::experimental::awaitable_operators::operator||;
        auto Self = shared_from_this();
        auto Result = co_await (Self->FrameLoop() || Self->TcpWatch());
        co_return Result.index() == 0 ? std::get<0>(Result) : std::get<1>(Result);
    }

    auto UdpAssoc::Close() noexcept -> void
    { RequestRetirement(); }

    auto UdpAssoc::PinRetirementOwner() const noexcept -> void
    {
        try
        {
            const auto Owner = std::const_pointer_cast<UdpAssoc>(weak_from_this().lock());
            if (!Owner) return;
            const std::weak_ptr<UdpAssoc> Weak = Owner;
            Retirement_->PinOwner(
                std::static_pointer_cast<void>(Owner),
                [Weak]
                {
                    if (const auto Value = Weak.lock()) Value->Report();
                });
        }
        catch (...)
        {
            Retirement_->RecordFailure({Prism::Fault::Code::Blocked});
        }
    }

    auto UdpAssoc::RequestRetirement(const bool Cancelled) noexcept -> void
    {
        auto Owner = weak_from_this().lock();
        if (!Owner)
        {
            Retirement_->RequestClose();
            return;
        }
        try
        {
            const std::weak_ptr<UdpAssoc> Weak = Owner;
            auto Completion = [Weak]
            {
                if (const auto Value = Weak.lock()) Value->Report();
            };
            auto OwnerPin = std::static_pointer_cast<void>(std::move(Owner));
            if (Cancelled)
                Retirement_->RequestCancel(std::move(OwnerPin), std::move(Completion));
            else
                Retirement_->RequestClose(std::move(OwnerPin), std::move(Completion));
        }
        catch (...)
        {
            Retirement_->RecordFailure({Prism::Fault::Code::Blocked});
        }
    }

    auto UdpAssoc::Report() noexcept -> void
    {
        if (Reported_) return;
        Reported_ = true;
        Observation_.Complete();
        if (Opts_.OnSessionEnd)
        {
            try { Opts_.OnSessionEnd({DatagramCount_, SentBytes_, RecvBytes_}); } catch (...) {}
        }
    }

    auto UdpAssoc::RequestCancellationRetirement() noexcept -> void
    {
        if (!Retirement_->IsCloseRequested()) RequestRetirement(true);
    }

    [[nodiscard]] auto UdpAssoc::ObserveNativeError(
        const boost::system::error_code &ErrorCode) noexcept -> Prism::Fault::Code
    {
        const auto Code = Prism::Fault::ToCode(ErrorCode);
        if (Code != Prism::Fault::Code::Canceled)
            Retirement_->RecordNative(ErrorCode);
        return Code;
    }

    [[nodiscard]] auto UdpAssoc::FrameLoop() -> Net::awaitable<Prism::Fault::Code>
    {
        try
        {
            Net::steady_timer Idle(Ex_);
            std::vector<std::byte> Rx(65535);
            ReplyWorkspace Reply;
            while (true)
            {
                if (Retirement_->IsCloseRequested())
                    co_return Prism::Fault::Code::Canceled;
                Net::ip::udp::endpoint ClientEp;
                boost::system::error_code ErrorCode;
                ReceiveOptions Receive{Retirement_->Ingress(), Idle, Rx, ClientEp, ErrorCode};
                const auto Size = co_await RecvGuarded(Receive);
                if (ErrorCode)
                {
                    const auto Code = ObserveNativeError(ErrorCode);
                    if (Code == Prism::Fault::Code::Canceled) co_return Code;
                    co_return Prism::Fault::Code::Success;
                }
                if (!Size) co_return Prism::Fault::Code::Success;
                const auto ControlPeer = BindGate_->ControlPeer();
                if (!ControlPeer || ClientEp.address() != ControlPeer->address()) continue;
                AcceptedDatagram Packet;
                const auto Window = std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t*>(Rx.data()), *Size);
                if (ParseUdpDatagram(Window, Packet.Target, Packet.Payload) != Error::None) continue;
                Packet.Peer = ClientEp;
                ++DatagramCount_;
                if (!FirstTargetReported_ && !Packet.Target.Host.empty() && Packet.Target.Port != 0U)
                {
                    FirstTargetReported_ = true;
                    if (Opts_.OnFirstTarget)
                    {
                        try { Opts_.OnFirstTarget(Packet.Target); } catch (...) {}
                    }
                }
                const auto Status = co_await Prism::Protocols::AwaitDatagramDeadline(
                    Exchange(Packet, Reply), {Ex_, Opts_.IdleTimeout});
                if (Prism::Fault::Failed(Status)) co_return Status;
            }
        }
        catch (const boost::asio::multiple_exceptions& ErrorValue)
        {
            const auto Cause = UdpAssocRetirement::FailureFromException(
                ErrorValue.first_exception());
            if (Cause.Code == Prism::Fault::Code::Canceled)
            {
                co_return Cause.Code;
            }
            Retirement_->RecordFailure(Cause);
            co_return Cause.Code;
        }
        catch (...)
        {
            co_return Retirement_->RecordException(std::current_exception()).Code;
        }
    }

    auto UdpAssoc::Exchange(const AcceptedDatagram& Packet, ReplyWorkspace& Reply)
        -> Net::awaitable<Prism::Fault::Code>
    {
        auto Target = co_await ResolveTarget(Packet.Target);
        if (Retirement_->IsCloseRequested())
            co_return Prism::Fault::Code::Canceled;
        if (!Target)
        {
            if (Target.error().Code != Prism::Fault::Code::Canceled)
                Retirement_->RecordFailure(Target.error());
            co_return Target.error().Code;
        }
        boost::system::error_code ErrorCode;
        auto &Egress = Retirement_->Egress();
        auto &Ingress = Retirement_->Ingress();
        auto Protocol = Retirement_->EgressProtocol();
        if (!Egress.is_open() || !Protocol || *Protocol != Target->protocol())
        {
            if (Egress.is_open())
            {
                const auto Close = Retirement_->CloseEgress();
                if (Close.Failed()) co_return Close.Code;
            }
            Egress.open(Target->protocol(), ErrorCode);
            if (!ErrorCode)
            {
                Retirement_->SetEgressProtocol(Target->protocol());
            }
        }
        if (ErrorCode)
        {
            co_return ObserveNativeError(ErrorCode);
        }
        const auto Sent = co_await Egress.async_send_to(
            Net::buffer(Packet.Payload.data(), Packet.Payload.size()), *Target,
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (ErrorCode)
        {
            co_return ObserveNativeError(ErrorCode);
        }
        if (Retirement_->IsCloseRequested())
            co_return Prism::Fault::Code::Canceled;
        SentBytes_ += Sent;
        Observation_.Transfer(
            Sent, Prism::Foundation::TrafficObservation::Direction::Upload);
        Net::ip::udp::endpoint Source;
        std::size_t Size = 0;
        for (;;)
        {
            Size = co_await Egress.async_receive_from(Net::buffer(Reply.Payload), Source,
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                co_return ObserveNativeError(ErrorCode);
            }
            if (Source == *Target)
            {
                break;
            }
        }
        if (Retirement_->IsCloseRequested())
            co_return Prism::Fault::Code::Canceled;
        BuildUdpDatagram(Detail::EndpointToAddress(Source),
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(Reply.Payload.data()), Size),
            Reply.Wire);
        co_await Ingress.async_send_to(Net::buffer(Reply.Wire), Packet.Peer,
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (ErrorCode)
        {
            co_return ObserveNativeError(ErrorCode);
        }
        RecvBytes_ += Size;
        Observation_.Transfer(
            Size, Prism::Foundation::TrafficObservation::Direction::Download);
        co_return Prism::Fault::Code::Success;
    }

    [[nodiscard]] auto UdpAssoc::RecvGuarded(ReceiveOptions Options)
        -> Net::awaitable<std::optional<std::size_t>>
    {
        using boost::asio::experimental::awaitable_operators::operator||;
        if (Opts_.IdleTimeout.count() <= 0)
        {
            try
            {
                co_return co_await Options.Socket.async_receive_from(
                    Net::buffer(Options.Buffer), Options.Endpoint, Net::use_awaitable);
            }
            catch (const boost::system::system_error &ErrorValue)
            {
                Options.Error = ErrorValue.code();
                co_return std::nullopt;
            }
        }
        Options.Idle.expires_after(Opts_.IdleTimeout);
        auto Receive = Options.Socket.async_receive_from(
            Net::buffer(Options.Buffer),
            Options.Endpoint,
            Net::redirect_error(Net::use_awaitable, Options.Error));
        auto Wait = Options.Idle.async_wait(Net::use_awaitable);
        auto Result = co_await (std::move(Receive) || std::move(Wait));
        Options.Idle.cancel();
        if (Result.index() == 1)
        {
            co_return std::nullopt; // 空闲超时
        }
        co_return std::get<0>(Result);
    }

    [[nodiscard]] auto UdpAssoc::TcpWatch() -> Net::awaitable<Prism::Fault::Code>
    {
        try
        {
            const auto Tcp = Retirement_->Tcp();
            if (!Tcp)
            {
                co_return Prism::Fault::Code::Success;
            }
            std::array<std::byte, 1> Probe{};
            const auto Result = co_await Tcp->ReadSome(std::span(Probe));
            if (Result.Failure.Code == Prism::Fault::Code::Canceled)
            {
                co_return Result.Failure.Code;
            }
            if (Result.Failure.Native && Result.Failure.Code != Prism::Fault::Code::Eof)
            {
                Retirement_->RecordFailure(Result.Failure);
                co_return Result.Failure.Code;
            }
            co_return Prism::Fault::Code::Success;
        }
        catch (...)
        {
            co_return Retirement_->RecordException(std::current_exception()).Code;
        }
    }

} // namespace Prism::Socks5
