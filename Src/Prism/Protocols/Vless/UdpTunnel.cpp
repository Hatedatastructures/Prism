/** @file UdpTunnel.cpp @brief VLESS 普通 UDP 帧读写、目标解析与空闲超时实现。 */
#include <Prism/Protocols/Vless/UdpTunnel.hpp>
#include <Prism/Protocols/Vless/UdpCodec.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <stdexcept>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#include "Detail/Target.hpp"

namespace Prism::Vless
{
    struct UdpTunnel::RunState final
    {
        using Signal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;

        explicit RunState(Net::any_io_executor Executor)
            : FirstSend(Executor, 1), InputEnd(Executor, 1), ReplyIdle(std::move(Executor)) {}

        Signal FirstSend;
        Signal InputEnd;
        Net::steady_timer ReplyIdle;
        Net::cancellation_signal ReaderCancellation;
        Net::cancellation_signal ReplyCancellation;
        bool HasSent{false};
        bool InputEnded{false};
    };

    UdpTunnel::UdpTunnel(std::shared_ptr<Conn<>> Stream, UdpTunnelOptions Options)
        : Stream_(std::move(Stream)), Options_(std::move(Options)),
          Executor_(Net::make_strand(RequireStreamExecutor(Stream_))),
          Frames_(Stream_, Options_.Services.IdleTimeout), Egress_(Executor_),
          Activity_(std::make_shared<Prism::Protocols::ProtocolActivity>(Executor_))
    {
        Observation_.Sink = Options_.Services.Traffic;
        Observation_.Owner = Prism::Foundation::TrafficEvent{
            .Generation = Options_.TaskIdentity.Generation,
            .Worker = Options_.TaskIdentity.WorkerId,
            .Session = Options_.TaskIdentity.SessionId,
            .Stream = Options_.TaskIdentity.StreamId,
            .Task = Options_.TaskIdentity.TaskId,
            .Account = Options_.AccountId};
    }

    [[nodiscard]] auto UdpTunnel::RequireStreamExecutor(const std::shared_ptr<Conn<>>& Stream)
        -> Net::any_io_executor
    {
        if (!Stream || !Stream->Executor())
            throw std::invalid_argument("VLESS UDP requires a stream executor");
        return Stream->Executor();
    }

    [[nodiscard]] auto UdpTunnel::Activity() const
        -> std::shared_ptr<Prism::Contract::CarrierActivity>
    {
        return std::const_pointer_cast<UdpTunnel>(weak_from_this().lock());
    }

    auto UdpTunnel::Seal() noexcept -> void
    {
        Activity_->Seal();
    }

    [[nodiscard]] auto UdpTunnel::IsRetired() const noexcept -> bool
    {
        const auto Carrier = Stream_ ? Stream_->Activity() : nullptr;
        return CloseResourcesCompleted_.load(std::memory_order_acquire) &&
            Activity_->IsRetired() && Carrier && Carrier->IsRetired();
    }

    UdpTunnelFrames::UdpTunnelFrames(std::shared_ptr<Conn<>> Stream, std::chrono::milliseconds Timeout)
        : Stream_(std::move(Stream)), Timeout_(Timeout), Timer_(Stream_->Executor())
    {
    }
    [[nodiscard]] auto UdpTunnelFrames::Read()
        -> Net::awaitable<std::expected<std::vector<std::uint8_t>, UdpFailure>>
    {
        std::array<std::byte, 2> Header{};
        const auto HeaderResult = co_await ReadExact(Header);
        if (!HeaderResult)
        {
            auto Failure = HeaderResult.error();
            if (Failure.Cause.Code == Prism::Fault::Code::Eof && Failure.Transferred != 0U)
                Failure.Cause.Code = Prism::Fault::Code::BadMessage;
            co_return std::unexpected(std::move(Failure));
        }

        const auto Length = (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Header[0])) << 8U) |
            std::to_integer<std::uint8_t>(Header[1]);
        std::vector<std::uint8_t> Frame(Length + Header.size());
        Frame[0] = std::to_integer<std::uint8_t>(Header[0]);
        Frame[1] = std::to_integer<std::uint8_t>(Header[1]);
        if (Length != 0U)
        {
            auto* Payload = reinterpret_cast<std::byte*>(Frame.data() + Header.size());
            const auto PayloadResult = co_await ReadExact(std::span<std::byte>(Payload, Length));
            if (!PayloadResult)
            {
                auto Failure = PayloadResult.error();
                if (Failure.Cause.Code == Prism::Fault::Code::Eof)
                    Failure.Cause.Code = Prism::Fault::Code::BadMessage;
                co_return std::unexpected(std::move(Failure));
            }
        }
        co_return Frame;
    }
    [[nodiscard]] auto UdpTunnelFrames::Write(std::span<const std::uint8_t> Frame)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        std::size_t Transferred = 0;
        while (Transferred < Frame.size())
        {
            const auto Remaining = Frame.size() - Transferred;
            const auto Result = co_await Stream_->WriteSome(std::as_bytes(Frame.subspan(Transferred)));
            if (Result.Bytes > Remaining)
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, Result.Failure.Native});
            Transferred += Result.Bytes;
            if (Result.Failure.Failed())
                co_return std::unexpected(Result.Failure);
            if (Result.Bytes == 0U)
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }
    [[nodiscard]] auto UdpTunnelFrames::ReadExact(std::span<std::byte> Buffer) -> Net::awaitable<UdpResult>
    {
        if (PendingTerminal_)
            co_return std::unexpected(UdpFailure{*PendingTerminal_, 0U});

        if (Timeout_.count() <= 0)
        {
            const auto Result = co_await ReadCarrierExact(Buffer);
            if (Result.Failure.Failed()) PendingTerminal_ = Result.Failure;
            co_return Project(Result, Buffer.size());
        }

        using Net::experimental::awaitable_operators::operator||;
        Timer_.expires_after(Timeout_);
        boost::system::error_code TimerError;
        auto Read = ReadCarrierExact(Buffer);
        auto Timeout = Timer_.async_wait(Net::redirect_error(Net::use_awaitable, TimerError));
        const auto Result = co_await (std::move(Read) || std::move(Timeout));
        if (Result.index() == 1U)
            co_return std::unexpected(UdpFailure{{Prism::Fault::Code::Timeout}, 0U});
        Timer_.cancel();
        const auto ReadResult = std::get<0>(std::move(Result));
        if (ReadResult.Failure.Failed()) PendingTerminal_ = ReadResult.Failure;
        co_return Project(ReadResult, Buffer.size());
    }
    [[nodiscard]] auto UdpTunnelFrames::ReadCarrierExact(std::span<std::byte> Buffer)
        -> Net::awaitable<Prism::IoResult>
    {
        auto& Carrier = static_cast<Prism::Transmission&>(*Stream_);
        co_return co_await Carrier.ReadExact(Buffer);
    }
    [[nodiscard]] auto UdpTunnelFrames::Project(const Prism::IoResult Result, const std::size_t Expected)
        -> UdpResult
    {
        if (Result.Bytes > Expected)
            return std::unexpected(
                UdpFailure{{Prism::Fault::Code::InvalidArgument, Result.Failure.Native}, 0U});
        if (Result.Bytes == Expected)
        {
            // 保存的终态留给后续字段；完整字段先供当前帧解析消费。
            return {};
        }
        if (Result.Failure.Failed())
            return std::unexpected(UdpFailure{Result.Failure, Result.Bytes});
        return std::unexpected(UdpFailure{{Prism::Fault::Code::BadMessage}, Result.Bytes});
    }

    auto UdpTunnel::ResolveTarget() -> Net::awaitable<std::expected<Udp::endpoint, Failure>>
    {
        const auto Target = Detail::ToNetworkTarget(Options_.Target);
        if (!Target)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::BadMessage});
        }

        using boost::asio::experimental::awaitable_operators::operator||;
        if (Options_.Services.IdleTimeout.count() <= 0)
        {
            co_return co_await Prism::Protocols::ResolveDatagram(
                Options_.Services, std::move(*Target));
        }

        Net::steady_timer Timer(Executor_);
        Timer.expires_after(Options_.Services.IdleTimeout);
        boost::system::error_code TimerError;
        auto Resolve = Prism::Protocols::ResolveDatagram(Options_.Services, *Target);
        auto Timeout = Timer.async_wait(
            Net::redirect_error(Net::use_awaitable, TimerError));
        const auto Result = co_await (std::move(Resolve) || std::move(Timeout));
        if (Result.index() == 1U)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::Timeout});
        }
        Timer.cancel();
        const auto Resolved = std::get<0>(std::move(Result));
        if (!Resolved)
        {
            co_return std::unexpected(Resolved.error());
        }
        if (Resolved->port() == 0U)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        co_return *Resolved;
    }

    auto UdpTunnel::Execute() -> Net::awaitable<TunnelResult>
    {
        co_return co_await RunCore();
    }

    [[nodiscard]] auto UdpTunnel::Run()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        if (Started_)
        {
            co_return std::unexpected(
                Failure{Prism::Fault::Code::InvalidArgument});
        }
        Started_ = true;
        auto Admission = Activity_->TryBegin();
        if (!Admission)
        {
            if (Closed_ && !Cancelled_ &&
                Admission.error().Code == Prism::Fault::Code::Canceled)
            {
                Report();
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            RecordFailure(Admission.error());
            CloseResources();
            Report();
            co_return std::unexpected(Admission.error());
        }
        auto Reservation = std::move(*Admission);
        if (!Stream_)
        {
            const Failure Cause{Prism::Fault::Code::InvalidArgument};
            RecordFailure(Cause);
            Report();
            Reservation.Complete();
            co_return std::unexpected(Cause);
        }
        if (Closed_)
        {
            Report();
            Reservation.Complete();
            if (Cancelled_)
                co_return std::unexpected(Failure{Prism::Fault::Code::Canceled});
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        TunnelResult Result;
        try
        {
            auto Self = shared_from_this();
            Result = co_await Net::co_spawn(
                Executor_, Self->Execute(),
                Net::bind_cancellation_slot(Cancellation_.slot(), Net::use_awaitable));
        }
        catch (const boost::system::system_error& ErrorValue)
        {
            Result = std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(ErrorValue.code())));
        }
        catch (const std::system_error& ErrorValue)
        {
            Result = std::unexpected(Prism::Fault::FromNative(ErrorValue.code()));
        }
        catch (...)
        {
            Result = std::unexpected(Failure{Prism::Fault::Code::IoError});
        }
        if (!Result && Closed_ && !Cancelled_ &&
            Result.error().Code == Prism::Fault::Code::Canceled)
            Result = TunnelResult{};
        if (!Result) RecordFailure(Result.error());

        Drained_ = true;
        CloseResources();
        Report();
        Reservation.Complete();
        const auto First = RunFailure_.Load();
        if (First.Failed()) co_return std::unexpected(First);
        if (!Result) co_return std::unexpected(Result.error());
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    [[nodiscard]] auto UdpTunnel::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Drained = co_await Activity_->Drain();
        if (!Drained) RecordFailure(Drained.error());
        const auto Carrier = Stream_ ? Stream_->Activity() : nullptr;
        if (!Carrier)
        {
            RecordFailure({Prism::Fault::Code::Blocked});
        }
        else
        {
            const auto CarrierDrained = co_await Carrier->Drain();
            if (!CarrierDrained) RecordFailure(CarrierDrained.error());
        }
        if (!IsRetired()) RecordFailure({Prism::Fault::Code::Blocked});
        const auto First = RunFailure_.Load();
        if (First.Failed()) co_return std::unexpected(First);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto UdpTunnel::Cancel() noexcept -> void
    {
        try
        {
            auto Self = shared_from_this();
            Net::dispatch(Executor_, [Self] { Self->CancelOnExecutor(); });
        }
        catch (...)
        {
            RecordFailure({Prism::Fault::Code::Blocked});
            Activity_->Block();
        }
    }

    auto UdpTunnel::Close() noexcept -> void
    {
        try
        {
            auto Self = shared_from_this();
            Net::dispatch(Executor_, [Self] { Self->CloseOnExecutor(); });
        }
        catch (...)
        {
            RecordFailure({Prism::Fault::Code::Blocked});
            Activity_->Block();
        }
    }

    auto UdpTunnel::RunCore() -> Net::awaitable<TunnelResult>
    {
        const auto Target = co_await ResolveTarget();
        if (!Target)
        {
            if (IsCloseCancellation(Target.error())) co_return TunnelResult{};
            RecordFailure(Target.error());
            co_return std::unexpected(Target.error());
        }

        RunState_ = std::make_shared<RunState>(Executor_);
        auto State = RunState_;
        using boost::asio::experimental::awaitable_operators::operator&&;
        auto Reader = Net::co_spawn(
            Executor_, ReceiveFrames(State, *Target),
            Net::bind_cancellation_slot(State->ReaderCancellation.slot(), Net::use_awaitable));
        auto Replies = Net::co_spawn(
            Executor_, SendReplies(State, *Target),
            Net::bind_cancellation_slot(State->ReplyCancellation.slot(), Net::use_awaitable));
        auto [ReadResult, ReplyResult] = co_await (std::move(Reader) && std::move(Replies));
        if (!ReadResult) RecordFailure(ReadResult.error());
        if (!ReplyResult) RecordFailure(ReplyResult.error());

        const auto First = RunFailure_.Load();
        if (First.Failed()) co_return std::unexpected(First);
        co_return TunnelResult{};
    }

    auto UdpTunnel::ReceiveFrames(const std::shared_ptr<RunState>& State,
                                  const Udp::endpoint Target)
        -> Net::awaitable<TunnelResult>
    {
        while (!Closed_ && !Cancelled_)
        {
            const auto Frame = co_await Frames_.Read();
            if (!Frame)
            {
                const auto Cause = Frame.error().Cause;
                State->InputEnded = true;
                (void)State->InputEnd.try_send(boost::system::error_code{});
                if (IsCloseCancellation(Cause)) co_return TunnelResult{};
                if (Cause.Code != Prism::Fault::Code::Eof)
                {
                    RecordFailure(Cause);
                    State->ReplyCancellation.emit(Net::cancellation_type::all);
                }
                if (Cause.Code == Prism::Fault::Code::Eof)
                    co_return TunnelResult{};
                co_return std::unexpected(Cause);
            }

            std::span<const std::uint8_t> Payload;
            const auto Parsed = ParseUdpPkt(
                std::span<const std::uint8_t>(Frame->data(), Frame->size()), Payload);
            if (!Parsed)
            {
                RecordFailure(Parsed.error().Cause);
                State->InputEnded = true;
                (void)State->InputEnd.try_send(boost::system::error_code{});
                State->ReplyCancellation.emit(Net::cancellation_type::all);
                co_return std::unexpected(Parsed.error().Cause);
            }

            boost::system::error_code ErrorCode;
            if (!Egress_.is_open()) Egress_.open(Target.protocol(), ErrorCode);
            if (ErrorCode)
            {
                const auto Cause = Prism::Fault::FromNative(
                    static_cast<std::error_code>(ErrorCode));
                if (IsCloseCancellation(Cause)) co_return TunnelResult{};
                RecordFailure(Cause);
                State->ReplyCancellation.emit(Net::cancellation_type::all);
                co_return std::unexpected(Cause);
            }
            ErrorCode.clear();
            const auto Sent = co_await Egress_.async_send_to(
                Net::buffer(Payload.data(), Payload.size()), Target,
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                const auto Cause = Prism::Fault::FromNative(
                    static_cast<std::error_code>(ErrorCode));
                RecordFailure(Cause);
                State->ReplyCancellation.emit(Net::cancellation_type::all);
                co_return std::unexpected(Cause);
            }

            ++DatagramCount_;
            SentBytes_ += Sent;
            Observation_.Transfer(
                Sent, Prism::Foundation::TrafficObservation::Direction::Upload);
            if (DatagramCount_ == 1U && Options_.OnFirstTarget)
            {
                try { Options_.OnFirstTarget(Options_.Target); } catch (...) {}
            }
            State->HasSent = true;
            if (Options_.Services.IdleTimeout.count() > 0)
                State->ReplyIdle.expires_after(Options_.Services.IdleTimeout);
            (void)State->FirstSend.try_send(boost::system::error_code{});
        }
        State->InputEnded = true;
        (void)State->InputEnd.try_send(boost::system::error_code{});
        if (Cancelled_)
        {
            const Failure Cause{Prism::Fault::Code::Canceled};
            RecordFailure(Cause);
            co_return std::unexpected(Cause);
        }
        co_return TunnelResult{};
    }

    auto UdpTunnel::SendReplies(const std::shared_ptr<RunState>& State,
                                const Udp::endpoint Target)
        -> Net::awaitable<TunnelResult>
    {
        boost::system::error_code FirstError;
        boost::system::error_code EndError;
        auto FirstSend = State->FirstSend.async_receive(
            Net::redirect_error(Net::use_awaitable, FirstError));
        auto InputEnd = State->InputEnd.async_receive(
            Net::redirect_error(Net::use_awaitable, EndError));
        using boost::asio::experimental::awaitable_operators::operator||;
        (void)co_await (std::move(FirstSend) || std::move(InputEnd));
        if (!State->HasSent)
        {
            const auto Cause = RunFailure_.Load();
            if (Cause.Failed()) co_return std::unexpected(Cause);
            co_return TunnelResult{};
        }

        std::array<std::byte, 65535> Buffer{};
        while (!Closed_ && !Cancelled_)
        {
            Udp::endpoint Source;
            boost::system::error_code ReceiveError;
            std::size_t Size = 0;
            if (Options_.Services.IdleTimeout.count() <= 0)
            {
                Size = co_await Egress_.async_receive_from(
                    Net::buffer(Buffer), Source,
                    Net::redirect_error(Net::use_awaitable, ReceiveError));
            }
            else
            {
                boost::system::error_code TimerError;
                auto Receive = Egress_.async_receive_from(
                    Net::buffer(Buffer), Source,
                    Net::redirect_error(Net::use_awaitable, ReceiveError));
                auto Timeout = State->ReplyIdle.async_wait(
                    Net::redirect_error(Net::use_awaitable, TimerError));
                const auto Ready = co_await (std::move(Receive) || std::move(Timeout));
                if (Ready.index() == 1U)
                {
                    if (TimerError == Net::error::operation_aborted) continue;
                    if (State->InputEnded && !RunFailure_.Load().Failed())
                        co_return TunnelResult{};
                    const Failure Cause{Prism::Fault::Code::Timeout};
                    RecordFailure(Cause);
                    State->ReaderCancellation.emit(Net::cancellation_type::all);
                    co_return std::unexpected(Cause);
                }
                Size = std::get<0>(std::move(Ready));
            }
            if (ReceiveError)
            {
                const auto Cause = Prism::Fault::FromNative(
                    static_cast<std::error_code>(ReceiveError));
                if (IsCloseCancellation(Cause)) co_return TunnelResult{};
                RecordFailure(Cause);
                State->ReaderCancellation.emit(Net::cancellation_type::all);
                co_return std::unexpected(Cause);
            }

            if (Source != Target) continue;

            if (Options_.Services.IdleTimeout.count() > 0)
                State->ReplyIdle.expires_after(Options_.Services.IdleTimeout);
            const auto Payload = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(Buffer.data()), Size);
            const auto Encoded = BuildUdpPkt(Payload, TxFrame_);
            if (!Encoded)
            {
                RecordFailure(Encoded.error().Cause);
                State->ReaderCancellation.emit(Net::cancellation_type::all);
                co_return std::unexpected(Encoded.error().Cause);
            }

            const auto Written = co_await Frames_.Write(TxFrame_);
            if (!Written)
            {
                if (IsCloseCancellation(Written.error())) co_return TunnelResult{};
                RecordFailure(Written.error());
                State->ReaderCancellation.emit(Net::cancellation_type::all);
                co_return std::unexpected(Written.error());
            }
            RecvBytes_ += Size;
            Observation_.Transfer(
                Size, Prism::Foundation::TrafficObservation::Direction::Download);
        }

        if (Cancelled_)
        {
            const Failure Cause{Prism::Fault::Code::Canceled};
            RecordFailure(Cause);
            co_return std::unexpected(Cause);
        }
        co_return TunnelResult{};
    }

    [[nodiscard]] auto UdpTunnel::IsCloseCancellation(const Failure& Cause) const noexcept -> bool
    {
        return Closed_ && !Cancelled_ &&
            Cause.Code == Prism::Fault::Code::Canceled;
    }

    auto UdpTunnel::RecordFailure(const Failure Value) noexcept -> void
    {
        (void)RunFailure_.TrySet(Value);
    }

    auto UdpTunnel::Report() noexcept -> void
    {
        if (Reported_) return;
        Observation_.Complete();
        if (Options_.OnSessionEnd)
        {
            try
            {
                Options_.OnSessionEnd(UdpTunnelSummary{
                    DatagramCount_, SentBytes_, RecvBytes_});
            }
            catch (...)
            {
            }
        }
        Reported_ = true;
    }

    auto UdpTunnel::CancelOnExecutor() noexcept -> void
    {
        if (Cancelled_ || Drained_)
        {
            return;
        }
        Cancelled_ = true;
        RecordFailure({Prism::Fault::Code::Canceled});
        Activity_->Seal();
        if (Closed_)
        {
            Cancellation_.emit(Net::cancellation_type::all);
            if (RunState_)
            {
                RunState_->ReaderCancellation.emit(Net::cancellation_type::all);
                RunState_->ReplyCancellation.emit(Net::cancellation_type::all);
                (void)RunState_->InputEnd.try_send(boost::system::error_code{});
            }
        }
        CloseResources();
    }

    auto UdpTunnel::CloseOnExecutor() noexcept -> void
    {
        CloseResources();
    }

    auto UdpTunnel::CloseResources() noexcept -> void
    {
        if (Closed_ && CloseResourcesCompleted_.load(std::memory_order_acquire))
        {
            return;
        }
        if (!Closed_)
        {
            Activity_->Seal();
            Closed_ = true;
            Cancellation_.emit(Net::cancellation_type::all);
            if (RunState_)
            {
                RunState_->ReaderCancellation.emit(Net::cancellation_type::all);
                RunState_->ReplyCancellation.emit(Net::cancellation_type::all);
                (void)RunState_->InputEnd.try_send(boost::system::error_code{});
                RunState_->FirstSend.close();
                RunState_->InputEnd.close();
            }
        }

        boost::system::error_code ErrorCode;
        if (Egress_.is_open())
        {
            Egress_.cancel(ErrorCode);
            if (ErrorCode)
            {
                RecordFailure(Prism::Fault::FromNative(
                    static_cast<std::error_code>(ErrorCode)));
            }
            ErrorCode.clear();
            Egress_.close(ErrorCode);
            if (ErrorCode)
            {
                RecordFailure(Prism::Fault::FromNative(
                    static_cast<std::error_code>(ErrorCode)));
            }
        }
        bool CarrierClosed = false;
        if (Stream_)
        {
            try
            {
                if (Cancelled_)
                {
                    const auto Canceled = Stream_->Cancel();
                    if (!Canceled)
                    {
                        RecordFailure(Canceled.error());
                    }
                }
                const auto Closed = Stream_->Close();
                if (!Closed)
                {
                    RecordFailure(Closed.error());
                }
                CarrierClosed = Closed.has_value();
            }
            catch (...)
            {
                RecordFailure({Prism::Fault::Code::IoError});
            }
        }
        CloseResourcesCompleted_.store(
            CarrierClosed && !Egress_.is_open(), std::memory_order_release);
    }

} // namespace Prism::Vless
