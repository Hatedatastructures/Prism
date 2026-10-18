/**
 * @file UdpTunnel.hpp
 * @brief VLESS 普通 UDP 的固定目标与独立流入/UDP 回包 pump。
 * @details 流和 UDP socket 只承载 [uint16BE payload length][payload]；
 *          目标由握手固定，发送不等待对应回包，单一 reply loop 接收所有回包。
 */
#pragma once

#include <Prism/Protocols/Vless/Detail/Target.hpp>
#include <Prism/Contract/Ingress/DatagramSession.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Lifecycle/TaskState.hpp>
#include <Prism/Protocols/Common/DatagramObservation.hpp>
#include <Prism/Protocols/Common/ProtocolActivity.hpp>
#include <Prism/Protocols/Common/DatagramBinding.hpp>
#include <Prism/Protocols/Vless/Conn.hpp>
#include <Prism/Protocols/Vless/Types.hpp>
#include <Prism/Protocols/Vless/UdpCodec.hpp>
#include <Prism/Protocols/Vless/UdpTunnelFrames.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Vless
{
    namespace Net = boost::asio;
    using Udp = Net::ip::udp;
    using Failure = Prism::Fault::Failure;
    using TunnelResult = std::expected<void, Failure>;

    struct UdpTunnelSummary final
    {
        std::uint64_t Datagrams{0};
        std::uint64_t UpBytes{0};
        std::uint64_t DownBytes{0};
    };

    /** @brief VLESS 普通 UDP 的握手固定目标与会话服务。 */
    struct UdpTunnelOptions final
    {
        Prism::Contract::DatagramServices Services;
        Address Target;
        Prism::Lifecycle::TaskIdentity TaskIdentity{};
        Prism::AccountId AccountId{};
        std::function<void(const Address&)> OnFirstTarget{};
        std::function<void(const UdpTunnelSummary&)> OnSessionEnd{};
    };

    /** @brief 一次 Run 的双泵协调状态；每个长度帧和回包只由一个协程拥有。 */
    struct UdpTunnelRunState final
    {
        using Signal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;

        explicit UdpTunnelRunState(Net::any_io_executor Executor)
            : FirstSend(Executor, 1), InputEnd(Executor, 1), ReplyIdle(std::move(Executor)) {}

        Signal FirstSend;
        Signal InputEnd;
        Net::steady_timer ReplyIdle;
        Net::cancellation_signal ReaderCancellation;
        Net::cancellation_signal ReplyCancellation;
        bool HasSent{false};
        bool InputEnded{false};
    };

    /**
     * @brief 运行固定目标普通 VLESS UDP 隧道。
     * @details 一个 reader 持有所有入站流帧，一个 reply writer 持有所有 UDP 回包写入；
     *          两者并行，故上游静默或多回包不会把发送路径变成一问一答。
     */
    class UdpTunnel final : public Prism::Contract::DatagramSession,
                            public Prism::Contract::CarrierActivity,
                            public std::enable_shared_from_this<UdpTunnel>
    {
    public:
        explicit UdpTunnel(std::shared_ptr<Conn<>> Stream, UdpTunnelOptions Options)
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

        [[nodiscard]] auto Run()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
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

        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return std::const_pointer_cast<UdpTunnel>(weak_from_this().lock());
        }

        auto Seal() noexcept -> void override { Activity_->Seal(); }
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Executor_; }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            const auto Carrier = Stream_ ? Stream_->Activity() : nullptr;
            return CloseResourcesCompleted_.load(std::memory_order_acquire) &&
                Activity_->IsRetired() && Carrier && Carrier->IsRetired();
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
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

        auto Cancel() noexcept -> void override
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

        auto Close() noexcept -> void override
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

    private:
        [[nodiscard]] static auto RequireStreamExecutor(const std::shared_ptr<Conn<>>& Stream)
            -> Net::any_io_executor
        {
            if (!Stream || !Stream->Executor())
                throw std::invalid_argument("VLESS UDP requires a stream executor");
            return Stream->Executor();
        }

        auto CancelOnExecutor() noexcept -> void;
        auto CloseOnExecutor() noexcept -> void;

        auto Execute() -> Net::awaitable<TunnelResult>
        {
            co_return co_await RunCore();
        }

        auto RunCore() -> Net::awaitable<TunnelResult>
        {
            const auto Target = co_await ResolveTarget();
            if (!Target)
            {
                if (IsCloseCancellation(Target.error())) co_return TunnelResult{};
                RecordFailure(Target.error());
                co_return std::unexpected(Target.error());
            }

            RunState_ = std::make_shared<UdpTunnelRunState>(Executor_);
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

        [[nodiscard]] auto ResolveTarget() -> Net::awaitable<std::expected<Udp::endpoint, Failure>>
        {
            const auto Target = Prism::Vless::Detail::ToNetworkTarget(Options_.Target);
            if (!Target)
                co_return std::unexpected(Failure{Prism::Fault::Code::BadMessage});

            using boost::asio::experimental::awaitable_operators::operator||;
            if (Options_.Services.IdleTimeout.count() <= 0)
                co_return co_await Prism::Protocols::ResolveDatagram(
                    Options_.Services, std::move(*Target));

            Net::steady_timer Timer(Executor_);
            Timer.expires_after(Options_.Services.IdleTimeout);
            boost::system::error_code TimerError;
            auto Resolve = Prism::Protocols::ResolveDatagram(
                Options_.Services, *Target);
            auto Timeout = Timer.async_wait(
                Net::redirect_error(Net::use_awaitable, TimerError));
            const auto Result = co_await (std::move(Resolve) || std::move(Timeout));
            if (Result.index() == 1U)
                co_return std::unexpected(Failure{Prism::Fault::Code::Timeout});
            Timer.cancel();
            const auto Resolved = std::get<0>(std::move(Result));
            if (!Resolved) co_return std::unexpected(Resolved.error());
            if (Resolved->port() == 0U)
                co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            co_return *Resolved;
        }

        auto ReceiveFrames(const std::shared_ptr<UdpTunnelRunState>& State,
                           const Udp::endpoint Target) -> Net::awaitable<TunnelResult>
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

        auto SendReplies(const std::shared_ptr<UdpTunnelRunState>& State,
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

        [[nodiscard]] auto IsCloseCancellation(const Failure& Cause) const noexcept -> bool
        {
            return Closed_ && !Cancelled_ &&
                Cause.Code == Prism::Fault::Code::Canceled;
        }

        auto RecordFailure(const Failure Value) noexcept -> void
        {
            (void)RunFailure_.TrySet(Value);
        }

        auto Report() noexcept -> void
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

        auto CloseResources() noexcept -> void;

        std::shared_ptr<Conn<>> Stream_;
        UdpTunnelOptions Options_;
        Net::strand<Net::any_io_executor> Executor_;
        UdpTunnelFrames Frames_;
        Udp::socket Egress_;
        std::shared_ptr<Prism::Protocols::ProtocolActivity> Activity_;
        std::shared_ptr<UdpTunnelRunState> RunState_;
        Prism::Fault::FailureState RunFailure_;
        Prism::Foundation::TrafficObservation Observation_;
        Net::cancellation_signal Cancellation_;
        std::vector<std::uint8_t> TxFrame_;
        std::atomic<bool> CloseResourcesCompleted_{false};
        std::uint64_t DatagramCount_{0};
        std::uint64_t SentBytes_{0}, RecvBytes_{0};
        bool Started_{false}, Drained_{false}, Closed_{false}, Cancelled_{false}, Reported_{false};
    };
} // namespace Prism::Vless

#include <Prism/Protocols/Vless/UdpTunnelRetirement.hpp>
