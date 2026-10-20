/**
 * @file DatagramRelayPump.hpp
 * @brief Trojan/Vmess 共用的双向 UDP pump 与完整数据面资源。
 * @details Wire reader、双地址族 sender/receiver、限额队列、目标 peer 校验与单一 Wire writer
 *          同属此 owner；Retirement 保留 owner 到所有运行协程与 carrier Activity 真实退栈。
 */
#pragma once

#include <Prism/Protocols/Common/DatagramFailure.hpp>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Contract/Services/Datagram.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Protocols/Common/DatagramBinding.hpp>
#include <Prism/Protocols/Common/DatagramObservation.hpp>
#include <Prism/Protocols/Common/DatagramOperationDeadline.hpp>
#include <Prism/Protocols/Common/DatagramRelayState.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>
#include <variant>

namespace Prism::Protocols
{
    namespace Net = boost::asio;
    using Udp = Net::ip::udp;

    /** @brief 一个已解码数据报的协议目标与载荷。 */
    struct DatagramPacket final
    {
        Prism::Network::Target Target;
        std::vector<std::uint8_t> Payload;
    };

    /** @brief Relay 配置服务与会话观察 owner。 */
    struct DatagramRelayOptions final
    {
        Prism::Contract::DatagramServices Services;
        DatagramObservation Observation;
    };

    /** @brief 冷路径快照整条 NextLayer 的 CarrierActivity。 */
    [[nodiscard]] inline auto CaptureDatagramCarrierActivities(
        const Prism::Transmission& Carrier)
        -> std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>>
    {
        std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>> Activities;
        for (auto* Layer = &Carrier; Layer; Layer = Layer->NextLayer())
            Activities.push_back(Layer->Activity());
        return Activities;
    }

    /** @brief 以值持有 Wire、服务、独立 I/O 队列与回复缓冲的 typed relay owner。 */
    template<class Wire>
    class DatagramRelayPump final
    {
        using ActivityPtr = std::shared_ptr<Prism::Contract::CarrierActivity>;
        using Failure = Prism::Fault::Failure;
        using Result = std::expected<void, Failure>;
        using ReplyQueue = Net::experimental::concurrent_channel<
            void(boost::system::error_code, DatagramReply)>;
        using Signal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;
        static constexpr std::size_t QueueLimit = 64;
        static constexpr std::size_t PeerLimit = 256;
        static constexpr std::size_t MaxDatagram = 65535;

    public:
        DatagramRelayPump(Wire Value, DatagramRelayOptions Options)
            : Wire_(std::move(Value)), Options_(std::move(Options)),
              Deadline_(Wire_.Executor(), Options_.Services.IdleTimeout),
              Replies_(Wire_.Executor(), QueueLimit),
              V4_(Wire_.Executor(), false), V6_(Wire_.Executor(), true),
              CarrierActivities_(Wire_.CarrierActivities())
        {
            Traffic_.Sink = Options_.Services.Traffic;
            Traffic_.Owner = Prism::Foundation::TrafficEvent{
                .Generation = Options_.Observation.Request.TaskIdentity.Generation,
                .Worker = Options_.Observation.Request.TaskIdentity.WorkerId,
                .Session = Options_.Observation.Request.TaskIdentity.SessionId,
                .Stream = Options_.Observation.Request.TaskIdentity.StreamId,
                .Task = Options_.Observation.Request.TaskIdentity.TaskId,
                .Account = Options_.Observation.AccountId};
        }

        /** @brief 返回根 Wire 固定的原执行域。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Wire_.Executor();
        }

        /** @brief 返回 Run pump 接收取消的唯一 slot。 */
        [[nodiscard]] auto CancellationSlot() noexcept
        {
            return Cancellation_.slot();
        }

        /** @brief 返回完整 NextLayer 链的 Activity 快照。 */
        [[nodiscard]] auto CarrierActivities() const noexcept
            -> const std::vector<ActivityPtr>&
        {
            return CarrierActivities_;
        }

        /** @brief 在启动热路径前验证 Wire 和协议目标。 */
        [[nodiscard]] auto Validate() const noexcept -> Prism::Fault::Code
        {
            return Wire_.Validate();
        }

        /** @brief 取消当前双向 pump；最终关闭命令由 Retirement 发起。 */
        auto Stop(bool CancelRun) noexcept -> void
        {
            Closed_ = true;
            if (CancelRun)
            {
                Preserve(Failure{Prism::Fault::Code::Canceled});
            }
            Cancellation_.emit(Net::cancellation_type::all);
            ClosePumps();
        }

        /**
         * @brief 按关闭意图提交 Wire control 并关闭两个地址族的本地 UDP socket。
         * @param CancelRun 是否保留显式取消语义。
         */
        [[nodiscard]] auto RequestControls(const bool CancelRun) noexcept -> Result
        {
            std::optional<Failure> First = ControlFailure_;
            if (CancelRun)
            {
                try
                {
                    const auto Control = Wire_.Cancel();
                    if (!Control) Preserve(First, Control.error());
                }
                catch (...)
                {
                    Preserve(First, DatagramFailure::FromException(std::current_exception()));
                }
            }
            try
            {
                const auto Control = Wire_.Close();
                if (!Control) Preserve(First, Control.error());
            }
            catch (...)
            {
                Preserve(First, DatagramFailure::FromException(std::current_exception()));
            }
            CloseSocket(V4_.Socket, &First);
            CloseSocket(V6_.Socket, &First);
            if (First)
            {
                Preserve(ControlFailure_, *First);
                return std::unexpected(*First);
            }
            return {};
        }

        /** @brief 同时运行载体输入、双 family UDP sender/receiver 与唯一 carrier writer。 */
        [[nodiscard]] auto Run() -> Net::awaitable<Result>
        {
            using Net::experimental::awaitable_operators::operator&&;
            try
            {
                const auto [Input, Writer, Families] = co_await (
                    RunInputAndWriter() && RunFamilies());
                const auto [V4, V6] = Families;
                Record(Input);
                Record(Writer);
                Record(V4);
                Record(V6);
            }
            catch (...)
            {
                const auto Cause = DatagramFailure::FromException(
                    std::current_exception());
                if (!IsClosingCancellation(Cause)) Preserve(Cause);
                ClosePumps();
            }
            if (FirstFailure_) co_return std::unexpected(*FirstFailure_);
            co_return Result{};
        }

        /** @brief 完成一次 Run 的统计报告；幂等保留到退休完成。 */
        auto Report() noexcept -> void
        {
            if (Reported_) return;
            Options_.Observation.Finish({Datagrams_, UpBytes_, DownBytes_});
            Traffic_.Complete();
            Reported_ = true;
        }

    private:
        [[nodiscard]] auto RunInputAndWriter() -> Net::awaitable<std::tuple<Result, Result>>
        {
            using Net::experimental::awaitable_operators::operator&&;
            co_return co_await (ReadInputs() && WriteReplies());
        }

        [[nodiscard]] auto RunFamilies() -> Net::awaitable<std::tuple<Result, Result>>
        {
            using Net::experimental::awaitable_operators::operator&&;
            auto Results = co_await (RunFamily(V4_) && RunFamily(V6_));
            Replies_.close();
            co_return Results;
        }

        /** @brief 读取并解码输入；解析后即入有界 family queue，不等待任何 UDP 回复。 */
        [[nodiscard]] auto ReadInputs() -> Net::awaitable<Result>
        {
            while (!Closed_)
            {
                DatagramPacket Packet;
                const auto Received = co_await Deadline_.Await(Wire_.Receive(Packet));
                if (!Received)
                {
                    const auto Cause = Received.error();
                    if (IsClosingCancellation(Cause))
                    {
                        FinishInput();
                        co_return Result{};
                    }
                    if (Cause.Code == Prism::Fault::Code::Eof ||
                        Cause.Code == Prism::Fault::Code::Timeout)
                    {
                        FinishInput();
                        co_return Result{};
                    }
                    Abort(Cause);
                    co_return std::unexpected(Cause);
                }
                if (Datagrams_++ == 0U) Options_.Observation.FirstTarget(Packet.Target);

                const auto Target = co_await Deadline_.Await(
                    Prism::Protocols::ResolveDatagram(
                        Options_.Services, std::move(Packet.Target)));
                if (!Target)
                {
                    if (IsClosingCancellation(Target.error()))
                    {
                        FinishInput();
                        co_return Result{};
                    }
                    Abort(Target.error());
                    co_return std::unexpected(Target.error());
                }
                if (Target->port() == 0U)
                {
                    const Failure Cause{Prism::Fault::Code::InvalidArgument};
                    Abort(Cause);
                    co_return std::unexpected(Cause);
                }

                auto& Lane = Target->address().is_v4() ? V4_ : V6_;
                DatagramEgress Value{*Target, std::move(Packet.Payload)};
                boost::system::error_code Error;
                const auto Queued = co_await Deadline_.AwaitIo(
                    Lane.Outgoing.async_send(boost::system::error_code{},
                        std::move(Value), Net::redirect_error(Net::use_awaitable, Error)), Error);
                if (!Queued)
                {
                    const auto Cause = FirstFailure_.value_or(Queued.error());
                    if (IsClosingCancellation(Cause))
                    {
                        FinishInput();
                        co_return Result{};
                    }
                    if (!Closed_) Abort(Cause);
                    co_return std::unexpected(Cause);
                }
            }
            FinishInput();
            const auto Cause = FirstFailure_.value_or(Failure{Prism::Fault::Code::Canceled});
            if (FirstFailure_) co_return std::unexpected(Cause);
            co_return Result{};
        }

        /** @brief family sender 只发送已解析数据报并为回包 peer 建立精确闭包。 */
        [[nodiscard]] auto SendPackets(DatagramFamilyLane& Lane) -> Net::awaitable<Result>
        {
            for (;;)
            {
                boost::system::error_code QueueError;
                auto Value = co_await Lane.Outgoing.async_receive(
                    Net::redirect_error(Net::use_awaitable, QueueError));
                if (QueueError)
                {
                    Lane.SenderFinished = true;
                    (void)Lane.Ready.try_send(boost::system::error_code{});
                    if (Lane.Socket.is_open() && Options_.Services.IdleTimeout.count() > 0)
                        Lane.Idle.expires_after(Options_.Services.IdleTimeout);
                    co_return Result{};
                }

                boost::system::error_code Error;
                if (!Lane.Socket.is_open())
                {
                    const auto Protocol = Lane.IsV6 ? Udp::v6() : Udp::v4();
                    Lane.Socket.open(Protocol, Error);
                    if (!Error) Lane.Socket.bind(Udp::endpoint(Protocol, 0), Error);
                    if (Error)
                    {
                        const auto Cause = Prism::Fault::FromNative(
                            static_cast<std::error_code>(Error));
                        Abort(Cause);
                        co_return std::unexpected(Cause);
                    }
                    (void)Lane.Ready.try_send(boost::system::error_code{});
                }

                if (!RememberPeer(Lane, Value.Target))
                {
                    const Failure Cause{Prism::Fault::Code::ResourceUnavailable};
                    Abort(Cause);
                    co_return std::unexpected(Cause);
                }

                const auto Sent = co_await Deadline_.AwaitIo(Lane.Socket.async_send_to(
                    Net::buffer(Value.Payload.data(), Value.Payload.size()), Value.Target,
                    Net::redirect_error(Net::use_awaitable, Error)), Error);
                if (!Sent)
                {
                    const auto Cause = Sent.error();
                    Abort(Cause);
                    co_return std::unexpected(Cause);
                }
                UpBytes_ += *Sent;
                Traffic_.Transfer(*Sent,
                    Prism::Foundation::TrafficObservation::Direction::Upload);
            }
        }

        /** @brief family receiver 接收任意回复数，只转交来自本 session 目标集的 peer。 */
        [[nodiscard]] auto ReceiveReplies(DatagramFamilyLane& Lane)
            -> Net::awaitable<Result>
        {
            std::array<std::uint8_t, MaxDatagram> Buffer{};
            while (!Closed_)
            {
                if (!Lane.Socket.is_open())
                {
                    if (Lane.SenderFinished) co_return Result{};
                    boost::system::error_code ReadyError;
                    co_await Lane.Ready.async_receive(
                        Net::redirect_error(Net::use_awaitable, ReadyError));
                    if (ReadyError)
                    {
                        if (Closed_ || Lane.SenderFinished) co_return Result{};
                        const auto Cause = Prism::Fault::FromNative(
                            static_cast<std::error_code>(ReadyError));
                        Abort(Cause);
                        co_return std::unexpected(Cause);
                    }
                    continue;
                }

                Udp::endpoint Source;
                boost::system::error_code Error;
                std::size_t Count = 0;
                if (Options_.Services.IdleTimeout.count() > 0)
                {
                    using Net::experimental::awaitable_operators::operator||;
                    auto Receive = Lane.Socket.async_receive_from(Net::buffer(Buffer), Source,
                        Net::redirect_error(Net::use_awaitable, Error));
                    boost::system::error_code TimerError;
                    auto Timeout = Lane.Idle.async_wait(
                        Net::redirect_error(Net::use_awaitable, TimerError));
                    const auto Outcome = co_await (std::move(Receive) || std::move(Timeout));
                    if (Outcome.index() == 1U)
                    {
                        if (TimerError == Net::error::operation_aborted) continue;
                        if (TimerError)
                        {
                            const auto Cause = Prism::Fault::FromNative(
                                static_cast<std::error_code>(TimerError));
                            Abort(Cause);
                            co_return std::unexpected(Cause);
                        }
                        if (Lane.SenderFinished) co_return Result{};
                        continue;
                    }
                    Count = std::get<0>(std::move(Outcome));
                }
                else
                {
                    Count = co_await Lane.Socket.async_receive_from(Net::buffer(Buffer), Source,
                        Net::redirect_error(Net::use_awaitable, Error));
                }
                if (Error)
                {
                    if (Closed_ || Error == Net::error::operation_aborted) co_return Result{};
                    const auto Cause = Prism::Fault::FromNative(
                        static_cast<std::error_code>(Error));
                    Abort(Cause);
                    co_return std::unexpected(Cause);
                }
                if (!ContainsPeer(Lane, Source)) continue;
                if (Lane.SenderFinished && Options_.Services.IdleTimeout.count() > 0)
                    Lane.Idle.expires_after(Options_.Services.IdleTimeout);

                DatagramReply Reply{Source,
                    std::vector<std::uint8_t>(Buffer.begin(),
                        Buffer.begin() + static_cast<std::ptrdiff_t>(Count))};
                boost::system::error_code QueueError;
                const auto Queued = co_await Deadline_.AwaitIo(
                    Replies_.async_send(boost::system::error_code{},
                        std::move(Reply), Net::redirect_error(Net::use_awaitable, QueueError)),
                    QueueError);
                if (!Queued)
                {
                    if (Closed_) co_return Result{};
                    const auto Cause = Queued.error();
                    Abort(Cause);
                    co_return std::unexpected(Cause);
                }
            }
            co_return Result{};
        }

        [[nodiscard]] auto RunFamily(DatagramFamilyLane& Lane)
            -> Net::awaitable<Result>
        {
            using Net::experimental::awaitable_operators::operator&&;
            const auto [Sender, Receiver] = co_await (
                SendPackets(Lane) && ReceiveReplies(Lane));
            Record(Sender);
            Record(Receiver);
            if (!Sender) co_return std::unexpected(Sender.error());
            if (!Receiver) co_return std::unexpected(Receiver.error());
            co_return Result{};
        }

        /** @brief 单一 carrier writer 串行发送来自两 family 的任意数量回复。 */
        [[nodiscard]] auto WriteReplies() -> Net::awaitable<Result>
        {
            for (;;)
            {
                boost::system::error_code Error;
                auto Reply = co_await Replies_.async_receive(
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    if (Closed_ || InputEnded_) co_return Result{};
                    const auto Cause = Prism::Fault::FromNative(
                        static_cast<std::error_code>(Error));
                    Abort(Cause);
                    co_return std::unexpected(Cause);
                }

                const auto Sent = co_await Deadline_.Await(
                    Wire_.Send(Reply.Source, Reply.Payload));
                if (!Sent)
                {
                    if (IsClosingCancellation(Sent.error())) co_return Result{};
                    Abort(Sent.error());
                    co_return std::unexpected(Sent.error());
                }
                DownBytes_ += Reply.Payload.size();
                Traffic_.Transfer(Reply.Payload.size(),
                    Prism::Foundation::TrafficObservation::Direction::Download);
            }
        }

        /** @brief 保存一个精确 endpoint；达到固定容量时拒绝新增 peer。 */
        [[nodiscard]] static auto RememberPeer(DatagramFamilyLane& Lane,
                                                const Udp::endpoint& Target) -> bool
        {
            if (ContainsPeer(Lane, Target)) return true;
            if (Lane.Peers.size() == PeerLimit) return false;
            Lane.Peers.push_back(Target);
            return true;
        }

        [[nodiscard]] static auto ContainsPeer(const DatagramFamilyLane& Lane,
                                               const Udp::endpoint& Source) -> bool
        {
            return std::find(Lane.Peers.begin(), Lane.Peers.end(), Source) != Lane.Peers.end();
        }

        auto FinishInput() noexcept -> void
        {
            if (InputEnded_) return;
            InputEnded_ = true;
            V4_.Outgoing.close();
            V6_.Outgoing.close();
        }

        auto Abort(const Failure Cause) noexcept -> void
        {
            Preserve(Cause);
            Closed_ = true;
            FinishInput();
            ClosePumps();
            const auto Control = Wire_.Cancel();
            if (!Control) Preserve(ControlFailure_, Control.error());
        }

        [[nodiscard]] auto IsClosingCancellation(const Failure& Cause) const noexcept -> bool
        {
            return Closed_ && (Cause.Code == Prism::Fault::Code::Canceled ||
                Cause.Native == std::errc::operation_canceled);
        }

        auto ClosePumps() noexcept -> void
        {
            FinishInput();
            Replies_.close();
            V4_.Ready.close();
            V6_.Ready.close();
            CloseSocket(V4_.Socket, &ControlFailure_);
            CloseSocket(V6_.Socket, &ControlFailure_);
        }

        auto CloseSocket(Udp::socket& Socket, std::optional<Failure>* First) noexcept -> void
        {
            if (!Socket.is_open()) return;
            boost::system::error_code Error;
            Socket.cancel(Error);
            if (Error && First) Preserve(*First, Prism::Fault::FromNative(
                static_cast<std::error_code>(Error)));
            Error.clear();
            Socket.close(Error);
            if (Error && First) Preserve(*First, Prism::Fault::FromNative(
                static_cast<std::error_code>(Error)));
        }

        auto Preserve(const Failure Cause) noexcept -> void
        {
            if (Cause.Succeeded() || FirstFailure_) return;
            FirstFailure_ = Cause;
        }

        auto Record(const Result& Value) noexcept -> void
        {
            if (!Value) Preserve(Value.error());
        }

        static auto Preserve(std::optional<Failure>& First, const Failure Next) noexcept -> void
        {
            if (Next.Succeeded() || First) return;
            First = Next;
        }

        Wire Wire_;
        DatagramRelayOptions Options_;
        DatagramOperationDeadline Deadline_;
        ReplyQueue Replies_;
        DatagramFamilyLane V4_;
        DatagramFamilyLane V6_;
        std::vector<ActivityPtr> CarrierActivities_;
        Prism::Foundation::TrafficObservation Traffic_;
        Net::cancellation_signal Cancellation_;
        std::optional<Failure> FirstFailure_;
        std::optional<Failure> ControlFailure_;
        std::size_t UpBytes_{0}, DownBytes_{0};
        std::uint64_t Datagrams_{0};
        bool InputEnded_{false}, Closed_{false}, Reported_{false};
    };
} // namespace Prism::Protocols
