/**
 * @file DatagramListener.hpp
 * @brief Preview 唯一 UDP socket 的接收、停止和排空生命周期。
 * @details 该 listener 只拥有 socket 和 packet pump，不知道协议 handler、
 *          Worker session map 或 DNS。所有数据以 owner-held BoundaryPacket 交给
 *          BoundaryDispatcher，QUIC 与普通 UDP 不创建第二个 socket。
 */
#pragma once

#include <Preview/Boundary/Datagram/DatagramClassifier.hpp>
#include <Preview/Contract/Services/Quic.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

namespace Preview::Boundary
{

    namespace Net = boost::asio;

    /** @brief 只用于 UDP 入口：对端 ICMP 拒绝/重置不停止共享 packet pump；取消与坏 socket 仍终止。 */
    [[nodiscard]] inline auto IsRecoverableReceiveError(
        const boost::system::error_code Error) noexcept -> bool
    {
        return Error == Net::error::connection_refused || Error == Net::error::connection_reset;
    }

    enum class DatagramStartCode : std::uint8_t
    {
        Success,
        Invalid,
        AlreadyStarted,
        BindFailed,
        Closed,
    };

    struct DatagramStartResult final
    {
        DatagramStartCode Code{DatagramStartCode::Invalid};
        boost::system::error_code Error;

        [[nodiscard]] auto Succeeded() const noexcept -> bool
        {
            return Code == DatagramStartCode::Success;
        }
    };

    struct DatagramDrainResult final
    {
        bool Completed{false};
        std::uint64_t PacketsReceived{0};
    };

    struct DatagramListenerHealth final
    {
        bool Bound{false};
        bool Ready{false};
        bool Draining{false};
        std::uint64_t PacketsReceived{0};
        std::uint64_t PacketsRejected{0};
        boost::system::error_code LastError;

        [[nodiscard]] auto Healthy() const noexcept -> bool
        {
            return Bound && Ready && !Draining && !LastError;
        }
    };

    class DatagramListener final
    {
    public:
        using PacketHandler = std::function<void(BoundaryPacket)>;
        using ErrorHandler = std::function<void(boost::system::error_code)>;

        struct StartRequest final
        {
            boost::asio::ip::udp::endpoint Endpoint;
            std::shared_ptr<DatagramClassifier> Demux;
            PacketHandler Handler;
            ErrorHandler OnError;
        };

        struct StopRequest final
        {
            bool CloseSocket{true};
        };

        explicit DatagramListener(Net::any_io_executor Executor)
            : State_(std::make_shared<State>(std::move(Executor)))
        {
        }

        ~DatagramListener() noexcept
        {
            Stop(StopRequest{});
        }

        DatagramListener(const DatagramListener &) = delete;
        auto operator=(const DatagramListener &) -> DatagramListener & = delete;

        [[nodiscard]] auto Start(StartRequest Request) -> Net::awaitable<DatagramStartResult>
        {
            const auto State = State_;
            if (!Request.Demux || !Request.Handler)
            {
                co_return DatagramStartResult{DatagramStartCode::Invalid, {}};
            }
            co_await Net::dispatch(State->Executor, Net::use_awaitable);
            if (State->Closed.load(std::memory_order_acquire))
            {
                co_return DatagramStartResult{DatagramStartCode::Closed, {}};
            }
            if (State->Started.exchange(true, std::memory_order_acq_rel))
            {
                co_return DatagramStartResult{DatagramStartCode::AlreadyStarted, {}};
            }

            State->Demux = std::move(Request.Demux);
            State->Handler = std::move(Request.Handler);
            State->OnError = std::move(Request.OnError);
            boost::system::error_code Error;
            State->Socket.open(Request.Endpoint.protocol(), Error);
            if (!Error)
            {
                State->Socket.set_option(Net::socket_base::reuse_address(true), Error);
            }
            if (!Error)
            {
                State->Socket.bind(Request.Endpoint, Error);
            }
            if (Error)
            {
                State->LastError = Error;
                State->Started.store(false, std::memory_order_release);
                boost::system::error_code CloseError;
                State->Socket.close(CloseError);
                co_return DatagramStartResult{DatagramStartCode::BindFailed, Error};
            }
            State->Bound.store(true, std::memory_order_release);
            State->Ready.store(true, std::memory_order_release);
            State->ReceiveLoopStarted.store(true, std::memory_order_release);
            Net::co_spawn(State->Executor, ReceiveLoop(State), Net::detached);
            co_return DatagramStartResult{DatagramStartCode::Success, {}};
        }

        auto Stop(StopRequest Request) noexcept -> void
        {
            const auto State = State_;
            if (State->Closed.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            State->Draining.store(true, std::memory_order_release);
            State->Ready.store(false, std::memory_order_release);
            boost::system::error_code CancelError;
            State->Socket.cancel(CancelError);
            if (Request.CloseSocket)
            {
                boost::system::error_code Error;
                State->Socket.close(Error);
            }
        }

        [[nodiscard]] auto Drain() -> Net::awaitable<DatagramDrainResult>
        {
            const auto State = State_;
            co_await Net::dispatch(State->Executor, Net::use_awaitable);
            if (!State->ReceiveLoopStarted.load(std::memory_order_acquire) ||
                State->ReceiveLoopCompleted.load(std::memory_order_acquire))
            {
                co_return DatagramDrainResult{true, State->PacketsReceived.load(std::memory_order_relaxed)};
            }
            boost::system::error_code Error;
            co_await State->Completion.async_receive(Net::redirect_error(Net::use_awaitable, Error));
            co_return DatagramDrainResult{!Error,
                                     State->PacketsReceived.load(std::memory_order_relaxed)};
        }

        [[nodiscard]] auto LocalEndpoint() const -> boost::asio::ip::udp::endpoint
        {
            boost::system::error_code Error;
            return State_->Socket.local_endpoint(Error);
        }

        [[nodiscard]] auto SharedSocket() const -> std::shared_ptr<Net::ip::udp::socket>
        {
            return std::shared_ptr<Net::ip::udp::socket>(
                State_, &State_->Socket);
        }

        /** @brief 返回拥有 Boundary socket state 的服务端 UDP sender 句柄。 */
        [[nodiscard]] auto SharedSender() const
            -> std::shared_ptr<Preview::Contract::QuicDatagramSender>;
        [[nodiscard]] auto Health() const noexcept -> DatagramListenerHealth
        {
            return {State_->Bound.load(std::memory_order_acquire),
                    State_->Ready.load(std::memory_order_acquire),
                    State_->Draining.load(std::memory_order_acquire),
                    State_->PacketsReceived.load(std::memory_order_relaxed),
                    State_->PacketsRejected.load(std::memory_order_relaxed),
                    State_->LastError};
        }

    private:
        struct State final : Preview::Contract::QuicDatagramSender,
            std::enable_shared_from_this<State>
        {
            explicit State(Net::any_io_executor ExecutorValue)
                : Context(Preview::Executor::ContextOwner::Find(ExecutorValue)),
                  Executor(std::move(ExecutorValue)), Socket(Executor), Completion(Executor, 1)
            {
            }

            /** @brief 已注册 executor 的独立 context pin 最后释放，晚于 socket 与等待 channel。 */
            std::shared_ptr<Preview::Executor::ContextOwner> Context;
            Net::any_io_executor Executor;
            Net::ip::udp::socket Socket;
            Net::experimental::channel<void(boost::system::error_code)> Completion;
            std::shared_ptr<DatagramClassifier> Demux;
            PacketHandler Handler;
            ErrorHandler OnError;
            std::atomic<bool> Started{false};
            std::atomic<bool> Closed{false};
            std::atomic<bool> Bound{false};
            std::atomic<bool> Ready{false};
            std::atomic<bool> Draining{false};
            std::atomic<bool> ReceiveLoopStarted{false};
            std::atomic<bool> ReceiveLoopCompleted{false};
            std::atomic<std::uint64_t> PacketsReceived{0};
            std::atomic<std::uint64_t> PacketsRejected{0};
            boost::system::error_code LastError;

            [[nodiscard]] auto SendTo(
                const std::span<const std::byte> Payload,
                const boost::asio::ip::udp::endpoint& Peer)
                -> Net::awaitable<boost::system::error_code> override
            {
                return SendOwned(shared_from_this(), Payload, Peer);
            }

            /** @brief 首次调度前保活 socket owner、复制 peer；payload 借用至发送完成。 */
            [[nodiscard]] static auto SendOwned(std::shared_ptr<State> Owner,
                std::span<const std::byte> Payload, boost::asio::ip::udp::endpoint Peer)
                -> Net::awaitable<boost::system::error_code>
            {
                if (Owner->Context && !Owner->Context->CanDispatch())
                {
                    co_return boost::asio::error::operation_aborted;
                }
                co_return co_await Net::co_spawn(Owner->Executor,
                    SendOnExecutor(Owner, Payload, std::move(Peer)), Net::use_awaitable);
            }

            [[nodiscard]] static auto SendOnExecutor(std::shared_ptr<State> Owner,
                std::span<const std::byte> Payload, boost::asio::ip::udp::endpoint Peer)
                -> Net::awaitable<boost::system::error_code>
            {
                if (Owner->Closed.load(std::memory_order_acquire) || !Owner->Socket.is_open())
                {
                    co_return boost::system::errc::make_error_code(
                        boost::system::errc::operation_canceled);
                }
                boost::system::error_code Error;
                const auto Length = co_await Owner->Socket.async_send_to(
                    Net::buffer(Payload.data(), Payload.size()), Peer,
                    Net::redirect_error(Net::use_awaitable, Error));
                if (!Error && Length != Payload.size())
                {
                    Error = boost::system::errc::make_error_code(
                        boost::system::errc::message_size);
                }
                co_return Error;
            }
        };

        static auto ReportPacketError(
            const std::shared_ptr<State> &StateValue,
            const boost::system::error_code Error) noexcept -> void
        {
            StateValue->PacketsRejected.fetch_add(1, std::memory_order_relaxed);
            StateValue->LastError = Error;
            if (!StateValue->OnError)
            {
                return;
            }
            try
            {
                StateValue->OnError(Error);
            }
            catch (...)
            {
                // 诊断回调不能破坏 packet pump 生命周期。
            }
        }

        [[nodiscard]] static auto ReceiveLoop(std::shared_ptr<State> StateValue)
            -> Net::awaitable<void>
        {
            std::array<std::byte, 65536> Buffer{};
            while (!StateValue->Closed.load(std::memory_order_acquire))
            {
                boost::system::error_code Error;
                Net::ip::udp::endpoint Peer;
                const auto Size = co_await StateValue->Socket.async_receive_from(
                    Net::buffer(Buffer), Peer,
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    if (!StateValue->Closed.load(std::memory_order_acquire))
                    {
                        if (IsRecoverableReceiveError(Error))
                        {
                            // UDP 对端退出后产生的 ICMP 拒绝不应终止入口泵。
                            continue;
                        }
                        StateValue->LastError = Error;
                        if (StateValue->OnError)
                        {
                            try
                            {
                                StateValue->OnError(Error);
                            }
                            catch (...)
                            {
                                // 入口错误回调不能让 receive pump 逃逸异常。
                            }
                        }
                    }
                    break;
                }
                if (Size == 0U || !StateValue->Demux || !StateValue->Handler)
                {
                    StateValue->PacketsRejected.fetch_add(1, std::memory_order_relaxed);
                    continue;
                }
                try
                {
                    BoundaryPacket Packet;
                    Packet.Payload.assign(Buffer.begin(), Buffer.begin() + Size);
                    Packet.Peer = Peer;
                    Packet.Classification = StateValue->Demux->Classify(Packet.Payload);
                    Packet.Sequence = StateValue->PacketsReceived.fetch_add(
                                          1, std::memory_order_relaxed) + 1U;
                    StateValue->Handler(std::move(Packet));
                }
                catch (...)
                {
                    ReportPacketError(
                        StateValue,
                        boost::system::errc::make_error_code(boost::system::errc::io_error));
                }
            }
            StateValue->Ready.store(false, std::memory_order_release);
            StateValue->ReceiveLoopCompleted.store(true, std::memory_order_release);
            (void)StateValue->Completion.try_send(boost::system::error_code{});
        }

        std::shared_ptr<State> State_;
    };

inline auto DatagramListener::SharedSender() const
    -> std::shared_ptr<Preview::Contract::QuicDatagramSender>
{
    return std::static_pointer_cast<Preview::Contract::QuicDatagramSender>(State_);
}
} // namespace Preview::Boundary
