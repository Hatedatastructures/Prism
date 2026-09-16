/**
 * @file UdpListener.hpp
 * @brief Preview 唯一 UDP socket 的接收、停止和排空生命周期。
 * @details 该 listener 只拥有 socket 和 packet pump，不知道协议 handler、
 *          Worker session map 或 DNS。所有数据以 owner-held UdpPacket 交给
 *          IngressDispatcher，QUIC 与普通 UDP 不创建第二个 socket。
 */
#pragma once

#include <Preview/Ingress/UdpDemux.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/dispatch.hpp>
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
#include <system_error>
#include <utility>

namespace Preview::Ingress
{

    namespace Net = boost::asio;

    enum class UdpStartCode : std::uint8_t
    {
        Success,
        Invalid,
        AlreadyStarted,
        BindFailed,
        Closed,
    };

    struct UdpStartResult final
    {
        UdpStartCode Code{UdpStartCode::Invalid};
        boost::system::error_code Error;

        [[nodiscard]] auto Succeeded() const noexcept -> bool
        {
            return Code == UdpStartCode::Success;
        }
    };

    struct UdpDrainResult final
    {
        bool Completed{false};
        std::uint64_t PacketsReceived{0};
    };

    struct UdpListenerHealth final
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

    class UdpListener final
    {
    public:
        using PacketHandler = std::function<void(UdpPacket)>;
        using ErrorHandler = std::function<void(boost::system::error_code)>;

        struct StartRequest final
        {
            boost::asio::ip::udp::endpoint Endpoint;
            std::shared_ptr<UdpDemux> Demux;
            PacketHandler Handler;
            ErrorHandler OnError;
        };

        struct StopRequest final
        {
            bool CloseSocket{true};
        };

        explicit UdpListener(Net::any_io_executor Executor)
            : State_(std::make_shared<State>(std::move(Executor)))
        {
        }

        ~UdpListener() noexcept
        {
            Stop(StopRequest{});
        }

        UdpListener(const UdpListener &) = delete;
        auto operator=(const UdpListener &) -> UdpListener & = delete;

        [[nodiscard]] auto Start(StartRequest Request) -> Net::awaitable<UdpStartResult>
        {
            const auto State = State_;
            if (!Request.Demux || !Request.Handler)
            {
                co_return UdpStartResult{UdpStartCode::Invalid, {}};
            }
            co_await Net::dispatch(State->Executor, Net::use_awaitable);
            if (State->Closed.load(std::memory_order_acquire))
            {
                co_return UdpStartResult{UdpStartCode::Closed, {}};
            }
            if (State->Started.exchange(true, std::memory_order_acq_rel))
            {
                co_return UdpStartResult{UdpStartCode::AlreadyStarted, {}};
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
                co_return UdpStartResult{UdpStartCode::BindFailed, Error};
            }
            State->Bound.store(true, std::memory_order_release);
            State->Ready.store(true, std::memory_order_release);
            State->ReceiveLoopStarted.store(true, std::memory_order_release);
            Net::co_spawn(State->Executor, ReceiveLoop(State), Net::detached);
            co_return UdpStartResult{UdpStartCode::Success, {}};
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

        [[nodiscard]] auto Drain() -> Net::awaitable<UdpDrainResult>
        {
            const auto State = State_;
            co_await Net::dispatch(State->Executor, Net::use_awaitable);
            if (!State->ReceiveLoopStarted.load(std::memory_order_acquire) ||
                State->ReceiveLoopCompleted.load(std::memory_order_acquire))
            {
                co_return UdpDrainResult{true, State->PacketsReceived.load(std::memory_order_relaxed)};
            }
            boost::system::error_code Error;
            co_await State->Completion.async_receive(Net::redirect_error(Net::use_awaitable, Error));
            co_return UdpDrainResult{!Error,
                                     State->PacketsReceived.load(std::memory_order_relaxed)};
        }

        [[nodiscard]] auto LocalEndpoint() const -> boost::asio::ip::udp::endpoint
        {
            boost::system::error_code Error;
            return State_->Socket.local_endpoint(Error);
        }

        [[nodiscard]] auto Health() const noexcept -> UdpListenerHealth
        {
            return {State_->Bound.load(std::memory_order_acquire),
                    State_->Ready.load(std::memory_order_acquire),
                    State_->Draining.load(std::memory_order_acquire),
                    State_->PacketsReceived.load(std::memory_order_relaxed),
                    State_->PacketsRejected.load(std::memory_order_relaxed),
                    State_->LastError};
        }

    private:
        struct State final
        {
            explicit State(Net::any_io_executor ExecutorValue)
                : Executor(std::move(ExecutorValue)), Socket(Executor), Completion(Executor, 1)
            {
            }

            Net::any_io_executor Executor;
            Net::ip::udp::socket Socket;
            Net::experimental::channel<void(boost::system::error_code)> Completion;
            std::shared_ptr<UdpDemux> Demux;
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
                    UdpPacket Packet;
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

} // namespace Preview::Ingress
