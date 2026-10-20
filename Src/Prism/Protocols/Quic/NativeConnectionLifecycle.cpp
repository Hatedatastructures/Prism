/**
 * @file NativeConnectionLifecycle.cpp
 * @brief 原生 QUIC connection lifecycle owner。
 * @details 负责启动、握手等待、协议就绪、关闭通知和上层 exporter；
 *          不实现 ngtcp2 packet encode/decode。
 */
#include <Prism/Protocols/Quic/Detail/NativeConnection.hpp>
#include <Prism/Protocols/Quic/Detail/NativeConnectionSocketRegistry.hpp>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Quic::Detail
{
    auto NativeConnection::EmitLifecycle(
        const Prism::Quic::ServerLifecycleStage Stage,
        const std::int64_t Code) noexcept -> void
    {
        if (!OnLifecycle_)
        {
            return;
        }
        try
        {
            OnLifecycle_(Prism::Quic::ServerLifecycleEvent{Stage, Code});
        }
        catch (...)
        {
        }
    }

    auto NativeConnection::Start() -> void
    {
        auto Self = shared_from_this();
        auto Start = [Self = std::move(Self)]() mutable -> void { Self->StartOnExecutor(); };
        Net::dispatch(Executor_, std::move(Start));
    }

    auto NativeConnection::StartOnExecutor() -> void
    {
        if (Started_ || Closed_)
        {
            return;
        }
        Started_ = true;
        if (!Socket_ || !Socket_->is_open() || (Role_ == Role::Server && !Sender_))
        {
            SignalHandshake(false);
            CloseOnExecutor();
            return;
        }

        if (Socket_->get_executor() != Executor_)
        {
            BoundedFailureAtomic_.store(true, std::memory_order_release);
            CloseOnExecutor();
            return;
        }

        if (!ExternalReceive_)
        {
            SocketToken_ = AcquireSocketToken(Socket_);
            if (!SocketToken_)
            {
                BoundedFailureAtomic_.store(true, std::memory_order_release);
                CloseOnExecutor();
                return;
            }
        }
        SocketReadyAtomic_.store(true, std::memory_order_release);

        if (!TlsContext_)
        {
            SignalHandshake(false);
            CloseOnExecutor();
            return;
        }

        if (Role_ == Role::Client && (!InitializeClient() || !InitializeTls(false)))
        {
            SignalHandshake(false);
            CloseOnExecutor();
            return;
        }

        if (Role_ == Role::Client)
        {
            QueueFlush();
        }

        if (!ExternalReceive_ && !StartTrackedLoop(LoopKind::Receive))
        {
            BoundedFailureAtomic_.store(true, std::memory_order_release);
            CloseOnExecutor();
            return;
        }
        if (!StartTrackedLoop(LoopKind::Pump))
        {
            BoundedFailureAtomic_.store(true, std::memory_order_release);
            CloseOnExecutor();
            return;
        }
        ReceiveLoopReadyAtomic_.store(true, std::memory_order_release);
    }

    auto NativeConnection::Close() -> void
    {
        if(ClosedAtomic_.load(std::memory_order_acquire))return;
        auto Self = shared_from_this();
        auto Close = [Self = std::move(Self)]() mutable -> void { Self->CloseOnExecutor(); };
        Net::dispatch(Executor_, std::move(Close));
    }

    auto NativeConnection::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return DrainOwned(shared_from_this());
    }

    /** @brief native owner 在创建等待任务时保活；实际关闭始终运行在固定 executor。 */
    auto NativeConnection::DrainOwned(std::shared_ptr<NativeConnection> Owner)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_return co_await Net::co_spawn(Owner->Executor_,
            Owner->DrainOnExecutor(), Net::use_awaitable);
    }

    auto NativeConnection::DrainOnExecutor()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        CloseOnExecutor();
        const auto Drained = co_await Loops_.Drain();
        if (!Drained) co_return std::unexpected(Drained.error());
        Prism::Fault::Failure DrainFailure{};
        if (Fatal_->HasFailure())
            DrainFailure = Prism::Fault::Failure{Prism::Fault::Code::Blocked};
        else if (SendFailure_.Failed())
            DrainFailure = SendFailure_;
        else
        {
            for (const auto &[StreamId, State] : Streams_)
            {
                (void)StreamId;
                if (State && State->StreamCloseFailure.Failed())
                {
                    DrainFailure = State->StreamCloseFailure;
                    break;
                }
            }
        }
        RetireCallbackOwnersOnExecutor();
        if (DrainFailure.Failed()) co_return std::unexpected(DrainFailure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto NativeConnection::RetireCallbackOwnersOnExecutor() noexcept -> void
    {
        OnEstablished_ = {};
        OnStream_ = {};
        OnUnidirectional_ = {};
        OnDatagram_ = {};
        OnClosed_ = {};
        OnExporter_ = {};
        OnLifecycle_ = {};
        Random_ = {};
        Sender_.reset();
        Socket_.reset();
        TlsContext_ = nullptr;
        TlsContextOwner_.reset();
        Datagram_.reset();
        while (!Streams_.empty())
        {
            const auto It = Streams_.begin();
            const auto State = It->second;
            Streams_.erase(It);
            if (!State)
            {
                continue;
            }
            State->NativeTerminal.store(true, std::memory_order_release);
            if (const auto Activity = State->Activity.lock())
            {
                Activity->MarkNativeTerminal(State->StreamCloseFailure);
            }
        }
        IncomingStreams_.clear();
        IncomingUnidirectionalStreams_.clear();
        Outbound_.clear();
        LocalCid_ = {};
        RemoteCid_ = {};
        ServerName_.clear();
        ExpectedAlpn_.clear();
        ExpectedServerName_.clear();
        CallbackOwnersRetiredAtomic_.store(true, std::memory_order_release);
    }

    auto NativeConnection::ReceivePacket(
        const Udp::endpoint &From,
        const std::span<const std::byte> Data) -> bool
    {
        EmitLifecycle(Prism::Quic::ServerLifecycleStage::PacketReceived,
                      static_cast<std::int64_t>(Data.size()));
        // 外部接收模式会在投递 Start 后立即注入首包；这里也初始化连接，避免首包致命时
        // 关闭仍归入口 listener 所有的 socket。
        if (!Started_)
        {
            StartOnExecutor();
        }
        if (!ExternalReceive_ || Closed_ || Data.empty())
        {
            EmitLifecycle(Prism::Quic::ServerLifecycleStage::PacketRejected);
            return false;
        }
        const auto Result = DecodeAndRead(From, Data);
        if (Result == DecodeResult::Fatal)
        {
            SignalHandshake(false);
            CloseOnExecutor();
            return false;
        }
        return Result == DecodeResult::Accepted;
    }

    auto NativeConnection::WaitHandshake() -> Net::awaitable<bool>
    {
        const auto Self = shared_from_this();
        (void)Self;
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        OperationReservation Reservation{Self};
        if (!Reservation)
        {
            co_return false;
        }
        if (HandshakeSignaled_)
        {
            co_return HandshakeResult_;
        }
        boost::system::error_code ReceiveError;
        const auto Result = co_await HandshakeNotify_.async_receive(
            Net::redirect_error(Net::use_awaitable, ReceiveError));
        if (ReceiveError)
        {
            co_return false;
        }
        co_return Result;
    }

    auto NativeConnection::MarkProtocolReady() -> Net::awaitable<bool>
    {
        const auto Self = shared_from_this();
        (void)Self;
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        OperationReservation Reservation{Self};
        if (!Reservation)
        {
            co_return false;
        }
        if (Closed_ || !HandshakeSignaled_ || !HandshakeResult_)
        {
            co_return false;
        }
        ProtocolReadyAtomic_.store(true, std::memory_order_release);
        co_return true;
    }


    auto NativeConnection::ExportKeyingMaterial(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) const -> bool
    {
        if (!Ssl_ || !HandshakeResult_ || Output.empty() || Label.empty())
        {
            return false;
        }
        return SSL_export_keying_material(
                   Ssl_, Output.data(), Output.size(), reinterpret_cast<const char *>(Label.data()), Label.size(),
                   reinterpret_cast<const std::uint8_t *>(Context.data()), Context.size(), 1) == 1;
    }


    auto NativeConnection::Health() const noexcept -> Prism::Quic::NativeConnectionHealth
    {
        return {SocketReadyAtomic_.load(std::memory_order_acquire),
                ReceiveLoopReadyAtomic_.load(std::memory_order_acquire),
                HandshakeReadyAtomic_.load(std::memory_order_acquire),
                ProtocolReadyAtomic_.load(std::memory_order_acquire),
                ClosedAtomic_.load(std::memory_order_acquire),
                BoundedFailureAtomic_.load(std::memory_order_acquire),
                DroppedDatagramsAtomic_.load(std::memory_order_relaxed)};
    }

    auto NativeConnection::IsRetired() const noexcept -> bool
    {
        return ClosedAtomic_.load(std::memory_order_acquire) &&
               NativeHandlesRetiredAtomic_.load(std::memory_order_acquire) &&
               CallbackOwnersRetiredAtomic_.load(std::memory_order_acquire) &&
               Loops_.IsSealed() && Loops_.Active() == 0 && !Loops_.IsBlocked();
    }


    auto NativeConnection::CloseOnExecutor() -> void
    {
        if (Closed_ && !Conn_ && !Ssl_ && !SocketToken_)
        {
            NativeHandlesRetiredAtomic_.store(true, std::memory_order_release);
            return;
        }
        Closed_ = true;
        Loops_.Seal();
        EmitLifecycle(Prism::Quic::ServerLifecycleStage::Closed);
        if (!CloseNotified_)
        {
            CloseNotified_ = true;
            if (OnClosed_)
            {
                try
                {
                    OnClosed_();
                }
                catch (...)
                {
                }
            }
        }
        ClosedAtomic_.store(true, std::memory_order_release);
        SocketReadyAtomic_.store(false, std::memory_order_release);
        ReceiveLoopReadyAtomic_.store(false, std::memory_order_release);
        HandshakeReadyAtomic_.store(false, std::memory_order_release);
        ProtocolReadyAtomic_.store(false, std::memory_order_release);
        SignalHandshake(false);
        if (Socket_ && !ExternalReceive_ && (SocketToken_ || !Started_))
        {
            boost::system::error_code ErrorCode;
            Socket_->cancel(ErrorCode);
            if (Role_ == Role::Client)
            {
                Socket_->close(ErrorCode);
            }
        }
        if (SocketToken_)
        {
            ReleaseSocketToken(Socket_, SocketToken_);
            SocketToken_.reset();
        }
        PumpTimer_.cancel();
        IncomingNotify_.cancel();
        IncomingUnidirectionalNotify_.cancel();
        HandshakeNotify_.cancel();
        WritePermit_.cancel();
        SendNotify_.cancel();
        FlowNotify_.cancel();
        for (const auto &[StreamId, State] : Streams_)
        {
            (void)StreamId;
            if (State)
            {
                State->Closed = true;
                (void)State->FinAcknowledgedNotify.try_send(boost::system::error_code{});
                if (SendFailure_.Failed() && !State->LocalWriteFailure.Failed())
                {
                    State->LocalWriteFailure = SendFailure_;
                }
                State->Notify.cancel();
            }
        }
        if (Datagram_)
        {
            Datagram_->Closed = true;
            Datagram_->Notify.cancel();
        }
        IncomingStreams_.clear();
        IncomingUnidirectionalStreams_.clear();
        Outbound_.clear();
        if (Conn_)
        {
            ngtcp2_conn_del(Conn_);
            Conn_ = nullptr;
        }
        for (const auto &[StreamId, State] : Streams_)
        {
            (void)StreamId;
            if (State)
            {
                State->SentBuffers.clear();
            }
        }
        if (Ssl_)
        {
            SSL_set_app_data(Ssl_, nullptr);
            SSL_free(Ssl_);
            Ssl_ = nullptr;
        }
        NativeHandlesRetiredAtomic_.store(true, std::memory_order_release);
    }


    auto NativeConnection::SignalHandshake(const bool Success) -> void
    {
        if (HandshakeSignaled_)
        {
            return;
        }
        HandshakeSignaled_ = true;
        HandshakeResult_ = Success;
        HandshakeReadyAtomic_.store(Success, std::memory_order_release);
        for (std::size_t Index = 0; Index < 16; ++Index)
        {
            (void)HandshakeNotify_.try_send(boost::system::error_code{}, Success);
        }
    }


    auto NativeConnection::OnHandshakeComplete() -> int
    {
        try
        {
        std::string Alpn;
        const unsigned char *Selected = nullptr;
        unsigned int Length = 0;
        if (Ssl_)
        {
            SSL_get0_alpn_selected(Ssl_, &Selected, &Length);
        }
        if (Selected != nullptr && Length != 0U)
        {
            Alpn.assign(reinterpret_cast<const char *>(Selected), Length);
        }
        if (!ExpectedAlpn_.empty() && Alpn != ExpectedAlpn_)
        {
            EmitLifecycle(Prism::Quic::ServerLifecycleStage::AlpnRejected);
            SignalHandshake(false);
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        if (!ExpectedServerName_.empty())
        {
            const char *ServerName = nullptr;
            if (Ssl_)
            {
                ServerName = SSL_get_servername(
                    Ssl_, TLSEXT_NAMETYPE_host_name);
            }
            if (!ServerName || ExpectedServerName_ != ServerName)
            {
                EmitLifecycle(Prism::Quic::ServerLifecycleStage::ServerNameRejected);
                SignalHandshake(false);
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }
        SignalHandshake(true);
        EmitLifecycle(Prism::Quic::ServerLifecycleStage::TlsHandshakeComplete);
        if (OnExporter_)
        {
            try
            {
                const std::weak_ptr<NativeConnection> Weak = weak_from_this();
                const auto Accepted = OnExporter_([Weak](std::span<std::uint8_t> Output,
                    std::span<const std::uint8_t> Label, std::string_view Context) -> bool
                {
                    const auto Owner = Weak.lock();
                    return Owner && Owner->ExportKeyingMaterial(Output, Label, Context);
                });
                if (!Accepted)
                {
                    BoundedFailureAtomic_.store(true, std::memory_order_release);
                    return NGTCP2_ERR_CALLBACK_FAILURE;
                }
            }
            catch (...)
            {
                Fatal_->Publish(std::current_exception());
                BoundedFailureAtomic_.store(true, std::memory_order_release);
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }
        if (OnEstablished_)
        {
            EmitLifecycle(Prism::Quic::ServerLifecycleStage::Established);
            try
            {
                const auto Accepted = OnEstablished_(std::move(Alpn));
                if (!Accepted)
                {
                    BoundedFailureAtomic_.store(true, std::memory_order_release);
                    return NGTCP2_ERR_CALLBACK_FAILURE;
                }
            }
            catch (...)
            {
                Fatal_->Publish(std::current_exception());
                BoundedFailureAtomic_.store(true, std::memory_order_release);
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }
        if (OnDatagram_)
        {
            try
            {
                const auto Accepted = OnDatagram_(DatagramProvider());
                if (!Accepted)
                {
                    BoundedFailureAtomic_.store(true, std::memory_order_release);
                    return NGTCP2_ERR_CALLBACK_FAILURE;
                }
            }
            catch (...)
            {
                Fatal_->Publish(std::current_exception());
                BoundedFailureAtomic_.store(true, std::memory_order_release);
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }
        return 0;
        }
        catch (...)
        {
            Fatal_->Publish(std::current_exception());
            BoundedFailureAtomic_.store(true, std::memory_order_release);
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }


} // namespace Prism::Quic::Detail
