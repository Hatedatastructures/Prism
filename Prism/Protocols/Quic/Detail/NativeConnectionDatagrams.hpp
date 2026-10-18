/**
 * @file NativeConnectionDatagrams.hpp
 * @brief 原生 QUIC DATAGRAM session owner。
 * @details 负责数据报 provider、发送重试、关闭与有界接收 inbox；
 *          丢弃统计仍由 NativeConnection health 暴露。
 */

#pragma once


#include <Prism/Protocols/Quic/Detail/NativeConnection.hpp>

namespace Prism::Quic::Detail
{
    inline auto NativeConnection::DatagramProvider() -> SharedDatagramProvider
    {
        if (ClosedAtomic_.load(std::memory_order_acquire) || !Datagram_)
        {
            return nullptr;
        }
        return std::make_shared<NativeDatagram>(weak_from_this(), Datagram_);
    }


    inline auto NativeConnection::WriteDatagram(
        std::vector<std::byte> Data,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        const auto Self = shared_from_this();
        (void)Self;
        ErrorCode.clear();
        if (Closed_ || !Conn_ || Data.empty())
        {
            if (Data.empty() && !Closed_ && Conn_)
            {
                co_return 0;
            }
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            co_return 0;
        }

        boost::system::error_code PermitError;
        co_await WritePermit_.async_receive(Net::redirect_error(Net::use_awaitable, PermitError));
        if (PermitError || Closed_ || !Conn_)
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            co_return 0;
        }

        std::size_t RetryCount = 0;
        Net::steady_timer RetryTimer(Executor_);
        while (!Closed_ && Conn_ && RetryCount < 1000)
        {
            std::array<std::byte, 65536> Packet{};
            ngtcp2_path_storage PathStorage{};
            auto Local = Socket_->local_endpoint();
            auto *Path = MakePath(PathStorage, Local, Peer_);
            ngtcp2_pkt_info PacketInfo{};
            int Accepted = 0;
            const ngtcp2_vec Vector{
                reinterpret_cast<std::uint8_t *>(Data.data()), Data.size()};
            const auto PacketLength = ngtcp2_conn_writev_datagram(
                Conn_, Path, &PacketInfo, reinterpret_cast<std::uint8_t *>(Packet.data()), Packet.size(), &Accepted,
                NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 0, &Vector, 1, Now());
            if (RandomFailed_)
            {
                ErrorCode = ToStdError(Prism::Error::IoError);
                break;
            }
            if (PacketLength < 0)
            {
                ErrorCode = ToStdError(Prism::Error::IoError);
                break;
            }
            if (PacketLength > 0)
            {
                QueuePacket(Packet.data(), static_cast<std::size_t>(PacketLength), Peer_);
            }
            if (Accepted > 0)
            {
                ngtcp2_conn_update_pkt_tx_time(Conn_, Now());
                if (!co_await WaitForSendDrain())
                {
                    ErrorCode = ToStdError(Prism::Error::BrokenPipe);
                    (void)WritePermit_.try_send(boost::system::error_code{});
                    co_return 0;
                }
                (void)WritePermit_.try_send(boost::system::error_code{});
                co_return Data.size();
            }
            RetryTimer.expires_after(std::chrono::milliseconds(1));
            boost::system::error_code TimerError;
            co_await RetryTimer.async_wait(Net::redirect_error(Net::use_awaitable, TimerError));
            if (TimerError || Closed_ || !Conn_)
            {
                ErrorCode = ToStdError(Prism::Error::BrokenPipe);
                break;
            }
            ++RetryCount;
        }
        if (!ErrorCode)
        {
            ErrorCode = ToStdError(Prism::Error::IoError);
        }
        (void)WritePermit_.try_send(boost::system::error_code{});
        co_return 0;
    }


    inline auto NativeConnection::CloseDatagram(const std::shared_ptr<DatagramState> &State) -> void
    {
        if (State)
        {
            State->Closed = true;
            (void)State->Notify.try_send(boost::system::error_code{});
        }
    }


    inline auto NativeConnection::OnDatagram(const std::span<const std::byte> Data) -> void
    {
        if (!Datagram_ || Datagram_->Closed)
        {
            return;
        }
        if (Datagram_->Inbox.Enqueue(Data))
        {
            (void)Datagram_->Notify.try_send(boost::system::error_code{});
        }
        else
        {
            auto Dropped = DroppedDatagramsAtomic_.load(std::memory_order_relaxed);
            while (Dropped != (std::numeric_limits<std::uint64_t>::max)() &&
                   !DroppedDatagramsAtomic_.compare_exchange_weak(
                       Dropped, Dropped + 1U, std::memory_order_relaxed))
            {
            }
        }
    }


} // namespace Prism::Quic::Detail

