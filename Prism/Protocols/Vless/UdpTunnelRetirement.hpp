/**
 * @file UdpTunnelRetirement.hpp
 * @brief VLESS UDP 隧道的取消与最终关闭 owner。
 * @details 关闭路径先封止数据面、唤醒 reader/reply pump，再关闭 UDP 出站 socket 和流载体；
 *          正常 pump 结束后不再额外 Cancel 已排空的载体，避免把正常退休标记为取消。
 */
#pragma once

#include <Prism/Protocols/Vless/UdpTunnel.hpp>

namespace Prism::Vless
{

    inline auto UdpTunnel::CancelOnExecutor() noexcept -> void
    {
        if (Cancelled_ || Drained_) return;
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

    inline auto UdpTunnel::CloseOnExecutor() noexcept -> void
    {
        CloseResources();
    }

    inline auto UdpTunnel::CloseResources() noexcept -> void
    {
        if (Closed_ && CloseResourcesCompleted_.load(std::memory_order_acquire)) return;
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
            if (ErrorCode) RecordFailure(Prism::Fault::FromNative(
                static_cast<std::error_code>(ErrorCode)));
            ErrorCode.clear();
            Egress_.close(ErrorCode);
            if (ErrorCode) RecordFailure(Prism::Fault::FromNative(
                static_cast<std::error_code>(ErrorCode)));
        }
        bool CarrierClosed = false;
        if (Stream_)
        {
            try
            {
                if (Cancelled_)
                {
                    const auto Canceled = Stream_->Cancel();
                    if (!Canceled) RecordFailure(Canceled.error());
                }
                const auto Closed = Stream_->Close();
                if (!Closed) RecordFailure(Closed.error());
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
