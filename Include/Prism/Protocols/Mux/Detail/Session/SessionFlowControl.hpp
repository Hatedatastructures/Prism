/**
 * @file SessionFlowControl.hpp
 * @brief 多路复用会话的 flow control 和接收预算职责。
 * @details 本文件只拥有窗口状态、等待通知以及接收队列预算的转换；帧处理
 *          通过这些成员提交数据和窗口更新。
 */

#pragma once

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <limits>
#include <memory>

#include <Prism/Protocols/Mux/Detail/Session/SessionContract.hpp>
#include <cstddef>
#include <cstdint>
#include <span>

namespace Prism::Mux
{

    template <typename C, Prism::Memory::Restrict Memory>
    [[nodiscard]] inline constexpr auto Session<C, Memory>::UsesFlowControl() noexcept -> bool
    {
        if constexpr (requires { C::UsesFlowControl; })
        {
            return C::UsesFlowControl;
        }
        return false;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    [[nodiscard]] inline constexpr auto Session<C, Memory>::InitialFlowWindow() noexcept
        -> std::uint64_t
    {
        if constexpr (requires { C::InitialWindow; })
        {
            return C::InitialWindow;
        }
        return 0;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::InitializeLocalFlow(const std::uint32_t StreamId) -> void
    {
        if constexpr (UsesFlowControl())
        {
            Flow_[StreamId] = FlowState{
                .SendWindow = 0,
                .ReceiveWindow = InitialFlowWindow(),
                .Notify = std::make_shared<FlowNotify>(Ex_, 1)};
        }
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::InitializeIncomingFlow(const FrameType &Frame) -> void
    {
        if constexpr (UsesFlowControl())
        {
            auto SendWindow = InitialFlowWindow();
            if constexpr (requires(const FrameType &Value)
                          {
                              C::OpenSendWindow(Value);
                          })
            {
                SendWindow = C::OpenSendWindow(Frame);
            }
            Flow_[C::FrameStreamId(Frame)] = FlowState{
                .SendWindow = SendWindow,
                .ReceiveWindow = InitialFlowWindow(),
                .Notify = std::make_shared<FlowNotify>(Ex_, 1)};
        }
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::RemoveFlow(const std::uint32_t StreamId) -> void
    {
        if constexpr (UsesFlowControl())
        {
            if (const auto It = Flow_.find(StreamId); It != Flow_.end())
            {
                if (It->second.Notify)
                {
                    (void)It->second.Notify->try_send(boost::system::error_code{});
                }
                Flow_.erase(It);
            }
        }
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::WakeFlowWaiters() noexcept -> void
    {
        if constexpr (UsesFlowControl())
        {
            for (auto &[Id, State] : Flow_)
            {
                (void)Id;
                if (State.Notify)
                {
                    (void)State.Notify->try_send(boost::system::error_code{});
                }
            }
        }
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::AddSendWindow(
        const std::uint32_t StreamId,
        const std::uint32_t Delta) -> void
    {
        if constexpr (UsesFlowControl())
        {
            const auto It = Flow_.find(StreamId);
            if (It == Flow_.end())
            {
                return;
            }
            const auto Limit = (std::numeric_limits<std::uint64_t>::max)();
            if (Delta > Limit - It->second.SendWindow)
            {
                It->second.SendWindow = Limit;
            }
            else
            {
                It->second.SendWindow += Delta;
            }
            if (It->second.Notify)
            {
                (void)It->second.Notify->try_send(boost::system::error_code{});
            }
        }
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::ReturnSendWindow(
        const std::uint32_t StreamId,
        const std::size_t Delta) -> void
    {
        const auto Bounded = (std::min)(
            Delta, static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()));
        AddSendWindow(StreamId, static_cast<std::uint32_t>(Bounded));
    }

    template <typename C, Prism::Memory::Restrict Memory>
    [[nodiscard]] inline auto Session<C, Memory>::ReserveSendWindow(
        const std::uint32_t StreamId,
        const std::size_t Requested) -> std::size_t
    {
        if constexpr (UsesFlowControl())
        {
            const auto It = Flow_.find(StreamId);
            if (It == Flow_.end())
            {
                return 0;
            }
            const auto Granted = (std::min)(
                Requested, static_cast<std::size_t>(It->second.SendWindow));
            It->second.SendWindow -= Granted;
            return Granted;
        }
        return Requested;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    [[nodiscard]] inline auto Session<C, Memory>::WaitForSendWindow(
        const std::uint32_t StreamId) -> Net::awaitable<bool>
    {
        if constexpr (UsesFlowControl())
        {
            while (!SessionClosed_)
            {
                const auto It = Flow_.find(StreamId);
                if (It == Flow_.end() || !It->second.Notify)
                {
                    co_return false;
                }
                if (It->second.SendWindow != 0)
                {
                    co_return true;
                }
                auto Notify = It->second.Notify;
                Notify->reset();
                co_await Notify->async_receive(Net::use_awaitable);
            }
            co_return false;
        }
        co_return true;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::IncreaseReceiveWindow(
        const std::uint32_t StreamId,
        const std::uint32_t Delta) -> void
    {
        if constexpr (UsesFlowControl())
        {
            const auto It = Flow_.find(StreamId);
            if (It == Flow_.end())
            {
                return;
            }
            const auto Limit = (std::numeric_limits<std::uint64_t>::max)();
            if (Delta > Limit - It->second.ReceiveWindow)
            {
                It->second.ReceiveWindow = Limit;
            }
            else
            {
                It->second.ReceiveWindow += Delta;
            }
        }
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline void Session<C, Memory>::OnStreamRxConsumed(
        const std::uint32_t StreamId,
        const std::size_t Bytes) noexcept
    {
        SessionRxBytes_ -= std::min(SessionRxBytes_, Bytes);
        if constexpr (requires(std::uint32_t Id, std::uint32_t Delta)
                      {
                          C::BuildWindowUpdate(Id, Delta);
                      })
        {
            if (Bytes == 0 || SessionClosed_ || !Raw_ || !Raw_->IsOpen())
            {
                return;
            }
            const auto Delta = (std::min)(
                Bytes, static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()));
            if (Delta == 0)
            {
                return;
            }
            if constexpr (UsesFlowControl())
            {
                if (!Flow_.contains(StreamId))
                {
                    return;
                }
                IncreaseReceiveWindow(StreamId, static_cast<std::uint32_t>(Delta));
            }
            try
            {
                auto Self = this->shared_from_this();
                Net::co_spawn(
                    Ex_,
                    [Self, StreamId, Delta = static_cast<std::uint32_t>(Delta)]() -> Net::awaitable<void>
                    {
                        (void)co_await Self->RawWrite(C::BuildWindowUpdate(StreamId, Delta));
                    },
                    Net::detached);
            }
            catch (...)
            {
            }
        }
    }

    template <typename C, Prism::Memory::Restrict Memory>
    [[nodiscard]] inline auto Session<C, Memory>::DeliverRx(
        const std::shared_ptr<StreamHandle<Memory>> &Handle,
        const std::span<const std::uint8_t> Payload) -> bool
    {
        if (Payload.empty())
        {
            return true;
        }
        if (!Handle || Handle->IsClosed())
        {
            return true;
        }
        const auto Used = (std::min)(SessionRxBytes_, Opt_.MaxSessionRxBytes);
        if (Opt_.MaxSessionRxBytes != 0 &&
            Payload.size() > Opt_.MaxSessionRxBytes - Used)
        {
            return false;
        }
        if constexpr (UsesFlowControl())
        {
            const auto It = Flow_.find(Handle->Id());
            if (It == Flow_.end() || Payload.size() > It->second.ReceiveWindow)
            {
                return false;
            }
            It->second.ReceiveWindow -= Payload.size();
        }
        if (!Handle->PushRx(Payload))
        {
            return false;
        }
        SessionRxBytes_ += Payload.size();
        return true;
    }

} // namespace Prism::Mux
