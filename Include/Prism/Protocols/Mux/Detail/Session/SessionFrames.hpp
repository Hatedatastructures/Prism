/**
 * @file SessionFrames.hpp
 * @brief 多路复用会话的帧读取、解析、分发和流 ID 职责。
 * @details 读取失败或帧校验失败统一进入会话拆除；合法帧只通过会话状态和
 *          flow control owner 修改流表。
 */

#pragma once

#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Protocols/Mux/Codec.hpp>
#include <Prism/Protocols/Mux/SessionOptions.hpp>
#include <Prism/Protocols/Mux/Detail/Session/SessionContract.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <vector>

namespace Prism::Mux
{

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::FrameLoop() -> Net::awaitable<void>
    {
        co_await Net::dispatch(Ex_, Net::use_awaitable);
        std::vector<std::uint8_t> Header(C::HeaderLen);
        std::vector<std::uint8_t> Payload;

        while (Raw_ && Raw_->IsOpen() && !SessionClosed_)
        {
            // 读帧头。
            const auto HeaderRead = co_await Raw_->ReadExact(
                std::as_writable_bytes(std::span<std::uint8_t>(Header.data(), C::HeaderLen)));
            if (HeaderRead.Bytes != C::HeaderLen)
            {
                Teardown(HeaderRead.Failure);
                if (Raw_)
                {
                    (void)Raw_->Close();
                }
                co_return;
            }

            // 解析帧头。
            FrameType Frame{};
            if (C::ParseHeader(Header, Frame) != Error::None)
            {
                (void)Diagnose::Warn(Opt_.Trace, "MuxFrameHeaderParseFailed Action=CloseSession");
                ProtocolErrorTeardown();
                co_return;
            }

            // 读负载。
            const auto Len = C::PayloadLen(Frame);
            if (Len == 0)
            {
                if (C::ParsePayload(Frame, {}) != Error::None)
                {
                    (void)Diagnose::Warn(Opt_.Trace, "MuxEmptyPayloadParseFailed Action=CloseSession");
                    ProtocolErrorTeardown();
                    co_return;
                }
                Dispatch(Frame, {});
                if (HeaderRead.Failure.Failed())
                {
                    Teardown(HeaderRead.Failure);
                    if (Raw_)
                    {
                        (void)Raw_->Close();
                    }
                    co_return;
                }
                continue;
            }
            if (Len > C::MaxPayloadLen)
            {
                (void)Diagnose::Warn(Opt_.Trace, "MuxFramePayloadLimitExceeded Action=CloseSession");
                ProtocolErrorTeardown();
                co_return;
            }
            if (HeaderRead.Failure.Failed())
            {
                Teardown(HeaderRead.Failure);
                if (Raw_)
                {
                    (void)Raw_->Close();
                }
                co_return;
            }
            Payload.resize(Len);
            const auto PayloadRead = co_await Raw_->ReadExact(
                std::as_writable_bytes(std::span<std::uint8_t>(Payload.data(), Len)));
            if (PayloadRead.Bytes != Len)
            {
                Teardown(PayloadRead.Failure);
                if (Raw_)
                {
                    (void)Raw_->Close();
                }
                co_return;
            }
            if (C::ParsePayload(Frame, Payload) != Error::None)
            {
                (void)Diagnose::Warn(Opt_.Trace, "MuxFramePayloadParseFailed Action=CloseSession");
                ProtocolErrorTeardown();
                co_return;
            }
            Dispatch(Frame, Payload);
            if (PayloadRead.Failure.Failed())
            {
                Teardown(PayloadRead.Failure);
                if (Raw_)
                {
                    (void)Raw_->Close();
                }
                co_return;
            }
        }
        Teardown();
        co_return;
    }

    /** @brief 接收 SYN 的唯一 stream 创建与预算 owner；当前 session executor 执行，不产生第二事实。 */
    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::DispatchOpen(const FrameType& Frame, std::span<const std::uint8_t> Payload) -> void
    {
            const auto Id = C::FrameStreamId(Frame);
            if (Id == 0 || Streams_.contains(Id))
            {
                ProtocolErrorTeardown();
                return;
            }
            if (!IsPeerStreamId(Id) || Streams_.size() >= Opt_.MaxStreams)
            {
                ProtocolErrorTeardown();
                return;
            }
            auto Handle = std::make_shared<StreamHandle<Memory>>(
                StreamOptions{Id, Opt_.MaxStreamRxBytes, TaskContextForStream(Id)},
                this->shared_from_this());
            Streams_[Id] = Handle;
            InitializeIncomingFlow(Frame);
            if constexpr (requires(const FrameType &Value)
                          {
                              C::IsOpenFrame(Value);
                              C::BuildOpenAck(std::uint32_t{});
                          })
            {
                if (C::IsOpenFrame(Frame))
                {
                    ProtocolEc AckError;
                    (void)EnqueueWrite(C::BuildOpenAck(Id), AckError);
                }
            }
            Incoming_.push_back(Handle);
            AcceptNotify_.try_send(boost::system::error_code{});
            if (!Payload.empty())
            {
                if (!DeliverRx(Handle, Payload))
                {
                    (void)Diagnose::Warn(Opt_.Trace, "MuxReceiveQueueBudgetExceeded Action=CloseSession");
                    ProtocolErrorTeardown();
                }
            }
            return;
    }
    /** @brief 已有流 DATA 与显式允许的隐式开流，错误仍由同 session teardown 收口。 */
    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::DispatchData(const FrameType& Frame, std::span<const std::uint8_t> Payload) -> void
    {
            const auto Id = C::FrameStreamId(Frame);
            const auto It = Streams_.find(Id);
            if (It != Streams_.end() && It->second)
            {
                if (!DeliverRx(It->second, Payload))
                {
                    (void)Diagnose::Warn(Opt_.Trace, "MuxReceiveQueueBudgetExceeded Action=CloseSession");
                    ProtocolErrorTeardown();
                }
                return;
            }
            // 隐式开流（h2mux 无 SYN 帧：首数据帧即开流）。
            if (Id == 0)
            {
                return;
            }
            if constexpr (requires { C::AllowsImplicitOpen; })
            {
                if (!C::AllowsImplicitOpen)
                {
                    ProtocolErrorTeardown();
                    return;
                }
            }
            else
            {
                ProtocolErrorTeardown();
                return;
            }
            if (!IsPeerStreamId(Id) || Streams_.size() >= Opt_.MaxStreams)
            {
                ProtocolErrorTeardown();
                return;
            }
            auto Handle = std::make_shared<StreamHandle<Memory>>(
                StreamOptions{Id, Opt_.MaxStreamRxBytes, TaskContextForStream(Id)},
                this->shared_from_this());
            Streams_[Id] = Handle;
            Incoming_.push_back(Handle);
            AcceptNotify_.try_send(boost::system::error_code{});
            if (!Payload.empty())
            {
                if (!DeliverRx(Handle, Payload))
                {
                    (void)Diagnose::Warn(Opt_.Trace, "MuxReceiveQueueBudgetExceeded Action=CloseSession");
                    ProtocolErrorTeardown();
                }
            }
            return;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::Dispatch(
        const FrameType &Frame,
        const std::span<const std::uint8_t> Payload) -> void
    {
        if constexpr (requires(const FrameType &Value)
                      {
                          C::IsWindowUpdate(Value);
                          C::IsWindowAck(Value);
                          C::IsOpenFrame(Value);
                          C::WindowDelta(Value);
                      })
        {
            if (C::IsWindowUpdate(Frame) && C::IsWindowAck(Frame))
            {
                AddSendWindow(C::FrameStreamId(Frame), C::WindowDelta(Frame));
                return;
            }
            if (C::IsWindowUpdate(Frame) && !C::IsOpenFrame(Frame))
            {
                AddSendWindow(C::FrameStreamId(Frame), C::WindowDelta(Frame));
                return;
            }
        }

        // 会话级控制帧（心跳/GO_AWAY）：不进入虚拟流状态机。
        if (C::IsControl(Frame))
        {
            return;
        }
        const auto Event = C::FrameEvent(Frame);
        switch (Event)
        {
        case StreamEvent::Open: DispatchOpen(Frame, Payload); break;
        case StreamEvent::Data: DispatchData(Frame, Payload); break;
        case StreamEvent::Fin: {
            const auto Id = C::FrameStreamId(Frame);
            const auto It = Streams_.find(Id);
            if (It != Streams_.end() && It->second)
            {
                if (It->second->IsPeerEof())
                {
                    ProtocolErrorTeardown();
                    break;
                }
                It->second->SetPeerEof();
            }
            break;
        }
        case StreamEvent::Rst: {
            const auto Id = C::FrameStreamId(Frame);
            RemoveFlow(Id);
            const auto It = Streams_.find(Id);
            if (It != Streams_.end() && It->second)
            {
                It->second->OnRst(); // 唤醒挂起读（返回 0）。
            }
            Streams_.erase(Id);
            break;
        }
        default: break; // 会话级/心跳帧：忽略。
        }
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::AllocateId() -> std::uint32_t
    {
        if (Streams_.size() >= Opt_.MaxStreams)
        {
            return 0;
        }
        const bool Odd = Opt_.Role == Prism::Mux::Role::Client;
        constexpr auto MaxId = (std::numeric_limits<std::uint32_t>::max)();
        const auto FirstId = std::uint32_t{1} + static_cast<std::uint32_t>(!Odd);
        const auto ExpectedParity = static_cast<std::uint32_t>(Odd);
        if (NextId_ == 0)
        {
            NextId_ = FirstId;
        }
        else
        {
            // 32 位流 ID 单调递增，耗尽前禁止无符号回绕复用旧 ID。
            if (NextId_ > MaxId - 2U)
            {
                StreamIdExhausted_ = true;
                return 0;
            }
            NextId_ += 2U;
        }
        if (NextId_ == 0 || (NextId_ & 1U) != ExpectedParity || Streams_.contains(NextId_))
        {
            StreamIdExhausted_ = true;
            return 0;
        }
        return NextId_;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    [[nodiscard]] inline auto Session<C, Memory>::IsPeerStreamId(
        const std::uint32_t Id) const noexcept -> bool
    {
        const bool PeerOdd = Opt_.Role == Prism::Mux::Role::Server;
        return ((Id & 1U) != 0U) == PeerOdd;
    }

} // namespace Prism::Mux
