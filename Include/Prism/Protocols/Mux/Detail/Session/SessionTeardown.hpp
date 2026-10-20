/**
 * @file SessionTeardown.hpp
 * @brief 多路复用会话的启动、取消、关闭和资源拆除职责。
 * @details 本文件是会话最终关闭者：清理流和等待者、失败待写请求、取消底层
 *          传输，并打破 Session 与 StreamHandle 的 shared_ptr 循环。
 */

#pragma once

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <memory>
#include <utility>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Mux/Detail/Session/SessionContract.hpp>
#include <chrono>

namespace Prism::Mux
{

    template <typename C, Prism::Memory::Restrict Memory>
    inline Session<C, Memory>::Session(
        SharedTransmission Raw,
        const SessionOptions &Options)
        : Raw_(std::move(Raw)),
          Opt_(Options),
          Ex_(Opt_.Registry ? Opt_.Registry->Executor() : Net::make_strand(Raw_->Executor())),
          Tasks_(Opt_.Registry ? Opt_.Registry : std::make_shared<Prism::Lifecycle::TaskRegistry>(Ex_)),
          Identity_(Opt_.Identity),
          AcceptNotify_(Ex_, 1)
    {
        if (Raw_ && Opt_.timeout > std::chrono::milliseconds::zero())
        {
            Raw_->SetTimeout(Opt_.timeout);
        }
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::Create(
        SharedTransmission Raw,
        const SessionOptions &Options) -> std::shared_ptr<Session<C, Memory>>
    {
        if (!Raw)
        {
            return {};
        }
        auto Self = std::shared_ptr<Session<C, Memory>>(
            new Session<C, Memory>(std::move(Raw), Options));
        Self->Start();
        return Self;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::RequestClose() noexcept -> void
    {
        auto Self = this->shared_from_this();
        Net::dispatch(Ex_, [Self] {
            if (Self->CloseStarted_)
            {
                return;
            }
            Self->CloseStarted_ = true;
            Self->CloseOnExecutor();
            Net::co_spawn(Self->Ex_, DrainOnRequestClose(Self), Net::detached);
        });
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::DrainOnRequestClose(std::shared_ptr<Session> Self)
        -> Net::awaitable<void>
    {
        co_await Self->Close();
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::Close() -> Net::awaitable<void>
    {
        co_await Net::dispatch(Ex_, Net::use_awaitable);
        if (!CloseStarted_)
        {
            CloseStarted_ = true;
            CloseOnExecutor();
        }
        const auto Drained = co_await Tasks_->Drain();
        if (!Drained) co_return;
        co_await Net::dispatch(Ex_, Net::use_awaitable);
        RetireStreamsOnExecutor();
        co_return;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::CloseOnExecutor() noexcept -> void
    {
        Teardown();
        CancelRawOnExecutor();
        if (Raw_)
        {
            (void)Raw_->Close();
        }
        (void)Tasks_->Cancel();
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::RetireStreamsOnExecutor() noexcept -> void
    {
        if (StreamsRetired_)
        {
            return;
        }
        StreamsRetired_ = true;
        for (auto &[Id, Handle] : Streams_)
        {
            (void)Id;
            if (Handle)
            {
                Handle->DetachSession();
            }
        }
        Streams_.clear();
        Incoming_.clear();
        Flow_.clear();
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::Cancel() -> void
    {
        auto Self = this->shared_from_this();
        Net::dispatch(
            Ex_,
            [Self]
            {
                Self->Canceled_ = true;
                Self->CancelRawOnExecutor();
            });
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::Start() -> void
    {
        auto Self = this->shared_from_this();
        Prism::Lifecycle::TaskRequest Request;
        Request.Context = Prism::Lifecycle::FromParent(Identity_);
        Request.StartOnSubmit = true;
        const auto WeakSelf = std::weak_ptr<Session>(Self);
        Request.Cancel = [WeakSelf]
        { if (const auto Owner = WeakSelf.lock()) Owner->CancelRaw(); };
        if (!Tasks_->SpawnTracked(std::move(Request), RunFrame(Self)))
        { Teardown(); CancelRaw(); (void)Raw_->Close(); }

    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::Teardown(
        const Prism::Fault::Failure ReadTerminal,
        const ProtocolEc &PendingError) -> void
    {
        if (SessionClosed_)
        {
            return;
        }
        SessionClosed_ = true;
        SessionRxBytes_ = 0;
        AcceptNotify_.try_send(boost::system::error_code{});
        WakeFlowWaiters();
        FailPendingWrites(PendingError);
        for (auto &[Id, Handle] : Streams_)
        {
            (void)Id;
            if (Handle)
            {
                if (ReadTerminal.Succeeded() || ReadTerminal.Code == Prism::Fault::Code::Eof)
                {
                    Handle->SetPeerEof();
                }
                else
                {
                    Handle->SetPeerFailure(ReadTerminal);
                }
            }
        }
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::ReleasePendingWriteBudget(
        const std::shared_ptr<WriteRequest> &Request) noexcept -> void
    {
        if (!Request || Request->BudgetReleased || Opt_.MaxPendingWriteBytes == 0)
        {
            return;
        }
        PendingWriteBytes_ -= (std::min)(PendingWriteBytes_, Request->Frame.size());
        Request->BudgetReleased = true;
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::ProtocolErrorTeardown() -> void
    {
        Teardown(Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
        if (Raw_)
        {
            (void)Raw_->Close();
        }
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::RunFrame(std::shared_ptr<Session> Self)
        -> Net::awaitable<void>
    {
        co_await Self->FrameLoop();
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::RunWriter(std::shared_ptr<Session> Self)
        -> Net::awaitable<void>
    {
        co_await Self->WriteLoop();
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::CancelRaw() noexcept -> void
    {
        try
        {
            auto Self = this->shared_from_this();
            Net::dispatch(Ex_, [Self] { Self->CancelRawOnExecutor(); });
        }
        catch (...)
        {
        }
    }

    template <typename C, Prism::Memory::Restrict Memory>
    inline auto Session<C, Memory>::CancelRawOnExecutor() noexcept -> void
    {
        if (Raw_)
        {
            (void)Raw_->Cancel();
        }
        WakeFlowWaiters();
        AcceptNotify_.try_send(boost::system::error_code{});
    }

} // namespace Prism::Mux
