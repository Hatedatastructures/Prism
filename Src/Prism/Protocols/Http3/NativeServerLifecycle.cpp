/**
 * @file NativeServerLifecycle.cpp
 * @brief HTTP/3 服务端关闭、排空与物理退休 owner。
 * @details Close 保留流映射和回调 owner，直到 Run 与子任务真实退栈。
 */

#include <Prism/Protocols/Http3/Detail/NativeServer.hpp>

namespace Prism::Http3::Detail
{
    auto NativeServerSessionOwner::Close() -> Prism::Transmission::ControlResult
    {
        auto Self = shared_from_this();
        Net::dispatch(Options_.Executor,
                      [Self = std::move(Self)]() mutable { Self->CloseOnExecutor(); });
        return {};
    }

    auto NativeServerSessionOwner::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::dispatch(Options_.Executor, Net::use_awaitable);
        CloseOnExecutor();
        const auto Drained = co_await Tasks_.Drain();
        if (!Drained) RecordFailure(Drained.error());
        if (Tasks_.Active() != 0)
        {
            if (!FirstFailure_.Failed())
                RecordFailure({Prism::Fault::Code::Blocked});
            co_return std::unexpected(FirstFailure_);
        }
        bool Complete = true;
        for (const auto &[StreamId, Provider] : Streams_)
        {
            (void)StreamId;
            const auto Retired = co_await DrainProvider(Provider);
            Complete = Retired && Complete;
        }
        for (const auto &Provider : PendingProviders_)
        {
            const auto Retired = co_await DrainProvider(Provider);
            Complete = Retired && Complete;
        }
        if (!Complete)
        {
            if (!FirstFailure_.Failed())
                RecordFailure({Prism::Fault::Code::Blocked});
            co_return std::unexpected(FirstFailure_);
        }
        if (Events_)
        {
            Events_->Retire();
            Events_.reset();
        }
        Streams_.clear();
        PendingProviders_.clear();
        Modes_.clear();
        Http3Streams_.fill(nullptr);
        Options_.OpenUnidirectional = {};
        Options_.AcceptUnidirectional = {};
        Options_.AcceptBidirectional = {};
        Options_.OnEvent = {};
        Options_.Observer = {};
        Options_.Factory.reset();
        Server_.reset();
        EventQueueRetiredAtomic_.store(true, std::memory_order_release);
        RetiredAtomic_.store(true, std::memory_order_release);
        if (TaskFailed_.load(std::memory_order_acquire) && !FirstFailure_.Failed())
        {
            RecordFailure({Prism::Fault::Code::Blocked});
        }
        if (FirstFailure_.Failed()) co_return std::unexpected(FirstFailure_);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto NativeServerSessionOwner::DrainProvider(
        const Prism::Quic::SharedStreamProvider &Provider) -> Net::awaitable<bool>
    {
        const auto Closed = Provider->Close();
        if (!Closed) RecordFailure(Closed.error());
        const auto Activity = Provider->Activity();
        if (!Activity)
        {
            RecordFailure({Prism::Fault::Code::InvalidArgument});
            co_return false;
        }
        const auto Drained = co_await Activity->Drain();
        if (!Drained) RecordFailure(Drained.error());
        if (!Activity->IsRetired())
        {
            RecordFailure({Prism::Fault::Code::Blocked});
            co_return false;
        }
        co_return true;
    }

    auto NativeServerSessionOwner::RecordFailure(
        const Prism::Fault::Failure Failure) noexcept -> void
    {
        if (!FirstFailure_.Failed() && Failure.Failed()) FirstFailure_ = Failure;
    }

    auto NativeServerSessionOwner::ProtocolReady() const noexcept -> bool
    {
        return Server_ && Server_->IsOpen() && !Closed_;
    }

    auto NativeServerSessionOwner::IsRetired() const noexcept -> bool
    {
        return RetiredAtomic_.load(std::memory_order_acquire);
    }

    auto NativeServerSessionOwner::CloseOnExecutor() -> void
    {
        if (Closed_)
        {
            ClosedAtomic_.store(true, std::memory_order_release);
            return;
        }
        Closed_ = true;
        Tasks_.Seal();
        if (Events_)
        {
            Events_->Close();
        }
        for (auto &[StreamId, Provider] : Streams_)
        {
            (void)StreamId;
            if (Provider)
            {
                const auto Closed = Provider->Close();
                if (!Closed) RecordFailure(Closed.error());
            }
        }
        for (const auto &Provider : PendingProviders_)
        {
            if (Provider)
            {
                const auto Closed = Provider->Close();
                if (!Closed) RecordFailure(Closed.error());
            }
        }
        if (Server_)
        {
            Server_->Close();
        }
        ClosedAtomic_.store(true, std::memory_order_release);
    }
}
