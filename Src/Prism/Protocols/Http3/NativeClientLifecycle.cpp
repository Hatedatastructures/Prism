/**
 * @file NativeClientLifecycle.cpp
 * @brief HTTP/3 客户端关闭、排空与物理退休 owner。
 * @details Close 取消工作但保留回调状态；Drain 只在任务和原生 QUIC 屏障完成后释放它们。
 */

#include <optional>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http3/Detail/NativeClient.hpp>

namespace Prism::Http3::Detail
{
    auto NativeClientSessionOwner::Close() -> Prism::Transmission::ControlResult
    {
        auto Self = shared_from_this();
        Net::dispatch(Options_.Executor,
                      [Self = std::move(Self)]() mutable { Self->CloseOnExecutor(); });
        return {};
    }

    auto NativeClientSessionOwner::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::dispatch(Options_.Executor, Net::use_awaitable);
        CloseOnExecutor();
        const auto Drained = co_await Tasks_.Drain();
        if (!Drained) RecordFailure(Drained.error());
        if (Tasks_.Active() != 0)
        {
            if (!FirstFailure_.Failed()) RecordFailure(
                {Prism::Fault::Code::Blocked});
            co_return std::unexpected(FirstFailure_);
        }
        if (Events_)
        {
            Events_->Retire();
            Events_.reset();
        }
        EventQueueRetiredAtomic_.store(true, std::memory_order_release);
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
        const auto Connection = Options_.Connection;
        if (Connection)
        {
            const auto NativeDrain = co_await Connection->Drain();
            if (!NativeDrain) RecordFailure(NativeDrain.error());
            if (!Connection->IsRetired())
            {
                if (!FirstFailure_.Failed())
                    RecordFailure({Prism::Fault::Code::Blocked});
                co_return std::unexpected(FirstFailure_);
            }
        }
        RetireOnExecutor();
        if (TaskFailed_.load(std::memory_order_acquire) && !FirstFailure_.Failed())
            RecordFailure({Prism::Fault::Code::Blocked});
        if (FirstFailure_.Failed()) co_return std::unexpected(FirstFailure_);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto NativeClientSessionOwner::IsRetired() const noexcept -> bool
    {
        return RetiredAtomic_.load(std::memory_order_acquire);
    }

    auto NativeClientSessionOwner::DrainProvider(
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

    auto NativeClientSessionOwner::CloseOnExecutor() -> void
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
        if (Options_.Connection)
        {
            Options_.Connection->Close();
        }
        ClosedAtomic_.store(true, std::memory_order_release);
    }

    auto NativeClientSessionOwner::RetireOnExecutor() noexcept -> void
    {
        if (Conn_)
        {
            nghttp3_conn_del(Conn_);
            Conn_ = nullptr;
        }
        Streams_.clear();
        PendingProviders_.clear();
        Http3Streams_.fill(nullptr);
        RequestStream_.reset();
        RequestHeaders_.reset();
        ResponseHeaders_.Clear();
        Options_.Random = {};
        Options_.Connection.reset();
        NativeEngineRetiredAtomic_.store(true, std::memory_order_release);
        RetiredAtomic_.store(true, std::memory_order_release);
    }
}
