/** @file ProviderSessionResources.cpp @brief Provider ticket carrier 与 root drain 实现。 */

#include <Prism/Protocols/Common/Provider/Session/Resources.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <exception>
#include <memory>
#include <utility>

namespace Prism::Protocols
{
    ProviderSessionResources::ProviderSessionResources(
        Prism::SharedTransmission Inbound) noexcept
    {
        Tracked_[0].store(std::move(Inbound), std::memory_order_release);
        TrackedCount_.store(1U, std::memory_order_release);
    }

    [[nodiscard]] auto ProviderSessionResources::Track(
        const Prism::SharedTransmission& Transport)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Transport)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto Count = TrackedCount_.load(std::memory_order_acquire);
        for (std::size_t Index = 0; Index < Count; ++Index)
        {
            if (Tracked_[Index].load(std::memory_order_acquire) == Transport)
            {
                return {};
            }
        }
        if (Count >= Tracked_.size())
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        Tracked_[Count].store(Transport, std::memory_order_release);
        TrackedCount_.store(Count + 1U, std::memory_order_release);
        return {};
    }

    auto ProviderSessionResources::Close(const Root& RootValue) noexcept
        -> Prism::Fault::Failure
    {
        CloseRoot(RootValue);
        auto Failure = Prism::Fault::Failure{};
        const auto Count = TrackedCount_.load(std::memory_order_acquire);
        for (std::size_t Index = Count; Index > 0U; --Index)
        {
            const auto Transport = Tracked_[Index - 1U].load(std::memory_order_acquire);
            PreserveFailure(Failure, CloseTransport(Transport, false));
        }
        return Failure;
    }

    auto ProviderSessionResources::CloseTransport(
        const Prism::SharedTransmission& Transport,
        const bool CancelInFlight) noexcept -> Prism::Fault::Failure
    {
        if (!Transport) return {};
        const auto Activity = Transport->Activity();
        if (Activity && Activity->IsRetired()) return {};
        auto Failure = Prism::Fault::Failure{};
        if (CancelInFlight)
        {
            const auto Cancelled = Transport->Cancel();
            if (!Cancelled) PreserveFailure(Failure, Cancelled.error());
        }
        const auto Closed = Transport->Close();
        if (!Closed) PreserveFailure(Failure, Closed.error());
        return Failure;
    }

    [[nodiscard]] auto ProviderSessionResources::Drain(
        const Root& RootValue,
        const Asio::any_io_executor& Executor) -> Asio::awaitable<DrainResult>
    {
        co_await Asio::dispatch(Executor, Asio::use_awaitable);
        co_await Asio::this_coro::throw_if_cancelled(false);
        DrainResult Result;
        const auto RootResult = co_await DrainRoot(RootValue);
        Result.Complete = RootResult.Complete;
        Result.Error = RootResult.Error;
        const auto Count = TrackedCount_.load(std::memory_order_acquire);
        for (std::size_t Index = Count; Index > 0U; --Index)
        {
            const auto Transport = Tracked_[Index - 1U].load(std::memory_order_acquire);
            if (RootValue && Transport == RootValue->Transport) continue;
            const auto TransportResult = co_await DrainTransport(Transport);
            Result.Complete = Result.Complete && TransportResult.Complete;
            PreserveFailure(Result.Error, TransportResult.Error);
        }
        co_return Result;
    }

    [[nodiscard]] auto ProviderSessionResources::IsRetired(
        const Root& RootValue) const noexcept -> bool
    {
        if (RootValue && !RootRetired(RootValue)) return false;
        const auto Count = TrackedCount_.load(std::memory_order_acquire);
        for (std::size_t Index = 0; Index < Count; ++Index)
        {
            const auto Transport = Tracked_[Index].load(std::memory_order_acquire);
            if (!Transport || !Transport->Activity() || !Transport->Activity()->IsRetired())
                return false;
        }
        return true;
    }

    auto ProviderSessionResources::Release() noexcept -> void
    {
        for (auto& Transport : Tracked_)
            Transport.store({}, std::memory_order_release);
        TrackedCount_.store(0U, std::memory_order_release);
    }

    auto ProviderSessionResources::PreserveFailure(
        Prism::Fault::Failure& Primary,
        const Prism::Fault::Failure& Next) noexcept -> void
    {
        if (Next.Failed() && (!Primary.Failed() ||
            (Primary.Code == Prism::Fault::Code::Canceled &&
             Next.Code != Prism::Fault::Code::Canceled)))
        {
            Primary = Next;
        }
    }

    [[nodiscard]] auto ProviderSessionResources::RootRetired(
        const Root& RootValue) noexcept -> bool
    {
        if (RootValue->Datagram)
        {
            const auto Activity = RootValue->Datagram->Activity();
            return Activity && Activity->IsRetired();
        }
        if (RootValue->Mux)
        {
            const auto Activity = RootValue->Mux->Activity();
            return RootValue->Mux->IsRetired() && Activity && Activity->IsRetired();
        }
        return true;
    }

    auto ProviderSessionResources::CloseRoot(const Root& RootValue) noexcept -> void
    {
        if (!RootValue) return;
        if (RootValue->Datagram) RootValue->Datagram->Close();
        if (RootValue->Mux) RootValue->Mux->Close();
    }

    [[nodiscard]] auto ProviderSessionResources::DrainActivity(
        const std::shared_ptr<Prism::Contract::CarrierActivity>& Activity)
        -> Asio::awaitable<DrainResult>
    {
        DrainResult Result;
        if (!Activity)
        {
            Result.Complete = false;
            Result.Error = {Prism::Fault::Code::Blocked};
            co_return Result;
        }
        Activity->Seal();
        try
        {
            const auto Drained = co_await Activity->Drain();
            if (!Drained) Result.Error = Drained.error();
        }
        catch (...)
        {
            Result.Error = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        Result.Complete = Activity->IsRetired();
        if (Result.Complete && Result.Error.Code == Prism::Fault::Code::Canceled)
            Result.Error = {};
        co_return Result;
    }

    [[nodiscard]] auto ProviderSessionResources::DrainRoot(const Root& RootValue)
        -> Asio::awaitable<DrainResult>
    {
        DrainResult Result;
        if (!RootValue) co_return Result;
        /** @brief 在首次挂起前固定 session，避免 root 退休回调清空 owner 槽位。 */
        const auto Datagram = RootValue->Datagram;
        const auto Mux = RootValue->Mux;
        if (Datagram)
        {
            const auto Activity = Datagram->Activity();
            const auto Drained = co_await DrainActivity(Activity);
            Result.Complete = Drained.Complete;
            Result.Error = Drained.Error;
        }
        if (Mux)
        {
            const auto Activity = Mux->Activity();
            const auto Drained = co_await DrainActivity(Activity);
            Result.Complete = Result.Complete && Drained.Complete && Mux->IsRetired();
            PreserveFailure(Result.Error, Drained.Error);
            if (!Mux->IsRetired())
            {
                PreserveFailure(Result.Error,
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
        }
        co_return Result;
    }

    [[nodiscard]] auto ProviderSessionResources::DrainTransport(
        const Prism::SharedTransmission& Transport) -> Asio::awaitable<DrainResult>
    {
        DrainResult Result;
        if (!Transport)
        {
            Result.Complete = false;
            Result.Error = {Prism::Fault::Code::Blocked};
            co_return Result;
        }
        const auto Activity = Transport->Activity();
        if (!Activity)
        {
            Result.Complete = false;
            Result.Error = {Prism::Fault::Code::Blocked};
            co_return Result;
        }
        Activity->Seal();
        try
        {
            const auto Drained = co_await Activity->Drain();
            if (!Drained) Result.Error = Drained.error();
        }
        catch (...)
        {
            Result.Error = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        Result.Complete = Activity->IsRetired();
        if (Result.Complete && Result.Error.Code == Prism::Fault::Code::Canceled)
            Result.Error = {};
        co_return Result;
    }
} // namespace Prism::Protocols
