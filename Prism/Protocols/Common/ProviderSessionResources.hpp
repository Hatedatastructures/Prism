/** @file ProviderSessionResources.hpp @brief 管理 provider ticket 拥有的 carriers 与协议 root。 */
#pragma once

#include <Prism/Protocols/Common/ProviderMuxRootState.hpp>
#include <Prism/Protocols/Common/ProviderSessionDrainAttempt.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Protocols
{
    namespace Asio = boost::asio;

    /**
     * @brief 一个 provider ticket 的固定容量 transport 与 root resource owner。
     * @details ticket 负责 admission 和重试；本 owner 负责 carrier close、activity drain、
     *          物理退休核验与释放，避免 ticket 同时维护两套资源生命周期。
     */
    class ProviderSessionResources final
    {
        using Root = std::shared_ptr<ProviderMuxRootState::RootOwner>;
        using DrainResult = Detail::ProviderSessionDrainResult;

    public:
        explicit ProviderSessionResources(Prism::SharedTransmission Inbound) noexcept
        {
            Tracked_[0].store(std::move(Inbound), std::memory_order_release);
            TrackedCount_.store(1U, std::memory_order_release);
        }

        [[nodiscard]] auto Track(const Prism::SharedTransmission& Transport)
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

        auto CloseRootOnly(const Root& RootValue) noexcept -> void
        {
            CloseRoot(RootValue);
        }

        /** @brief 同时请求 root 和已登记 transports 关闭，返回命令交付的首个真实错误。 */
        auto Close(const Root& RootValue) noexcept -> Prism::Fault::Failure
        {
            CloseRoot(RootValue);
            auto Failure = Prism::Fault::Failure{};
            const auto Count = TrackedCount_.load(std::memory_order_acquire);
            for (std::size_t Index = Count; Index > 0U; --Index)
            {
                PreserveFailure(Failure,
                    CloseTransport(Tracked_[Index - 1U].load(std::memory_order_acquire), false));
            }
            return Failure;
        }

        /** @brief 关闭晚于 owner close 登记的 carrier，必要时取消既有操作。 */
        auto CloseTransport(
            const Prism::SharedTransmission& Transport, bool CancelInFlight) noexcept
            -> Prism::Fault::Failure
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

        /** @brief 在原 executor 上排空 root、Connection/replay 和入站 carrier。 */
        [[nodiscard]] auto Drain(
            const Root& RootValue, const Asio::any_io_executor& Executor)
            -> Asio::awaitable<DrainResult>
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

        /** @brief 核验 root 与所有真实 transmission Activity 的物理退休回执。 */
        [[nodiscard]] auto IsRetired(const Root& RootValue) const noexcept -> bool
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

        auto Release() noexcept -> void
        {
            for (auto& Transport : Tracked_)
                Transport.store({}, std::memory_order_release);
            TrackedCount_.store(0U, std::memory_order_release);
        }

    private:
        static auto PreserveFailure(
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

        [[nodiscard]] static auto RootRetired(const Root& RootValue) noexcept -> bool
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

        static auto CloseRoot(const Root& RootValue) noexcept -> void
        {
            if (!RootValue) return;
            if (RootValue->Datagram) RootValue->Datagram->Close();
            if (RootValue->Mux) RootValue->Mux->Close();
        }

        [[nodiscard]] static auto DrainActivity(
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

        [[nodiscard]] static auto DrainRoot(const Root& RootValue)
            -> Asio::awaitable<DrainResult>
        {
            DrainResult Result;
            if (!RootValue) co_return Result;
            if (RootValue->Datagram)
            {
                const auto Drained = co_await DrainActivity(RootValue->Datagram->Activity());
                Result.Complete = Drained.Complete;
                Result.Error = Drained.Error;
            }
            if (RootValue->Mux)
            {
                const auto Drained = co_await DrainActivity(RootValue->Mux->Activity());
                Result.Complete = Result.Complete && Drained.Complete && RootValue->Mux->IsRetired();
                PreserveFailure(Result.Error, Drained.Error);
                if (!RootValue->Mux->IsRetired())
                {
                    PreserveFailure(Result.Error,
                        Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                }
            }
            co_return Result;
        }

        [[nodiscard]] static auto DrainTransport(
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

        std::array<std::atomic<Prism::SharedTransmission>, 4> Tracked_{};
        std::atomic<std::size_t> TrackedCount_{0U};
    };
}
