/** @file RuntimeGenerationSnapshot.cpp @brief 代次服务冻结与真实退休实现。 */

#include <Prism/Application/RuntimeGenerationSnapshot.hpp>

#include <atomic>
#include <expected>
#include <utility>

namespace Prism::Application
{
    auto RuntimeGenerationServices::DrainOwnedServices() const
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        auto Status = DrainStatus_.load(std::memory_order_acquire);
        while (Status != DrainStatus::Drained)
        {
            if (Status == DrainStatus::Draining)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
            }
            if (DrainStatus_.compare_exchange_weak(
                    Status, DrainStatus::Draining,
                    std::memory_order_acq_rel, std::memory_order_acquire))
            {
                break;
            }
        }
        if (Status == DrainStatus::Drained)
        {
            if (const auto Failure = FirstDrainFailure())
            {
                co_return std::unexpected(*Failure);
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        if (!UseState)
        {
            DrainStatus_.store(DrainStatus::Ready, std::memory_order_release);
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }

        co_await DrainProviderOwner();
        if (!UseState->CloseAdmissionIfUnused())
        {
            DrainStatus_.store(DrainStatus::Ready, std::memory_order_release);
            co_return std::unexpected(
                FirstDrainFailure().value_or(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked}));
        }
        co_await DrainResolverOwner();
        co_await DrainWorkerDialOwners();
        if (!PhysicalRetirementComplete())
        {
            DrainStatus_.store(DrainStatus::Failed, std::memory_order_release);
            co_return std::unexpected(FirstDrainFailure().value_or(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked}));
        }
        DrainStatus_.store(DrainStatus::Drained, std::memory_order_release);
        if (const auto Failure = FirstDrainFailure())
        {
            co_return std::unexpected(*Failure);
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto RuntimeGenerationServices::PhysicalRetirementComplete() const noexcept -> bool
    {
        if (!UseState || UseState->AdmissionOpen() || UseState->Outstanding() != 0U ||
            !ProvidersRetired_.load(std::memory_order_acquire))
        {
            return false;
        }
        if (OwnResolver && !ResolverRetired_.load(std::memory_order_acquire))
        {
            return false;
        }
        if (OwnWorkerDials && !WorkerDialsRetired_.load(std::memory_order_acquire))
        {
            return false;
        }
        return true;
    }

    auto RuntimeGenerationServices::PreserveFirstFailure(
        const Prism::Fault::Failure Cause) const -> void
    {
        if (FirstFailure_ && Cause.Failed())
        {
            (void)FirstFailure_->TrySet(Cause);
        }
    }

    auto RuntimeGenerationServices::DrainProviderOwner() const
        -> boost::asio::awaitable<void>
    {
        if (!Providers)
        {
            PreserveFirstFailure(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            co_return;
        }
        Providers->Close();
        const auto Result = co_await Providers->Drain();
        const auto Receipt = Providers->PhysicalRetirement();
        const auto Retired = Receipt.Complete();
        const auto Durable = Providers->DrainFailure();
        const bool RetryableAttemptFailure = !Result && !Durable &&
            (Result.error().Code == Prism::Fault::Code::Canceled ||
             Result.error().Code == Prism::Fault::Code::Blocked);
        if (Durable)
        {
            PreserveFirstFailure(*Durable);
        }
        else if (!Result && !RetryableAttemptFailure)
        {
            PreserveFirstFailure(Result.error());
        }
        ProvidersRetired_.store(Retired, std::memory_order_release);
        co_return;
    }

    auto RuntimeGenerationServices::DrainResolverOwner() const
        -> boost::asio::awaitable<void>
    {
        if (!OwnResolver)
        {
            co_return;
        }
        if (!Resolver)
        {
            PreserveFirstFailure(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            co_return;
        }
        const auto Result = co_await Resolver->Shutdown();
        ResolverRetired_.store(Result.has_value(), std::memory_order_release);
        if (!Result)
        {
            PreserveFirstFailure(Result.error());
        }
        co_return;
    }

    auto RuntimeGenerationServices::DrainWorkerDialOwners() const
        -> boost::asio::awaitable<void>
    {
        if (!OwnWorkerDials)
        {
            co_return;
        }
        bool Retired = !WorkerDials.empty();
        for (const auto &Dial : WorkerDials)
        {
            if (!Dial)
            {
                Retired = false;
                PreserveFirstFailure(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                continue;
            }
            const auto Result = co_await Dial->Shutdown();
            if (!Result)
            {
                Retired = false;
                PreserveFirstFailure(Result.error());
            }
        }
        WorkerDialsRetired_.store(Retired, std::memory_order_release);
        co_return;
    }

    auto PreparedRuntimeGenerationServices::Freeze() &&
        -> std::expected<RuntimeGenerationServices, Prism::Fault::Failure>
    {
        if (Frozen_)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        if (!Graph_.Session || !Graph_.Providers || !Graph_.Resolver ||
            !Graph_.UseState || !Graph_.DatagramSelection ||
            !Graph_.DatagramSelection->Matches(Graph_.Session->Generation, Graph_.UseState) ||
            Graph_.WorkerDials.empty() ||
            Graph_.WorkerSessions.size() != Graph_.WorkerDials.size() ||
            Graph_.Session->GenerationUseState != Graph_.UseState)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::Blocked});
        }
        for (const auto &Dial : Graph_.WorkerDials)
        {
            if (!Dial)
            {
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::Blocked});
            }
        }
        for (const auto &WorkerSession : Graph_.WorkerSessions)
        {
            if (WorkerSession.GenerationUseState != Graph_.UseState)
            {
                return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::Blocked});
            }
        }
        Frozen_ = true;
        return std::move(Graph_);
    }
} // namespace Prism::Application
