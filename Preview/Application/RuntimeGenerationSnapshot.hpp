/**
 * @file RuntimeGenerationSnapshot.hpp
 * @brief Preview 一代完整运行时绑定及其服务图 owner。
 */
#pragma once

#include <Preview/Application/Account/Catalog.hpp>
#include <Preview/Application/Configuration/ConfigurationGeneration.hpp>
#include <Preview/Composition/Provider/ProviderCatalog.hpp>
#include <Preview/Contract/Ingress/DatagramIngressSelection.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Net/Dns/Resolver.hpp>
#include <Preview/Net/Services/WorkerDialService.hpp>
#include <Preview/Runtime/SessionServices.hpp>

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace Preview::Application
{

    /** @brief 持有一代完整运行服务图，并负责该图的最终 Drain。 */
    class RuntimeGenerationServices final
    {
    public:
        RuntimeGenerationServices() = default;

        RuntimeGenerationServices(const RuntimeGenerationServices &) = delete;
        auto operator=(const RuntimeGenerationServices &) -> RuntimeGenerationServices & = delete;

        RuntimeGenerationServices(RuntimeGenerationServices &&Other) noexcept
            : Session(std::move(Other.Session)),
              Providers(std::move(Other.Providers)),
              Resolver(std::move(Other.Resolver)),
              WorkerDials(std::move(Other.WorkerDials)),
              WorkerSessions(std::move(Other.WorkerSessions)),
              UseState(std::move(Other.UseState)),
              DatagramSelection(std::move(Other.DatagramSelection)),
              OwnResolver(Other.OwnResolver),
              OwnWorkerDials(Other.OwnWorkerDials),
              FirstFailure_(std::move(Other.FirstFailure_)),
              ProvidersRetired_(Other.ProvidersRetired_.load(std::memory_order_acquire)),
              ResolverRetired_(Other.ResolverRetired_.load(std::memory_order_acquire)),
              WorkerDialsRetired_(Other.WorkerDialsRetired_.load(std::memory_order_acquire)),
              DrainStatus_(Other.DrainStatus_.load(std::memory_order_acquire))
        {
        }

        auto operator=(RuntimeGenerationServices &&) -> RuntimeGenerationServices & = delete;

        [[nodiscard]] auto OutstandingUses() const noexcept -> std::uint64_t
        {
            if (!UseState)
            {
                return 0U;
            }
            return UseState->Outstanding();
        }

        /** @brief 排空代次服务并保留首因；返回值与物理退休回执分离。 */
        [[nodiscard]] auto DrainOwnedServices() const
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            auto Status = DrainStatus_.load(std::memory_order_acquire);
            while (Status != DrainStatus::Drained)
            {
                if (Status == DrainStatus::Draining)
                {
                    co_return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::WouldBlock});
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
                if (FirstFailure_)
                {
                    co_return std::unexpected(*FirstFailure_);
                }
                co_return std::expected<void, Preview::Fault::Failure>{};
            }
            if (!UseState || !UseState->CloseAdmissionIfUnused())
            {
                DrainStatus_.store(DrainStatus::Ready, std::memory_order_release);
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }

            co_await DrainProviderOwner();
            co_await DrainResolverOwner();
            co_await DrainWorkerDialOwners();
            if (OutstandingUses() != 0U)
            {
                PreserveFirstFailure(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            if (!PhysicalRetirementComplete())
            {
                DrainStatus_.store(DrainStatus::Failed, std::memory_order_release);
                co_return std::unexpected(FirstFailure_.value_or(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked}));
            }
            DrainStatus_.store(DrainStatus::Drained, std::memory_order_release);
            if (FirstFailure_)
            {
                co_return std::unexpected(*FirstFailure_);
            }
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        /** @brief provider/DNS/worker typed owners全部实际退栈且代次租约归零才返回true。 */
        [[nodiscard]] auto PhysicalRetirementComplete() const noexcept -> bool
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

        /** @brief 读取该代 Drain 首个历史失败；后续重试不覆盖原 cause。 */
        [[nodiscard]] auto FirstDrainFailure() const -> std::optional<Preview::Fault::Failure>
        {
            return FirstFailure_;
        }
        Preview::Runtime::SharedSessionServices Session;
        std::shared_ptr<Preview::Composition::Provider::BoundCatalog> Providers;
        std::shared_ptr<Preview::Network::Dns::Resolver> Resolver;
        std::vector<std::shared_ptr<Preview::Network::Services::WorkerDialService>> WorkerDials;
        std::vector<Preview::Runtime::SessionServices> WorkerSessions;
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState;
        std::shared_ptr<const Preview::Contract::DatagramIngressSelection> DatagramSelection;
        bool OwnResolver{false};
        bool OwnWorkerDials{false};

    private:
        auto PreserveFirstFailure(const Preview::Fault::Failure Cause) const -> void
        {
            if (!FirstFailure_)
            {
                FirstFailure_ = Cause;
            }
        }

        auto DrainProviderOwner() const
            -> boost::asio::awaitable<void>
        {
            if (!Providers)
            {
                PreserveFirstFailure(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                co_return;
            }
            Providers->Close();
            const auto Result = co_await Providers->Drain();
            if (!Result)
            {
                PreserveFirstFailure(Result.error());
            }
            const auto Receipt = Providers->PhysicalRetirement();
            const auto Retired = Receipt.Complete();
            ProvidersRetired_.store(Retired, std::memory_order_release);
            if (!Retired)
            {
                PreserveFirstFailure(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            co_return;
        }

        auto DrainResolverOwner() const
            -> boost::asio::awaitable<void>
        {
            if (!OwnResolver)
            {
                co_return;
            }
            if (!Resolver)
            {
                PreserveFirstFailure(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
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

        auto DrainWorkerDialOwners() const
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
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
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

        enum class DrainStatus : std::uint8_t
        {
            Ready,
            Draining,
            Failed,
            Drained,
        };

        mutable std::optional<Preview::Fault::Failure> FirstFailure_;
        mutable std::atomic<bool> ProvidersRetired_{false};
        mutable std::atomic<bool> ResolverRetired_{false};
        mutable std::atomic<bool> WorkerDialsRetired_{false};
        mutable std::atomic<DrainStatus> DrainStatus_{DrainStatus::Ready};
    };

    /** @brief 冷路径准备 owner；仅 Freeze 可将完整服务图一次转移给 snapshot。 */
    class PreparedRuntimeGenerationServices final
    {
    public:
        PreparedRuntimeGenerationServices() = default;
        PreparedRuntimeGenerationServices(const PreparedRuntimeGenerationServices &) = delete;
        auto operator=(const PreparedRuntimeGenerationServices &)
            -> PreparedRuntimeGenerationServices & = delete;
        PreparedRuntimeGenerationServices(PreparedRuntimeGenerationServices &&) noexcept = default;
        auto operator=(PreparedRuntimeGenerationServices &&) noexcept
            -> PreparedRuntimeGenerationServices & = default;

        [[nodiscard]] auto Graph() noexcept -> RuntimeGenerationServices &
        {
            return Graph_;
        }

        [[nodiscard]] auto DrainOwnedServices() const
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_return co_await Graph_.DrainOwnedServices();
        }

        [[nodiscard]] auto PhysicalRetirementComplete() const noexcept -> bool
        {
            return Graph_.PhysicalRetirementComplete();
        }

        [[nodiscard]] auto Freeze() &&
            -> std::expected<RuntimeGenerationServices, Preview::Fault::Failure>
        {
            if (Frozen_)
            {
                return std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::InvalidArgument});
            }
            if (!Graph_.Session || !Graph_.Providers || !Graph_.Resolver ||
                !Graph_.UseState || !Graph_.DatagramSelection ||
                !Graph_.DatagramSelection->Matches(Graph_.Session->Generation, Graph_.UseState) ||
                Graph_.WorkerDials.empty() ||
                Graph_.WorkerSessions.size() != Graph_.WorkerDials.size() ||
                Graph_.Session->GenerationUseState != Graph_.UseState)
            {
                return std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::Blocked});
            }
            for (const auto &Dial : Graph_.WorkerDials)
            {
                if (!Dial)
                {
                    return std::unexpected(Preview::Fault::Failure{
                        Preview::Fault::Code::Blocked});
                }
            }
            for (const auto &WorkerSession : Graph_.WorkerSessions)
            {
                if (WorkerSession.GenerationUseState != Graph_.UseState)
                {
                    return std::unexpected(Preview::Fault::Failure{
                        Preview::Fault::Code::Blocked});
                }
            }
            Frozen_ = true;
            return std::move(Graph_);
        }

    private:
        RuntimeGenerationServices Graph_;
        bool Frozen_{false};
    };

    /** @brief GenerationPublication 原子发布的配置、账户及冻结服务图。 */
    class RuntimeGenerationSnapshot final : public Preview::Foundation::GenerationLifetime
    {
    public:
        RuntimeGenerationSnapshot(
            Configuration::SharedConfigurationGeneration ConfigurationValue,
            AccountCatalog AccountsValue,
            RuntimeGenerationServices ServicesValue)
            : Generation(std::move(ConfigurationValue)),
              Accounts(std::move(AccountsValue)),
              Services(std::move(ServicesValue))
        {
        }

        [[nodiscard]] auto Id() const noexcept -> Preview::GenerationId override
        {
            if (!Generation)
            {
                return {};
            }
            return Generation->Id();
        }

        [[nodiscard]] auto OutstandingUses() const noexcept -> std::uint64_t
        {
            return Services.OutstandingUses();
        }

        [[nodiscard]] auto CanRetire() const noexcept -> bool
        {
            if (!Services.UseState)
            {
                return false;
            }
            return OutstandingUses() == 0U;
        }

        /** @brief 排空快照拥有的服务图；失败保留图以便 owner 重试。 */
        [[nodiscard]] auto DrainOwnedServices() const
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_return co_await Services.DrainOwnedServices();
        }

        [[nodiscard]] auto PhysicalRetirementComplete() const noexcept -> bool
        {
            return Services.PhysicalRetirementComplete();
        }

        [[nodiscard]] auto FirstDrainFailure() const -> std::optional<Preview::Fault::Failure>
        {
            return Services.FirstDrainFailure();
        }

        const Configuration::SharedConfigurationGeneration Generation;
        const AccountCatalog Accounts;
        const RuntimeGenerationServices Services;
    };

    using SharedRuntimeGenerationSnapshot = std::shared_ptr<const RuntimeGenerationSnapshot>;

} // namespace Preview::Application
