/**
 * @file RuntimeGenerationSnapshot.hpp
 * @brief Prism 一代完整运行时绑定及其服务图 owner。
 */
#pragma once

#include <Prism/Application/AccountCatalog.hpp>
#include <Prism/Application/Configuration/ConfigurationGeneration.hpp>
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <Prism/Contract/Ingress/DatagramIngressSelection.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Net/Services/WorkerDialService.hpp>
#include <Prism/Runtime/SessionServices.hpp>

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace Prism::Application
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
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief provider/DNS/worker typed owners全部实际退栈且代次租约归零才返回true。 */
        [[nodiscard]] auto PhysicalRetirementComplete() const noexcept -> bool;

        /** @brief 读取该代 Drain 首个历史失败；后续重试不覆盖原 cause。 */
        [[nodiscard]] auto FirstDrainFailure() const -> std::optional<Prism::Fault::Failure>
        {
            if (!FirstFailure_)
            {
                return {};
            }
            const auto Failure = FirstFailure_->Load();
            if (Failure.Failed())
            {
                return Failure;
            }
            return {};
        }
        Prism::Runtime::SharedSessionServices Session;
        std::shared_ptr<Prism::Composition::Provider::BoundCatalog> Providers;
        std::shared_ptr<Prism::Network::Dns::Resolver> Resolver;
        std::vector<std::shared_ptr<Prism::Network::Services::WorkerDialService>> WorkerDials;
        std::vector<Prism::Runtime::SessionServices> WorkerSessions;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        std::shared_ptr<const Prism::Contract::DatagramIngressSelection> DatagramSelection;
        bool OwnResolver{false};
        bool OwnWorkerDials{false};

    private:
        auto PreserveFirstFailure(const Prism::Fault::Failure Cause) const -> void;

        auto DrainProviderOwner() const
            -> boost::asio::awaitable<void>;

        auto DrainResolverOwner() const
            -> boost::asio::awaitable<void>;

        auto DrainWorkerDialOwners() const
            -> boost::asio::awaitable<void>;

        enum class DrainStatus : std::uint8_t
        {
            Ready,
            Draining,
            Failed,
            Drained,
        };

        std::shared_ptr<Prism::Fault::FailureState> FirstFailure_{
            std::make_shared<Prism::Fault::FailureState>()};
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
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_return co_await Graph_.DrainOwnedServices();
        }

        [[nodiscard]] auto PhysicalRetirementComplete() const noexcept -> bool
        {
            return Graph_.PhysicalRetirementComplete();
        }

        [[nodiscard]] auto Freeze() &&
            -> std::expected<RuntimeGenerationServices, Prism::Fault::Failure>;

    private:
        RuntimeGenerationServices Graph_;
        bool Frozen_{false};
    };

    /** @brief GenerationPublication 原子发布的配置、账户及冻结服务图。 */
    class RuntimeGenerationSnapshot final : public Prism::Foundation::GenerationLifetime
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

        [[nodiscard]] auto Id() const noexcept -> Prism::GenerationId override
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
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_return co_await Services.DrainOwnedServices();
        }

        [[nodiscard]] auto PhysicalRetirementComplete() const noexcept -> bool
        {
            return Services.PhysicalRetirementComplete();
        }

        [[nodiscard]] auto FirstDrainFailure() const -> std::optional<Prism::Fault::Failure>
        {
            return Services.FirstDrainFailure();
        }

        const Configuration::SharedConfigurationGeneration Generation;
        const AccountCatalog Accounts;
        const RuntimeGenerationServices Services;
    };

    using SharedRuntimeGenerationSnapshot = std::shared_ptr<const RuntimeGenerationSnapshot>;

} // namespace Prism::Application
