/** @file TlsCarrierCatalogOwner.hpp @brief TCP TLS callbacks 的 generation owner 与真实退休回执。 */
#pragma once

#include <Prism/Composition/Recognition/CandidateRegistry.hpp>
#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>
#include <Prism/Contract/Ingress/CarrierCatalogOwner.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Runtime/Recognition/Candidate.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/system/error_code.hpp>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Composition::Provider
{
    namespace Net = boost::asio;
    namespace Recognition = Prism::Composition::Recognition;
    namespace Core = Prism::Recognition;
    using CarrierRegistration = Recognition::CandidateRegistry::CarrierRegistration;
    using CarrierResult = Core::CarrierAcceptResult;
    using CarrierFailure = Prism::Fault::Failure;
    using CallbackSignal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;

    /** @brief 一代 callback 注册表唯一拥有者；wrapper 只弱引用本 owner。 */
    class BoundTlsCarrierCatalog final
        : public Prism::Contract::CarrierCatalogOwner,
          public std::enable_shared_from_this<BoundTlsCarrierCatalog>
    {
    public:
        struct Entry final
        {
            Prism::Composition::Protocol::ProviderKey Key;
            std::string Id;
            CarrierRegistration Registration;
        };

        BoundTlsCarrierCatalog(const BoundTlsCarrierCatalog &) = delete;
        auto operator=(const BoundTlsCarrierCatalog &) -> BoundTlsCarrierCatalog & = delete;
        ~BoundTlsCarrierCatalog() override;

        /** @brief 把弱包装 callback 登记到尚未发布的 registry。 */
        [[nodiscard]] auto Register(Recognition::CandidateRegistry &Registry)
            -> std::expected<void, Prism::Contract::ProviderFailure>;

        /** @brief 封止本 catalog 的新 callback；已有协程继续持有活动计数。 */
        auto Close() noexcept -> void override;

        /** @brief 等待 callback frame 与 generation lease 退出，再清理闭包并发布退休回执。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, CarrierFailure>> override;

        /** @brief 只有 owner 已封 admission、无活动回调并清空 registrations 后为 true。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override;

    private:
        friend class FrozenTlsCarrierCatalog;

        struct Invocation final
        {
            std::shared_ptr<BoundTlsCarrierCatalog> Owner;
            Prism::Foundation::GenerationUseLease Lease;
            ~Invocation();
        };

        struct DrainGuard final
        {
            std::atomic_flag &Flag;
            ~DrainGuard();
        };

        explicit BoundTlsCarrierCatalog(
            std::vector<Entry> Values,
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState);

        [[nodiscard]] auto MakeRegistration(const std::size_t Index)
            -> CarrierRegistration;

        template<typename Input>
        [[nodiscard]] static auto InvokeOrRetire(
            std::weak_ptr<BoundTlsCarrierCatalog> Weak,
            const std::size_t Index,
            Input Request) -> Net::awaitable<CarrierResult>;

        template<typename Input>
        [[nodiscard]] auto Invoke(const std::size_t Index, Input Request)
            -> Net::awaitable<CarrierResult>;

        template<typename Input>
        [[nodiscard]] static auto RejectInput(Input Request, CarrierFailure Cause)
            -> Net::awaitable<CarrierResult>;

        [[nodiscard]] auto Enter() noexcept -> bool;

        auto Leave() noexcept -> void;

        [[nodiscard]] auto ActiveCount() const noexcept -> std::uint64_t;

        auto NotifyDrain() noexcept -> void;

        auto ClearWaiter(const std::shared_ptr<CallbackSignal> &Signal) noexcept -> void;

        [[nodiscard]] static auto ProviderFailure(
            const Prism::Contract::ProviderError Code,
            const std::string_view Id,
            const std::string_view Path) -> Prism::Contract::ProviderFailure;

        static constexpr std::uint64_t ClosedBit{std::uint64_t{1} << 63U};
        static constexpr std::uint64_t CountMask{ClosedBit - 1U};
        std::vector<Entry> Entries_;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState_;
        std::atomic<std::uint64_t> Gate_{0U};
        std::atomic<bool> Retired_{false};
        std::atomic_flag Draining_ = ATOMIC_FLAG_INIT;
        std::atomic<std::shared_ptr<CallbackSignal>> Waiter_{};
        bool Registered_{false};
    };
}
