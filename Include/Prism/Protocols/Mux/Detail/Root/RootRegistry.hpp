/** @file RootRegistry.hpp @brief 以预创建节点强持有未退休 mux root。 */
#pragma once
#include <Prism/Protocols/Mux/Detail/Root/RootSession.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <boost/system/system_error.hpp>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>

namespace Prism::Mux::Detail
{
    class RootRegistry final
    {
        static constexpr std::uint64_t ClosedMask = std::uint64_t{1} << 63U;
        static constexpr std::uint64_t RegistrationMask = ~ClosedMask;

    public:
        /** @brief 保持冷创建登记未完成，直到 RootBinding 已转交完整 Plane。 */
        class Registration final
        {
        public:
            explicit Registration(std::atomic_uint64_t &Value) noexcept;
            Registration(const Registration &) = delete;
            auto operator=(const Registration &) -> Registration & = delete;
            Registration(Registration &&Other) noexcept;
            auto operator=(Registration &&) -> Registration & = delete;
            ~Registration();
            explicit operator bool() const noexcept;

        private:
            std::atomic_uint64_t &Gate;
            bool Active{false};
        };

    private:
        struct State final : RootRetirementOwner
        {
            auto Retire(Prism::Fault::Failure Failure) noexcept -> void override;

            auto CollectRetired() noexcept -> void;

            std::atomic_uint64_t RegistrationGate{0};
            std::atomic<std::shared_ptr<RootRegistryNode>> Head;
            Prism::Fault::FailureState HistoricalFailure;
        };

        struct PendingRootOwner final
        {
            explicit PendingRootOwner(std::shared_ptr<RootRegistryNode> Value) noexcept;
            ~PendingRootOwner();
            std::shared_ptr<RootRegistryNode> Node;
            bool Published{false};
        };

        [[nodiscard]] static auto FailureFromException(std::exception_ptr Failure) noexcept
            -> Prism::Fault::Failure;

    public:
        RootRegistry();

        /** @brief 在构造 root 前取得登记门票据，封止 Drain 的提前完成。 */
        [[nodiscard]] auto BeginRegistration()
            -> std::optional<Registration>;

        /** @brief 把冷创建时预留的 owner 节点转交给 registry；调用方须持有登记门票据。 */
        [[nodiscard]] auto Register(const std::shared_ptr<RootSession> &Root)
            -> bool;

        /** @brief 封止新注册并向当前目录中的每个 root 发出取消。 */
        auto Close() noexcept -> void;

        [[nodiscard]] auto IsClosed() const noexcept -> bool;

        /** @brief 只在封止、无登记中请求且目录确实为空时报告物理退休。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

        /** @brief 返回 root owner 已发布的持久终态首因，不包含可重试的本轮取消。 */
        [[nodiscard]] auto DrainFailure() const noexcept -> Prism::Fault::Failure;

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    private:
        std::shared_ptr<State> State_;
    };
}
