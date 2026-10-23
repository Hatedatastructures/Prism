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
            friend class RootRegistry;
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
            /** @brief 本轮 Drain 已观察到的显式取消；与不可重试的持久失败分开保存。 */
            Prism::Fault::FailureState AttemptCancellation;
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

        /** @brief 仅在本 registry 的有效登记门票据保护下发布预留 owner 节点。 */
        [[nodiscard]] auto Register(
            const Registration &Ticket,
            const std::shared_ptr<RootSession> &Root)
            -> bool;

        /** @brief 封止新注册；取消活动 root，并正常关闭尚未运行的 root。 */
        auto Close() noexcept -> void;
        /** @brief 封止新注册并对全部活动 root 发出正常关闭请求。 */
        auto CloseForDrain() noexcept -> void;

        [[nodiscard]] auto IsClosed() const noexcept -> bool;

        /** @brief 只在封止、无登记中请求且目录确实为空时报告物理退休。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

        /** @brief 返回 root owner 已发布的持久终态首因，不包含可重试的本轮取消。 */
        [[nodiscard]] auto DrainFailure() const noexcept -> Prism::Fault::Failure;

        /** @brief 显式 Close 后按真实物理退休完成，同时返回本轮 Canceled 历史结果。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    private:
        std::shared_ptr<State> State_;
    };
}
