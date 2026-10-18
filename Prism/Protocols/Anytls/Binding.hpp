/** @file Binding.hpp @brief AnyTLS 的冷密码 wire 配置与 ingress 服务绑定。 */
#pragma once
#include <Prism/Protocols/Anytls/IngressFactory.hpp>
#include <Prism/Contract/Services/Authentication.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <utility>

namespace Prism::Anytls
{
    [[nodiscard]] inline auto PrepareAccountCredential(std::string_view Value)
        ->Prism::Account::Credential
    {
        return Prism::Account::Credential::Password(Value);
    }

    struct PreparedBinding final
    {
        std::string Instance;
        IngressOptions Options;
    };

    /**
     * @brief AnyTLS 冷配置与候选投影的 provider owner。
     * @details 派生候选接管投影得到的值并按自身 generation 生命周期释放；本 owner 的回执
     *          只覆盖其冷配置材料和候选构造中的投影租约。
     */
    class Binding final
    {
        struct State final
        {
            explicit State(IngressOptions Value) : Options(std::move(Value)) {}
            std::atomic<std::uint64_t> ProjectionGate{0U};
            std::atomic<bool> DrainInProgress{false};
            std::atomic<bool> Retired{false};
            std::optional<IngressOptions> Options;
        };

    public:
        /** @brief 构造持有配置材料的唯一 AnyTLS provider owner。 */
        explicit Binding(IngressOptions Value)
            : State_(std::make_shared<State>(std::move(Value)))
        {
        }

        Binding(const Binding&) = delete;
        auto operator=(const Binding&) -> Binding& = delete;

        /** @brief 封止新的候选投影；已取得的投影租约仍可完成当前同步构造。 */
        auto Close() const noexcept -> void
        {
            State_->ProjectionGate.fetch_or(ClosedBit, std::memory_order_acq_rel);
        }

        /** @brief 保活一次同步候选构造，直至派生 ingress owner 已建立。 */
        class Projection final
        {
        public:
            Projection(const Projection&) = delete;
            auto operator=(const Projection&) -> Projection& = delete;
            Projection(Projection&& Other) noexcept : State_(std::move(Other.State_)) {}
            auto operator=(Projection&& Other) noexcept -> Projection&
            {
                if (this != &Other)
                {
                    Release();
                    State_ = std::move(Other.State_);
                }
                return *this;
            }
            ~Projection() { Release(); }

            [[nodiscard]] auto Options() const noexcept -> const IngressOptions&
            {
                return *State_->Options;
            }

        private:
            friend class Binding;
            explicit Projection(std::shared_ptr<State> Value) noexcept
                : State_(std::move(Value))
            {
            }
            auto Release() noexcept -> void
            {
                if (State_)
                {
                    State_->ProjectionGate.fetch_sub(1U, std::memory_order_release);
                    State_.reset();
                }
            }
            std::shared_ptr<State> State_;
        };

        /** @brief 封止后不再创建候选；租约存活期间 Drain 返回 Blocked 且保留配置。 */
        [[nodiscard]] auto BeginProjection() const noexcept -> std::optional<Projection>
        {
            auto Gate = State_->ProjectionGate.load(std::memory_order_acquire);
            while ((Gate & ClosedBit) == 0U)
            {
                if ((Gate & ProjectionMask) == ProjectionMask)
                {
                    return std::nullopt;
                }
                if (State_->ProjectionGate.compare_exchange_weak(
                        Gate, Gate + 1U, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return Projection(State_);
                }
            }
            return std::nullopt;
        }

        /** @brief 释放本 provider 的冷配置；并发投影未退出时保留材料并报告 Blocked。 */
        [[nodiscard]] auto Drain() const
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            Close();
            if (State_->Retired.load(std::memory_order_acquire))
            {
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            bool Expected = false;
            if (!State_->DrainInProgress.compare_exchange_strong(
                    Expected, true, std::memory_order_acq_rel, std::memory_order_acquire))
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
            }
            struct DrainRelease final
            {
                std::atomic<bool>& InProgress;
                ~DrainRelease() { InProgress.store(false, std::memory_order_release); }
            } Release{State_->DrainInProgress};
            if ((State_->ProjectionGate.load(std::memory_order_acquire) & ProjectionMask) != 0U)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            State_->Options.reset();
            State_->Retired.store(true, std::memory_order_release);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool
        {
            const auto Gate = State_->ProjectionGate.load(std::memory_order_acquire);
            return (Gate & ClosedBit) != 0U && (Gate & ProjectionMask) == 0U &&
                State_->Retired.load(std::memory_order_acquire);
        }

        /** @brief 返回独立持久失败回执；活动投影导致的 Blocked 仅属于本轮 attempt。 */
        [[nodiscard]] auto DrainFailure() const noexcept -> Prism::Fault::Failure
        {
            return {};
        }

    private:
        static constexpr std::uint64_t ClosedBit = std::uint64_t{1} << 63U;
        static constexpr std::uint64_t ProjectionMask = ClosedBit - 1U;
        std::shared_ptr<State> State_;
    };

    [[nodiscard]] inline auto PrepareProviderBinding(
        std::string Instance,
        Prism::Contract::AuthenticationServices Authentication,
        Prism::Contract::StreamServices Streams)
        -> std::expected<PreparedBinding, Prism::Contract::ProviderFailure>
    {
        if (!Authentication.Generation || !Authentication.Authenticator || !Authentication.Credentials)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::MissingAuthentication, {}, "Authentication"});
        }
        if (!Streams.Egress)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::MissingEgress, {}, "Streams.Egress"});
        }
        std::string Password;
        const auto Enumerated = Authentication.Credentials.ForEachCredential(
            Prism::Account::CredentialKind::Password,
            [&Password](const std::shared_ptr<const Prism::Account::AccountBinding>&,
                        const Prism::Account::CredentialMaterial& Material)
            {
                if (!Password.empty()) return;
                const auto Bytes = Material.Credential.View().Bytes();
                Password.assign(reinterpret_cast<const char*>(Bytes.data()), Bytes.size());
            });
        if (!Enumerated || Password.empty())
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::InvalidCredential, {}, "Authentication.Password"});
        }
        IngressOptions Options;
        Options.Configuration.Password = std::move(Password);
        Options.Authenticator = std::move(Authentication.Authenticator);
        Options.Streams = std::move(Streams);
        return PreparedBinding{std::move(Instance), std::move(Options)};
    }

    [[nodiscard]] inline auto BindProvider(PreparedBinding Prepared)
        -> std::shared_ptr<const Binding>
    {
        return std::make_shared<const Binding>(std::move(Prepared.Options));
    }
}
