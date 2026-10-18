/** @file Binding.hpp @brief HTTP/1 typed factory 的 admission 与真实退休 owner。 */
#pragma once

#include <Prism/Protocols/Http1/IngressFactory.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Contract/Services/Authentication.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Http11
{
    /** @brief 密码凭据按值拥有 secure bytes；不借用配置文本，不执行 I/O 或关闭。 */
    [[nodiscard]] inline auto PrepareAccountCredential(std::string_view Value)
        -> Prism::Account::Credential
    {
        return Prism::Account::Credential::Password(Value);
    }

    struct PreparedBinding final
    {
        std::string Instance;
        Prism::SharedAuthenticator Authenticator;
        boost::asio::any_io_executor Executor;
        bool RequireAuth{true}; ///< 绑定拥有的认证准入策略，生产 Prepare 保持必需认证。
    };

    /** @brief 唯一 HTTP/1 stream factory 与 in-flight Accept 的物理关闭 owner。 */
    class Binding final : public Prism::Contract::StreamFactory
    {
        struct State final
        {
            explicit State(PreparedBinding Value)
                : Factory(std::make_shared<IngressFactory>(IngressOptions{
                      .RequireAuth = Value.RequireAuth, .Authenticator = std::move(Value.Authenticator)})),
                  Barrier(std::make_shared<Prism::Lifecycle::DrainBarrier>(
                      std::make_shared<Prism::Executor::ExecutorReclaimer>(
                          std::move(Value.Executor))))
            {
            }

            std::atomic<std::shared_ptr<IngressFactory>> Factory;
            std::shared_ptr<Prism::Lifecycle::DrainBarrier> Barrier;
            std::atomic<bool> Closed{false};
            std::atomic<bool> Retired{false};
            Prism::Fault::FailureState DrainFailure;
        };

        class AcceptActivity final
        {
        public:
            explicit AcceptActivity(std::shared_ptr<Prism::Lifecycle::DrainBarrier> Value)
                : Barrier_(std::move(Value))
            {
            }
            AcceptActivity(const AcceptActivity&) = delete;
            auto operator=(const AcceptActivity&) -> AcceptActivity& = delete;
            ~AcceptActivity() { if (Barrier_) Barrier_->Leave(); }

        private:
            std::shared_ptr<Prism::Lifecycle::DrainBarrier> Barrier_;
        };

    public:
        explicit Binding(PreparedBinding Value) : State_(std::make_shared<State>(std::move(Value))) {}
        ~Binding() override { Close(); }

        /** @brief 关闭期间拒绝新接入；已进入的握手在真实返回前保持活动预约。 */
        [[nodiscard]] auto Accept(Prism::Contract::StreamAcceptInput Input)
            -> boost::asio::awaitable<Prism::Contract::AcceptOutcome> override
        {
            const auto State = State_;
            if (!State->Closed.load(std::memory_order_acquire) && State->Barrier->Enter())
            {
                AcceptActivity Activity(State->Barrier);
                const auto Factory = State->Factory.load(std::memory_order_acquire);
                if (Factory)
                {
                    co_return co_await Factory->Accept(std::move(Input));
                }
            }
            co_return co_await RejectClosed(std::move(Input));
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "http"; }

        /** @brief 封止新 Accept；活动请求和认证材料由 Drain 真实收束。 */
        auto Close() noexcept -> void
        {
            State_->Barrier->Seal();
            State_->Closed.store(true, std::memory_order_release);
        }

        /** @brief 已封止且唯一工厂已清空、所有 Accept 已退栈时返回 true。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool
        {
            return State_->Retired.load(std::memory_order_acquire) &&
                State_->Barrier->Active() == 0U &&
                !State_->Factory.load(std::memory_order_acquire);
        }

        /** @brief 等待 in-flight Accept 退栈；失败保留同一 state，允许同 owner 重试。 */
        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_return co_await DrainState(State_);
        }

    private:
        [[nodiscard]] static auto RejectClosed(Prism::Contract::StreamAcceptInput Input)
            -> boost::asio::awaitable<Prism::Contract::AcceptOutcome>
        {
            if (!Input.Inbound)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(
                std::move(Input.Inbound));
            if (!Prepared)
            {
                co_return std::unexpected(Prepared.error());
            }
            co_return co_await Prepared->Reject(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }

        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Value)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            Value->Barrier->Seal();
            Value->Closed.store(true, std::memory_order_release);
            const auto Result = co_await Value->Barrier->Drain();
            if (!Result)
            {
                (void)Value->DrainFailure.TrySet(Result.error());
            }
            if (Value->Barrier->Active() == 0U)
            {
                Value->Factory.store({}, std::memory_order_release);
                Value->Retired.store(true, std::memory_order_release);
            }
            const auto FirstFailure = Value->DrainFailure.Load();
            if (FirstFailure.Failed())
            {
                co_return std::unexpected(FirstFailure);
            }
            if (!Result)
            {
                co_return std::unexpected(Result.error());
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        std::shared_ptr<State> State_;
    };

    /** @brief 冷 prepare 已校验同代 authenticator 和 executor 后发布唯一绑定。 */
    [[nodiscard]] inline auto PrepareProviderBinding(
        std::string Instance,
        Prism::Contract::AuthenticationServices Authentication,
        boost::asio::any_io_executor Executor)
        -> std::expected<PreparedBinding, Prism::Contract::ProviderFailure>
    {
        if (!Authentication.Generation || !Authentication.Authenticator ||
            !Authentication.Credentials)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::MissingAuthentication, {}, "Authentication"});
        }
        if (!Executor)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::InvalidConfiguration, Instance, "Executor"});
        }
        if (!Authentication.Matches(Authentication.Generation))
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::GenerationMismatch, {}, "Authentication.Generation"});
        }
        return PreparedBinding{
            std::move(Instance), std::move(Authentication.Authenticator), std::move(Executor)};
    }

    [[nodiscard]] inline auto BindProvider(PreparedBinding Prepared)
        -> std::shared_ptr<Binding>
    {
        return std::make_shared<Binding>(std::move(Prepared));
    }
}
