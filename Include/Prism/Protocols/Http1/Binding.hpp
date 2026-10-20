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

namespace Prism::Http11
{
    /** @brief 密码凭据按值拥有 secure bytes；不借用配置文本，不执行 I/O 或关闭。 */
    [[nodiscard]] auto PrepareAccountCredential(std::string_view Value)
        -> Prism::Account::Credential;

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
            explicit State(PreparedBinding Value);

            std::atomic<std::shared_ptr<IngressFactory>> Factory;
            std::shared_ptr<Prism::Lifecycle::DrainBarrier> Barrier;
            std::atomic<bool> Closed{false};
            std::atomic<bool> Retired{false};
            Prism::Fault::FailureState DrainFailure;
        };

        class AcceptActivity final
        {
        public:
            explicit AcceptActivity(std::shared_ptr<Prism::Lifecycle::DrainBarrier> Value);
            AcceptActivity(const AcceptActivity&) = delete;
            auto operator=(const AcceptActivity&) -> AcceptActivity& = delete;
            ~AcceptActivity();

        private:
            std::shared_ptr<Prism::Lifecycle::DrainBarrier> Barrier_;
        };

    public:
        explicit Binding(PreparedBinding Value);
        ~Binding() override;

        /** @brief 关闭期间拒绝新接入；已进入的握手在真实返回前保持活动预约。 */
        [[nodiscard]] auto Accept(Prism::Contract::StreamAcceptInput Input)
            -> boost::asio::awaitable<Prism::Contract::AcceptOutcome> override;

        [[nodiscard]] auto Name() const -> std::string_view override { return "http"; }

        /** @brief 封止新 Accept；活动请求和认证材料由 Drain 真实收束。 */
        auto Close() noexcept -> void;

        /** @brief 已封止且唯一工厂已清空、所有 Accept 已退栈时返回 true。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

        /** @brief 等待 in-flight Accept 退栈；失败保留同一 state，允许同 owner 重试。 */
        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

    private:
        [[nodiscard]] static auto RejectClosed(Prism::Contract::StreamAcceptInput Input)
            -> boost::asio::awaitable<Prism::Contract::AcceptOutcome>;

        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Value)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

        std::shared_ptr<State> State_;
    };

    /** @brief 冷 prepare 已校验同代 authenticator 和 executor 后发布唯一绑定。 */
    [[nodiscard]] auto PrepareProviderBinding(
        std::string Instance,
        Prism::Contract::AuthenticationServices Authentication,
        boost::asio::any_io_executor Executor)
        -> std::expected<PreparedBinding, Prism::Contract::ProviderFailure>;

    [[nodiscard]] auto BindProvider(PreparedBinding Prepared) -> std::shared_ptr<Binding>;
}
