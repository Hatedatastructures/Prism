/**
 * @file Auth.hpp
 * @brief 认证中间件（T4-1）
 * @details 基于 Authenticator 接口校验凭据，通过后写入 ctx.Identity()：
 *          - 凭据提取函数协议无关（HTTP Basic / socks5 / trojan 等按需注入）
 *          - 认证失败或缺失凭据 → auth_failed（管线终止）
 *          - 成功后 identity 供统计/审计按账户聚合
 * @note 对应生产 AuthenticationCheck；生产目录认证（Directory）接入见 T5-1
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <Prism/Account/Credential.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Runtime/Middleware/Pipeline.hpp>

namespace Prism::Experiments
{

    namespace Net = boost::asio;
    using Prism::Middleware::Context;
    using Prism::Middleware::Middleware;

    /**
     * @class AuthenticationCheck
     * @brief 认证中间件
     * @details 从 ctx 提取凭据（identity, Secret），经 Authenticator
     *          校验；通过则写入 ctx.Identity()，失败/缺失返回 auth_failed。
     */
    class AuthenticationCheck final : public Middleware
    {
    public:
        /** @brief 一次认证输入；Credential 拥有 secret，Context 不保存原始凭据。 */
        struct CredentialInput
        {
            std::string Identity;
            std::shared_ptr<const Prism::Account::Credential> Credential;
        };

        /// 凭据提取签名：提取一次性拥有的 typed 凭据；nullopt = 缺失凭据
        using CredentialFn = std::function<std::optional<CredentialInput>(const Context &)>;

        /**
         * @brief 构造
         * @param Auth 认证器（可空，运行时校验）
         * @param cred 凭据提取函数（可空，默认读 ctx 内预设字段）
         */
        explicit AuthenticationCheck(Prism::SharedAuthenticator Auth,
                                 CredentialFn Cred = {})
            : Auth_(std::move(Auth)), Cred_(std::move(Cred))
        {
        }

        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "Auth";
        }

        /**
         * @brief 执行认证
         * @param Inbound 入站传输（不修改）
         * @param ctx 上下文（成功后写入 identity）
         * @return 认证成功返回空 Failure；拒绝时保留 AuthFailed 或 NotSupported 领域码。
         */
        auto Handle(Prism::SharedTransmission & /*Inbound*/, Context &ctx)
            -> Net::awaitable<Prism::Fault::Failure> override
        {
            if (!Auth_)
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::NotSupported};
            }
            // Context 可能被复用；重新认证前先释放上一次租约，避免失败路径泄漏配额。
            ctx.AccountLease().Release();
            ctx.Identity().clear();
            ctx.AccountId() = {};
            auto Input = Cred_ ? Cred_(ctx) : std::nullopt;
            if (!Input || !Input->Credential || !Input->Credential->IsValid())
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::AuthFailed};
            }
            auto Result = Auth_->Authenticate(Prism::AuthenticationRequest{
                .AccountId = ctx.AccountId(),
                .Identity = Input->Identity,
                .Credential = Input->Credential->View(),
                .Rate = {}});
            if (!Result)
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::AuthFailed};
            }
            auto Lease = std::move(*Result);
            ctx.Identity() = std::string(Lease.Identity());
            ctx.DisplayIdentity() = std::string(Lease.DisplayIdentity());
            ctx.AccountId() = Lease.AccountId();
            ctx.AccountLease() = std::move(Lease);
            co_return Prism::Fault::Failure{};
        }

    private:
        Prism::SharedAuthenticator Auth_; ///< 认证器
        CredentialFn Cred_;                 ///< 凭据提取
    };

} // namespace Prism::Experiments
