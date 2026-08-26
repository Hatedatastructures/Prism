/**
 * @file Auth.hpp
 * @brief 认证中间件（T4-1）
 * @details 基于 Authenticator 接口校验凭据，通过后写入 ctx.identity：
 *          - 凭据提取函数协议无关（HTTP Basic / socks5 / trojan 等按需注入）
 *          - 认证失败或缺失凭据 → auth_failed（管线终止）
 *          - 成功后 identity 供统计/审计按账户聚合
 * @note 对应生产 AuthMiddleware；生产目录认证（Directory）接入见 T5-1
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <common/Core/Authenticator.hpp>
#include <common/Core/Fault/Code.hpp>
#include <common/Core/Fault/Handling.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Middleware/Pipeline.hpp>

namespace Preview::Middleware::Builtin
{

    namespace net = boost::asio;

    /**
     * @class AuthMiddleware
     * @brief 认证中间件
     * @details 从 ctx 提取凭据（identity, Secret），经 Authenticator
     *          校验；通过则写入 ctx.identity，失败/缺失返回 auth_failed。
     */
    class AuthMiddleware final : public Middleware
    {
    public:
        /// 凭据提取签名：从 ctx 提取 (identity, Secret)；nullopt = 缺失凭据
        using CredentialFn =
            std::function<std::optional<std::pair<std::string, std::string>>(const Context &)>;

        /**
         * @brief 构造
         * @param Auth 认证器（可空，运行时校验）
         * @param cred 凭据提取函数（可空，默认读 ctx 内预设字段）
         */
        explicit AuthMiddleware(Preview::SharedAuthenticator Auth,
                                 CredentialFn Cred = DefaultCredential)
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
         * @return success / auth_failed / not_supported
         */
        auto Handle(Preview::SharedTransmission & /*Inbound*/, Context &ctx)
            -> net::awaitable<Preview::Fault::Code> override
        {
            if (!Auth_ || !Cred_)
            {
                co_return Preview::Fault::Code::NotSupported;
            }
            const auto Cred = Cred_(ctx);
            if (!Cred)
            {
                co_return Preview::Fault::Code::AuthFailed;
            }
            const auto Result = Auth_->Check(Cred->first, Cred->second);
            if (!Result.Ok)
            {
                co_return Preview::Fault::Code::AuthFailed;
            }
            ctx.identity = std::move(Result.identity);
            co_return Preview::Fault::Code::Success;
        }

    private:
        /// 默认凭据提取：读取 ctx 预设的 RawIdentity/RawSecret（测试/简单协议）
        static auto DefaultCredential(const Context &ctx)
            -> std::optional<std::pair<std::string, std::string>>
        {
            if (ctx.RawIdentity.empty() || ctx.RawSecret.empty())
            {
                return std::nullopt;
            }
            return std::make_pair(ctx.RawIdentity, ctx.RawSecret);
        }

        Preview::SharedAuthenticator Auth_; ///< 认证器
        CredentialFn Cred_;                 ///< 凭据提取
    };

} // namespace Preview::Middleware::Builtin
