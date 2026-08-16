/**
 * @file auth.hpp
 * @brief 认证中间件（T4-1）
 * @details 基于 authenticator 接口校验凭据，通过后写入 ctx.identity：
 *          - 凭据提取函数协议无关（HTTP Basic / socks5 / trojan 等按需注入）
 *          - 认证失败或缺失凭据 → auth_failed（管线终止）
 *          - 成功后 identity 供统计/审计按账户聚合
 * @note 对应生产 auth_middleware；生产目录认证（directory）接入见 T5-1
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <common/core/authenticator.hpp>
#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/middleware/pipeline.hpp>

namespace psmtest::middleware::builtin
{

    namespace net = boost::asio;

    /**
     * @class auth_middleware
     * @brief 认证中间件
     * @details 从 ctx 提取凭据（identity, secret），经 authenticator
     *          校验；通过则写入 ctx.identity，失败/缺失返回 auth_failed。
     */
    class auth_middleware final : public middleware
    {
    public:
        /// 凭据提取签名：从 ctx 提取 (identity, secret)；nullopt = 缺失凭据
        using credential_fn =
            std::function<std::optional<std::pair<std::string, std::string>>(const context &)>;

        /**
         * @brief 构造
         * @param auth 认证器（可空，运行时校验）
         * @param cred 凭据提取函数（可空，默认读 ctx 内预设字段）
         */
        explicit auth_middleware(psmtest::shared_authenticator auth,
                                 credential_fn cred = default_credential)
            : auth_(std::move(auth)), cred_(std::move(cred))
        {
        }

        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto name() const -> std::string_view override
        {
            return "auth";
        }

        /**
         * @brief 执行认证
         * @param inbound 入站传输（不修改）
         * @param ctx 上下文（成功后写入 identity）
         * @return success / auth_failed / not_supported
         */
        auto handle(psmtest::shared_transmission & /*inbound*/, context &ctx)
            -> net::awaitable<psmtest::fault::code> override
        {
            if (!auth_ || !cred_)
            {
                co_return psmtest::fault::code::not_supported;
            }
            const auto cred = cred_(ctx);
            if (!cred)
            {
                co_return psmtest::fault::code::auth_failed;
            }
            const auto result = auth_->check(cred->first, cred->second);
            if (!result.ok)
            {
                co_return psmtest::fault::code::auth_failed;
            }
            ctx.identity = std::move(result.identity);
            co_return psmtest::fault::code::success;
        }

    private:
        /// 默认凭据提取：读取 ctx 预设的 raw_identity/raw_secret（测试/简单协议）
        static auto default_credential(const context &ctx)
            -> std::optional<std::pair<std::string, std::string>>
        {
            if (ctx.raw_identity.empty() || ctx.raw_secret.empty())
            {
                return std::nullopt;
            }
            return std::make_pair(ctx.raw_identity, ctx.raw_secret);
        }

        psmtest::shared_authenticator auth_; ///< 认证器
        credential_fn cred_;                 ///< 凭据提取
    };

} // namespace psmtest::middleware::builtin
