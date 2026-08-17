/**
 * @file authenticator.hpp
 * @brief 目录认证器（T5-1 O1）
 * @details 基于账户目录的认证器：
 *          - 凭据为目录键，命中且未禁用/未过期 → 通过
 *          - 通过时返回 lease 身份（占活跃连接，T5-3 配额生效）
 *          - 失败原因：不存在 / 禁用 / 过期
 * @note 实现 authenticator 接口，接入 middleware auth（T4-1）
 */

#pragma once

#include <cstdint>
#include <string_view>

#include <common/core/account/directory.hpp>
#include <common/core/authenticator.hpp>

namespace preview::account
{

    /**
     * @enum auth_reason
     * @brief 认证失败原因
     */
    enum class auth_reason : std::uint8_t
    {
        not_found, ///< 账户不存在
        disabled,  ///< 账户禁用
        expired,   ///< 账户过期
    };

    /**
     * @struct directory_auth_result
     * @brief 目录认证结果
     */
    struct directory_auth_result
    {
        bool ok{false};                       ///< 是否通过
        std::string_view identity{};          ///< 通过后的身份（凭据）
        auth_reason reason{auth_reason::not_found}; ///< 失败原因
        preview::account::lease lease{};      ///< 通过后持有租约（占配额）
    };

    /**
     * @class directory_authenticator
     * @brief 目录认证器
     * @details 凭据 → 目录查找 → 状态校验 → 租约获取。
     *          通过后租约随结果转移（调用方持有至会话结束）。
     */
    class directory_authenticator final : public preview::authenticator
    {
    public:
        /// 时钟函数签名（可注入，测试用）
        using now_fn = std::uint64_t (*)();

        /**
         * @brief 构造
         * @param dir 账户目录（调用方持有）
         * @param now 时钟函数（nullptr = 不过期校验）
         */
        explicit directory_authenticator(const directory *dir, now_fn now = nullptr)
            : dir_(dir), now_(now)
        {
        }

        /**
         * @brief 获取中间件认证结果
         * @param identity 身份标识（未使用；目录按凭据键控）
         * @param secret 凭据（目录键）
         * @return 认证结果（ok + identity + 租约）
         */
        [[nodiscard]] auto check_directory(std::string_view identity, std::string_view secret) const
            -> directory_auth_result
        {
            directory_auth_result result;
            if (!dir_)
            {
                result.reason = auth_reason::not_found;
                return result;
            }
            const auto e = dir_->find(secret);
            if (!e)
            {
                result.reason = auth_reason::not_found;
                return result;
            }
            if (e->disabled())
            {
                result.reason = auth_reason::disabled;
                return result;
            }
            if (now_ != nullptr)
            {
                const auto now = now_();
                if (e->expired(now))
                {
                    result.reason = auth_reason::expired;
                    return result;
                }
            }
            std::uint64_t now_arg = 0;
            if (now_ != nullptr)
            {
                now_arg = now_();
            }
            auto l = preview::account::try_acquire(*dir_, secret, now_arg);
            if (!l)
            {
                result.reason = auth_reason::disabled; // 超限视为不可用
                return result;
            }
            result.ok = true;
            result.identity = std::string_view(secret);
            result.lease = std::move(l);
            return result;
        }

        /**
         * @brief 认证器接口（identity 参数兼容；secret 为目录凭据）
         */
        [[nodiscard]] auto check(std::string_view identity, std::string_view secret) const
            -> preview::auth_result override
        {
            auto r = check_directory(identity, secret);
            if (!r.ok)
            {
                return {false, {}};
            }
            return {true, std::string(r.identity)};
        }

    private:
        const directory *dir_; ///< 账户目录（非拥有）
        now_fn now_;           ///< 时钟函数
    };

} // namespace preview::account
