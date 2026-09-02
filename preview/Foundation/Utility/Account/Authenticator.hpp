/**
 * @file Authenticator.hpp
 * @brief 目录认证器（T5-1 O1）
 * @details 基于账户目录的认证器：
 *          - 凭据为目录键，命中且未禁用/未过期 → 通过
 *          - 通过时返回 Lease 身份（占活跃连接，T5-3 配额生效）
 *          - 失败原因：不存在 / 禁用 / 过期
 * @note 实现 Authenticator 接口，接入 Middleware Auth（T4-1）
 */

#pragma once

#include <cstdint>
#include <string_view>

#include <preview/Foundation/Utility/Account/Directory.hpp>
#include <preview/Foundation/Authenticator.hpp>

namespace Preview::Account
{

    /**
     * @enum AuthReason
     * @brief 认证失败原因
     */
    enum class AuthReason : std::uint8_t
    {
        NotFound, ///< 账户不存在
        Disabled,  ///< 账户禁用
        Expired,   ///< 账户过期
    };

    /**
     * @struct DirectoryAuthResult
     * @brief 目录认证结果
     */
    struct DirectoryAuthResult
    {
        bool Ok{false};                       ///< 是否通过
        std::string_view identity{};          ///< 通过后的身份（凭据）
        AuthReason reason{AuthReason::NotFound}; ///< 失败原因
        Preview::Account::Lease Lease{};      ///< 通过后持有租约（占配额）
    };

    /**
     * @class DirectoryAuthenticator
     * @brief 目录认证器
     * @details 凭据 → 目录查找 → 状态校验 → 租约获取。
     *          通过后租约随结果转移（调用方持有至会话结束）。
     */
    class DirectoryAuthenticator final : public Preview::Authenticator
    {
    public:
        /// 时钟函数签名（可注入，测试用）
        using NowFn = std::uint64_t (*)();

        /**
         * @brief 构造
         * @param dir 账户目录（调用方持有）
         * @param now 时钟函数（nullptr = 不过期校验）
         */
        explicit DirectoryAuthenticator(const Directory *dir, NowFn Now = nullptr)
            : Dir_(dir), Now_(Now)
        {
        }

        /**
         * @brief 获取中间件认证结果
         * @param identity 身份标识（未使用；目录按凭据键控）
         * @param Secret 凭据（目录键）
         * @return 认证结果（Ok + identity + 租约）
         */
        [[nodiscard]] auto CheckDirectory(std::string_view identity, std::string_view Secret) const
            -> DirectoryAuthResult
        {
            DirectoryAuthResult Result;
            if (!Dir_)
            {
                Result.reason = AuthReason::NotFound;
                return Result;
            }
            const auto E = Dir_->Find(Secret);
            if (!E)
            {
                Result.reason = AuthReason::NotFound;
                return Result;
            }
            if (E->Disabled())
            {
                Result.reason = AuthReason::Disabled;
                return Result;
            }
            if (Now_ != nullptr)
            {
                const auto Now = Now_();
                if (E->Expired(Now))
                {
                    Result.reason = AuthReason::Expired;
                    return Result;
                }
            }
            std::uint64_t NowArg = 0;
            if (Now_ != nullptr)
            {
                NowArg = Now_();
            }
            auto L = Preview::Account::TryAcquire(*Dir_, Secret, NowArg);
            if (!L)
            {
                Result.reason = AuthReason::Disabled; // 超限视为不可用
                return Result;
            }
            Result.Ok = true;
            Result.identity = std::string_view(Secret);
            Result.Lease = std::move(L);
            return Result;
        }

        /**
         * @brief 认证器接口（identity 参数兼容；Secret 为目录凭据）
         */
        [[nodiscard]] auto Check(std::string_view identity, std::string_view Secret) const
            -> Preview::AuthResult override
        {
            auto R = CheckDirectory(identity, Secret);
            if (!R.Ok)
            {
                return {false, {}};
            }
            Preview::AuthResult Result{true, std::string(R.identity)};
            Result.Lease.emplace(std::move(R.Lease));
            return Result;
        }

    private:
        const Directory *Dir_; ///< 账户目录（非拥有）
        NowFn Now_;           ///< 时钟函数
    };

} // namespace Preview::Account
