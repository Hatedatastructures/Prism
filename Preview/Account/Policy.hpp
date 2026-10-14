/** @file Policy.hpp
 * @brief Binding 一次发布的不可变额度/速率策略，lease 保留原代次。
 */
#pragma once
#include <Preview/Account/Quota.hpp>
#include <Preview/Account/Rate.hpp>
#include <Preview/Account/PolicyVersion.hpp>
namespace Preview::Account
{
    struct PolicySettings final
    {
        QuotaPolicy Quota;
        RatePolicy Rate;
    };
    class PolicySnapshot final
    {
    public:
        struct CreateRequest final
        {
            Preview::Account::PolicyVersion Version;
            PolicySettings Settings;
            std::shared_ptr<const RateLimiter> Rate;
        };
        explicit PolicySnapshot(CreateRequest Request) : Version_(Request.Version),
            Settings_(std::move(Request.Settings)), Rate_(std::move(Request.Rate)) {}
        [[nodiscard]] auto Version() const noexcept -> Preview::Account::PolicyVersion { return Version_; }
        [[nodiscard]] auto Quota() const noexcept -> const QuotaPolicy& { return Settings_.Quota; }
        [[nodiscard]] auto Rate() const noexcept -> const std::shared_ptr<const RateLimiter>& { return Rate_; }
        [[nodiscard]] auto Settings() const noexcept -> const PolicySettings& { return Settings_; }
    private:
        const Preview::Account::PolicyVersion Version_;
        const PolicySettings Settings_;
        const std::shared_ptr<const RateLimiter> Rate_;
    };
}
