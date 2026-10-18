/** @file Policy.hpp
 * @brief Binding 一次发布的不可变额度/速率策略，lease 保留原代次。
 */
#pragma once
#include <Prism/Account/Quota.hpp>
#include <Prism/Account/Rate.hpp>
#include <Prism/Account/PolicyVersion.hpp>
#include <Prism/Account/PolicyConfiguration.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
namespace Prism::Account
{
    struct PolicySettings final
    {
        QuotaPolicy Quota;
        RatePolicy Rate;
        TransferPolicy Transfer;
    };
    class PolicySnapshot final
    {
    public:
        struct CreateRequest final
        {
            Prism::Account::PolicyVersion Version;
            PolicySettings Settings;
            std::shared_ptr<const RateLimiter> Rate;
        };
        explicit PolicySnapshot(CreateRequest Request) : Version_(Request.Version),
            Settings_(std::move(Request.Settings)), Rate_(std::move(Request.Rate)) {}
        [[nodiscard]] auto Version() const noexcept -> Prism::Account::PolicyVersion { return Version_; }
        [[nodiscard]] auto Quota() const noexcept -> const QuotaPolicy& { return Settings_.Quota; }
        [[nodiscard]] auto Rate() const noexcept -> const std::shared_ptr<const RateLimiter>& { return Rate_; }
        [[nodiscard]] auto Settings() const noexcept -> const PolicySettings& { return Settings_; }
    private:
        const Prism::Account::PolicyVersion Version_;
        const PolicySettings Settings_;
        const std::shared_ptr<const RateLimiter> Rate_;
    };
    /** @brief 只读取当前正式发布的策略；实现不得在候选准备阶段改变事实。 */
    class PolicySource
    {
    public:
        virtual ~PolicySource() = default;
        [[nodiscard]] virtual auto Load(Prism::AccountId Id) const noexcept
            -> std::shared_ptr<const PolicySnapshot> = 0;
    };
}
