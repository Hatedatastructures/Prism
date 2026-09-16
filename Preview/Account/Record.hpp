/**
 * @file Record.hpp
 * @brief 不可变账户配置记录
 * @details AccountRecord 只保存账户身份、凭据和策略；所有会话期变化都
 *          进入独立的 AccountRuntimeState。
 */
#pragma once

#include "Credential.hpp"
#include "Runtime.hpp"

#include "../Foundation/Identifier/Id.hpp"

#include <memory>
#include <string>
#include <stdexcept>
#include <utility>

namespace Preview::Account
{

    class AccountDirectory;

    class AccountRecord final
    {
    public:
        struct CreateRequest
        {
            Preview::AccountId AccountId;
            Credential CredentialValue;
            QuotaPolicy Quota{};
            RatePolicy Rate{};
            Preview::GenerationId PolicyGeneration{};
        };

        explicit AccountRecord(CreateRequest Request)
            : AccountId_(std::move(Request.AccountId)),
              Credential_(std::move(Request.CredentialValue)),
              Quota_(Request.Quota),
              Rate_(std::move(Request.Rate)),
              PolicyGeneration_(Request.PolicyGeneration),
              Runtime_(std::make_shared<AccountRuntimeState>(Rate_, Quota_.MaxBytes,
                                                              PolicyGeneration_))
        {
            Validate();
        }

        AccountRecord(const AccountRecord &) = delete;
        auto operator=(const AccountRecord &) -> AccountRecord & = delete;
        AccountRecord(AccountRecord &&) = delete;
        auto operator=(AccountRecord &&) -> AccountRecord & = delete;

        [[nodiscard]] auto AccountId() const noexcept -> Preview::AccountId
        {
            return AccountId_;
        }

        [[nodiscard]] auto Credential() const noexcept -> CredentialView
        {
            return Credential_.View();
        }

        [[nodiscard]] auto Quota() const noexcept -> const QuotaPolicy &
        {
            return Quota_;
        }

        [[nodiscard]] auto Rate() const noexcept -> const RatePolicy &
        {
            return Rate_;
        }

        [[nodiscard]] auto PolicyGeneration() const noexcept -> Preview::GenerationId
        {
            return PolicyGeneration_;
        }

        [[nodiscard]] auto Runtime() const noexcept -> const SharedAccountRuntimeState &
        {
            return Runtime_;
        }

        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return static_cast<bool>(AccountId_) && Credential_.IsValid() && static_cast<bool>(Runtime_);
        }

        [[nodiscard]] auto Redacted() const -> std::string
        {
            std::string Result;
            Result.reserve(24);
            Result.append(std::to_string(AccountId_.Value()));
            Result.append(":");
            Result.append(Credential_.Redacted());
            return Result;
        }

    private:
        friend class AccountDirectory;

        [[nodiscard]] auto WithRuntime(SharedAccountRuntimeState Runtime,
                                       Preview::GenerationId PolicyGeneration) const
            -> std::shared_ptr<const AccountRecord>
        {
            if (!Runtime)
            {
                throw std::invalid_argument("account runtime is required");
            }
            CreateRequest Request{
                AccountId_,
                Preview::Account::Credential(Credential_.Kind(),
                                             SecureBytes(Credential_.View().Bytes())),
                Quota_,
                Rate_,
                PolicyGeneration};
            return std::shared_ptr<const AccountRecord>(
                new AccountRecord(std::move(Request), std::move(Runtime)));
        }

        AccountRecord(CreateRequest Request, SharedAccountRuntimeState Runtime)
            : AccountId_(std::move(Request.AccountId)),
              Credential_(std::move(Request.CredentialValue)),
              Quota_(Request.Quota),
              Rate_(std::move(Request.Rate)),
              PolicyGeneration_(Request.PolicyGeneration),
              Runtime_(std::move(Runtime))
        {
            Validate();
        }

        void Validate() const
        {
            if (!static_cast<bool>(AccountId_) || !Credential_.IsValid() || !Runtime_)
            {
                throw std::invalid_argument("invalid account record");
            }
        }

        const Preview::AccountId AccountId_;
        const Preview::Account::Credential Credential_;
        const QuotaPolicy Quota_;
        const RatePolicy Rate_;
        const Preview::GenerationId PolicyGeneration_;
        const SharedAccountRuntimeState Runtime_;
    };

    using SharedAccountRecord = std::shared_ptr<const AccountRecord>;

} // namespace Preview::Account
