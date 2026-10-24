/** @file IdentityRegistry.cpp @brief Prism 账户身份注册和候选身份提交实现。 */
#include <Prism/Application/Account/IdentityRegistry.hpp>

#include <limits>
#include <utility>

namespace Prism::Application
{

    AccountIdentityRegistry::AccountIdentityRegistry()
        : RuntimeRegistry_(std::make_shared<Prism::Account::AccountRuntimeRegistry>())
    {
    }

    auto AccountIdentityRegistry::BeginPreparation()
        -> std::expected<std::shared_ptr<AccountIdentityPreparation>, Prism::Fault::Failure>
    {
        if (Mutation_.test_and_set(std::memory_order_acquire))
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        try
        {
            return std::shared_ptr<AccountIdentityPreparation>(
                new AccountIdentityPreparation(shared_from_this()));
        }
        catch (...)
        {
            Mutation_.clear(std::memory_order_release);
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
    }

    AccountIdentityPreparation::AccountIdentityPreparation(
        std::shared_ptr<AccountIdentityRegistry> OwnerValue) noexcept
        : Owner_(std::move(OwnerValue)),
          BaseNextAccount_(Owner_->NextAccount_),
          BaseNextScope_(Owner_->NextScope_)
    {
    }

    AccountIdentityPreparation::~AccountIdentityPreparation()
    {
        Rollback();
    }

    auto AccountIdentityPreparation::Account(const std::string_view Name)
        -> std::expected<Prism::AccountId, Prism::Fault::Failure>
    {
        if (!Owner_ || Completed_ || Name.empty() || Name.size() > 253U)
        {
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (const auto It = Owner_->Accounts_.find(Name); It != Owner_->Accounts_.end())
        {
            return It->second;
        }
        if (const auto It = CandidateAccounts_.find(Name); It != CandidateAccounts_.end())
        {
            return It->second;
        }
        if (Owner_->Accounts_.size() + CandidateAccounts_.size() >= AccountIdentityRegistry::MaxAccounts ||
            Owner_->NextAccount_ == 0U)
        {
            return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        const Prism::AccountId Id{Owner_->NextAccount_};
        if (Owner_->NextAccount_ == std::numeric_limits<std::uint64_t>::max())
        {
            Owner_->NextAccount_ = 0U;
        }
        else
        {
            ++Owner_->NextAccount_;
        }
        try
        {
            CandidateAccounts_.emplace(std::string(Name), Id);
        }
        catch (...)
        {
            return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        return Id;
    }

    auto AccountIdentityPreparation::Scope(const std::string_view ProtocolId)
        -> std::expected<Prism::Account::CredentialScope, Prism::Fault::Failure>
    {
        if (!Owner_ || Completed_ || ProtocolId.empty() || ProtocolId.size() > 253U)
        {
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (const auto It = Owner_->Scopes_.find(ProtocolId); It != Owner_->Scopes_.end())
        {
            return It->second;
        }
        if (const auto It = CandidateScopes_.find(ProtocolId); It != CandidateScopes_.end())
        {
            return It->second;
        }
        if (Owner_->Scopes_.size() + CandidateScopes_.size() >= AccountIdentityRegistry::MaxScopes ||
            Owner_->NextScope_ == 0U)
        {
            return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        const Prism::Account::CredentialScope Id{Owner_->NextScope_++};
        try
        {
            CandidateScopes_.emplace(std::string(ProtocolId), Id);
        }
        catch (...)
        {
            return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        return Id;
    }

    auto AccountIdentityPreparation::StageCommit() noexcept
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Owner_ || Completed_)
        {
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (Staged_)
        {
            return {};
        }
        for (const auto &Entry : CandidateAccounts_)
        {
            if (Owner_->Accounts_.contains(Entry.first))
            {
                return std::unexpected(Failure{Prism::Fault::Code::Blocked});
            }
        }
        for (const auto &Entry : CandidateScopes_)
        {
            if (Owner_->Scopes_.contains(Entry.first))
            {
                return std::unexpected(Failure{Prism::Fault::Code::Blocked});
            }
        }
        Staged_ = true;
        return {};
    }

    auto AccountIdentityPreparation::Commit() noexcept
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Owner_ || Completed_ || !Staged_)
        {
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        Owner_->Accounts_.merge(CandidateAccounts_);
        Owner_->Scopes_.merge(CandidateScopes_);
        Completed_ = true;
        Owner_->Mutation_.clear(std::memory_order_release);
        return {};
    }

    auto AccountIdentityPreparation::Rollback() noexcept -> void
    {
        if (Owner_ && !Completed_)
        {
            Owner_->NextAccount_ = BaseNextAccount_;
            Owner_->NextScope_ = BaseNextScope_;
            Completed_ = true;
            Owner_->Mutation_.clear(std::memory_order_release);
        }
    }

} // namespace Prism::Application
