/** @file GenerationPublication.cpp @brief 原子化代次与账户发布实现。 */
#include <Prism/Runtime/GenerationPublication.hpp>

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

namespace Prism::Runtime
{
    GenerationPublication::GenerationPublication()
        : AdmissionGate_(std::make_shared<Prism::Contract::AccountAdmissionGate>()),
          State_(std::make_shared<const Published>(Published{
              {}, {}, std::make_shared<const AccountSnapshot>(
                          std::vector<Prism::AccountId>{},
                          std::vector<Prism::AccountId>{}, false)}))
    {
    }

    auto GenerationPublication::Current() const noexcept
        -> std::shared_ptr<const Prism::Foundation::GenerationLifetime>
    {
        return State_.load(std::memory_order_acquire)->Active;
    }

    auto GenerationPublication::Read() const noexcept -> GenerationPublicationView
    {
        const auto State = State_.load(std::memory_order_acquire);
        return {State->Active, State->Accounts};
    }

    auto GenerationPublication::Contains(const Prism::GenerationId Id) const noexcept -> bool
    {
        const auto State = State_.load(std::memory_order_acquire);
        if (State->Active && State->Active->Id() == Id)
        {
            return true;
        }
        return std::any_of(State->RetiredGenerations.begin(), State->RetiredGenerations.end(),
            [Id](const Retired& Entry)
            {
                const auto Owner = Entry.Owner.lock();
                return Owner && Entry.Id == Id && Owner->Id() == Id;
            });
    }

    auto GenerationPublication::RetainedCount() const noexcept -> std::size_t
    {
        const auto State = State_.load(std::memory_order_acquire);
        const auto RetiredCount = static_cast<std::size_t>(std::count_if(
            State->RetiredGenerations.begin(), State->RetiredGenerations.end(),
            [](const Retired& Entry) { return !Entry.Owner.expired(); }));
        return RetiredCount + static_cast<std::size_t>(State->Active != nullptr);
    }

    auto GenerationPublication::Load() const noexcept -> AccountSnapshotPin
    {
        return State_.load(std::memory_order_acquire)->Accounts;
    }

    auto GenerationPublication::BeginAdmission(const Prism::AccountId Id) noexcept
        -> std::expected<Prism::Contract::AccountAdmissionPermit, Failure>
    {
        if (!Id)
        {
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (!AdmissionGate_->TryBeginAdmission())
        {
            return std::unexpected(Failure{Prism::Fault::Code::WouldBlock});
        }
        const auto State = State_.load(std::memory_order_acquire);
        if (!State->Accounts || !State->Accounts->IsAdmitted(Id))
        {
            AdmissionGate_->ReleaseAccountAdmission();
            if (State->Accounts && State->Accounts->Closed)
            {
                return std::unexpected(Failure{Prism::Fault::Code::Canceled});
            }
            return std::unexpected(Failure{Prism::Fault::Code::Forbidden});
        }
        try
        {
            return Prism::Contract::AccountAdmissionPermit{
                std::static_pointer_cast<Prism::Contract::AccountAdmissionLeaseOwner>(
                    AdmissionGate_)};
        }
        catch (...)
        {
            AdmissionGate_->ReleaseAccountAdmission();
            return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
        }
    }

    auto GenerationPublication::RevokeAccounts(
        const std::span<const Prism::AccountId> Ids) noexcept
        -> std::expected<void, Failure>
    {
        if (Ids.empty())
        {
            return {};
        }
        for (const auto Id : Ids)
        {
            if (!Id)
            {
                return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            }
        }
        if (!AdmissionGate_->TryBeginPublication())
        {
            return std::unexpected(Failure{Prism::Fault::Code::WouldBlock});
        }
        auto Result = RevokeWhileExclusive(Ids);
        AdmissionGate_->EndPublication();
        return Result;
    }

    auto GenerationPublication::CloseAllAccounts() noexcept
        -> std::expected<void, Failure>
    {
        if (!AdmissionGate_->TryBeginPublication())
        {
            return std::unexpected(Failure{Prism::Fault::Code::WouldBlock});
        }
        auto Result = CloseAccountsWhileExclusive();
        AdmissionGate_->EndPublication();
        return Result;
    }

    auto GenerationPublication::Prepare(
        const std::shared_ptr<const Prism::Foundation::GenerationLifetime>& Expected,
        std::shared_ptr<const Prism::Foundation::GenerationLifetime> Candidate,
        std::vector<Prism::AccountId> CandidateAccounts) const
        -> std::expected<PrepareToken, PrepareError>
    {
        if (!Candidate || !Candidate->Id())
        {
            return std::unexpected(PrepareError::MissingGeneration);
        }
        const auto CurrentState = State_.load(std::memory_order_acquire);
        if (CurrentState->Active != Expected)
        {
            return std::unexpected(PrepareError::StaleBase);
        }
        if (CurrentState->Accounts->Closed)
        {
            return std::unexpected(PrepareError::Closed);
        }
        if (Expected && Candidate->Id() <= Expected->Id())
        {
            return std::unexpected(PrepareError::NonMonotonicGeneration);
        }

        const auto Accounts = PrepareAccounts(*CurrentState->Accounts,
            std::move(CandidateAccounts));
        if (!Accounts)
        {
            return std::unexpected(Accounts.error());
        }

        std::vector<Retired> Retained;
        Retained.reserve(CurrentState->RetiredGenerations.size() + 1U);
        for (const auto& Entry : CurrentState->RetiredGenerations)
        {
            if (!Entry.Owner.expired())
            {
                Retained.push_back(Entry);
            }
        }
        if (Expected)
        {
            Retained.push_back(Retired{Expected->Id(), Expected});
        }
        if (Retained.size() + 1U > MaxRetainedGenerations)
        {
            return std::unexpected(PrepareError::RetentionLimit);
        }
        auto Next = std::make_shared<const Published>(Published{
            std::move(Candidate), std::move(Retained), *Accounts});
        return PrepareToken{CurrentState, std::move(Next)};
    }

    auto GenerationPublication::Publish(PrepareToken& Token) noexcept
        -> std::expected<void, PublishError>
    {
        if (!Token.Expected_ || !Token.Next_)
        {
            return std::unexpected(PublishError::InvalidToken);
        }
        if (!AdmissionGate_->TryBeginPublication())
        {
            return std::unexpected(PublishError::AdmissionBusy);
        }
        auto Expected = Token.Expected_;
        const auto Published = State_.compare_exchange_strong(Expected, Token.Next_,
            std::memory_order_acq_rel, std::memory_order_acquire);
        AdmissionGate_->EndPublication();
        if (!Published)
        {
            return std::unexpected(PublishError::StaleBase);
        }
        Token.Expected_.reset();
        Token.Next_.reset();
        return {};
    }

    auto GenerationPublication::Clear() noexcept -> bool
    {
        if (!AdmissionGate_->TryBeginPublication())
        {
            return false;
        }
        try
        {
            const auto Current = State_.load(std::memory_order_acquire);
            if (!Current->Active && Current->RetiredGenerations.empty() &&
                Current->Accounts->Closed)
            {
                AdmissionGate_->EndPublication();
                return true;
            }
            auto Closed = std::make_shared<const AccountSnapshot>(
                std::vector<Prism::AccountId>{},
                std::vector<Prism::AccountId>{}, true);
            auto Next = std::make_shared<const Published>(Published{{}, {}, std::move(Closed)});
            State_.store(std::move(Next), std::memory_order_release);
            AdmissionGate_->EndPublication();
            return true;
        }
        catch (...)
        {
            AdmissionGate_->EndPublication();
            return false;
        }
    }

    auto GenerationPublication::PrepareAccounts(
        const AccountSnapshot& Current,
        std::vector<Prism::AccountId> Members)
        -> std::expected<AccountSnapshotPin, PrepareError>
    {
        if (Members.size() > AccountSnapshot::MaxMembers)
        {
            return std::unexpected(PrepareError::AccountLimit);
        }
        if (std::any_of(Members.begin(), Members.end(), [](const auto Id) { return !Id; }))
        {
            return std::unexpected(PrepareError::InvalidAccount);
        }
        std::sort(Members.begin(), Members.end());
        if (std::adjacent_find(Members.begin(), Members.end()) != Members.end())
        {
            return std::unexpected(PrepareError::InvalidAccount);
        }
        auto Revoked = Current.Revoked;
        for (const auto Id : Current.Members)
        {
            if (!std::binary_search(Members.begin(), Members.end(), Id))
            {
                Revoked.push_back(Id);
            }
        }
        std::sort(Revoked.begin(), Revoked.end());
        Revoked.erase(std::unique(Revoked.begin(), Revoked.end()), Revoked.end());
        if (Revoked.size() > AccountSnapshot::MaxRevocations)
        {
            return std::unexpected(PrepareError::RevocationLimit);
        }
        return std::make_shared<const AccountSnapshot>(
            std::move(Members), std::move(Revoked), false);
    }

    auto GenerationPublication::RevokeWhileExclusive(
        const std::span<const Prism::AccountId> Ids) noexcept
        -> std::expected<void, Failure>
    {
        try
        {
            const auto Current = State_.load(std::memory_order_acquire);
            if (!Current->Active || Current->Accounts->Closed)
            {
                return std::unexpected(Failure{Prism::Fault::Code::Canceled});
            }
            auto Revoked = Current->Accounts->Revoked;
            for (const auto Id : Ids)
            {
                if (!Current->Accounts->IsMember(Id))
                {
                    return std::unexpected(Failure{Prism::Fault::Code::AuthFailed});
                }
                Revoked.push_back(Id);
            }
            std::sort(Revoked.begin(), Revoked.end());
            Revoked.erase(std::unique(Revoked.begin(), Revoked.end()), Revoked.end());
            if (Revoked.size() == Current->Accounts->Revoked.size())
            {
                return {};
            }
            if (Revoked.size() > AccountSnapshot::MaxRevocations)
            {
                return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
            }
            auto Accounts = std::make_shared<const AccountSnapshot>(
                Current->Accounts->Members, std::move(Revoked), false);
            auto Next = std::make_shared<const Published>(Published{
                Current->Active, Current->RetiredGenerations, std::move(Accounts)});
            auto Expected = Current;
            if (!State_.compare_exchange_strong(Expected, std::move(Next),
                    std::memory_order_acq_rel, std::memory_order_acquire))
            {
                return std::unexpected(Failure{Prism::Fault::Code::WouldBlock});
            }
            return {};
        }
        catch (...)
        {
            return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
        }
    }

    auto GenerationPublication::CloseAccountsWhileExclusive() noexcept
        -> std::expected<void, Failure>
    {
        try
        {
            const auto Current = State_.load(std::memory_order_acquire);
            if (Current->Accounts->Closed)
            {
                return {};
            }
            auto Accounts = std::make_shared<const AccountSnapshot>(
                Current->Accounts->Members, Current->Accounts->Revoked, true);
            auto Next = std::make_shared<const Published>(Published{
                Current->Active, Current->RetiredGenerations, std::move(Accounts)});
            auto Expected = Current;
            if (!State_.compare_exchange_strong(Expected, std::move(Next),
                    std::memory_order_acq_rel, std::memory_order_acquire))
            {
                return std::unexpected(Failure{Prism::Fault::Code::WouldBlock});
            }
            return {};
        }
        catch (...)
        {
            return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
        }
    }
}
