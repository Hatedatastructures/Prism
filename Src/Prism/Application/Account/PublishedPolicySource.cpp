/** @file PublishedPolicySource.cpp @brief 按原子发布快照读取账户策略。 */

#include <Prism/Application/Account/PublishedPolicySource.hpp>
#include <Prism/Application/RuntimeGenerationSnapshot.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>

#include <utility>

namespace Prism::Application
{

    PublishedPolicySource::PublishedPolicySource(
        std::shared_ptr<Prism::Runtime::GenerationPublication> Publisher)
        : Publisher_(std::move(Publisher))
    {
    }

    auto PublishedPolicySource::Load(const Prism::AccountId Id) const noexcept
        -> std::shared_ptr<const Prism::Account::PolicySnapshot>
    {
        const auto Publisher = Publisher_.lock();
        if (!Publisher)
        {
            return {};
        }
        const auto Current = std::dynamic_pointer_cast<const RuntimeGenerationSnapshot>(
            Publisher->Current());
        if (!Current || !Current->Accounts.Store)
        {
            return {};
        }
        const auto Binding = Current->Accounts.Store->FindById(Id);
        if (!Binding)
        {
            return {};
        }
        return Binding->Policy();
    }

} // namespace Prism::Application
