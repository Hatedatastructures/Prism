/** @file PublishedPolicySource.hpp
 * @brief 从唯一 Generation publication 读取账户资源策略，不发布候选策略。
 */
#pragma once
#include <Preview/Account/Policy.hpp>
#include <Preview/Application/RuntimeGenerationSnapshot.hpp>
#include <Preview/Runtime/GenerationPublication.hpp>
#include <memory>

namespace Preview::Application
{
    /** @brief 仅 pin 发布器，不持有 RuntimeState，避免进程服务图形成强引用环。 */
    class PublishedPolicySource final : public Preview::Account::PolicySource
    {
    public:
        explicit PublishedPolicySource(std::shared_ptr<Preview::Runtime::GenerationPublication> Publisher)
            : Publisher_(std::move(Publisher)) {}
        [[nodiscard]] auto Load(const Preview::AccountId Id) const noexcept
            -> std::shared_ptr<const Preview::Account::PolicySnapshot> override
        {
            const auto Publisher = Publisher_.lock();
            if (!Publisher) return {};
            const auto Current = std::dynamic_pointer_cast<const RuntimeGenerationSnapshot>(Publisher->Current());
            if (!Current || !Current->Accounts.Store) return {};
            const auto Binding = Current->Accounts.Store->FindById(Id);
            if (!Binding) return {};
            return Binding->Policy();
        }
    private:
        const std::weak_ptr<Preview::Runtime::GenerationPublication> Publisher_;
    };
}
