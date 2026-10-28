/** @file PublishedPolicySource.hpp @brief 从唯一 generation publication 读取账户策略的内部适配。 */
#pragma once

#include <Prism/Account/Policy.hpp>

#include <memory>

namespace Prism::Runtime
{
    class GenerationPublication;
}

namespace Prism::Application
{

    /** @brief 只 pin 发布器，不持有 RuntimeState，避免进程服务图形成强引用环。 */
    class PublishedPolicySource final : public Prism::Account::PolicySource
    {
    public:
        explicit PublishedPolicySource(
            std::shared_ptr<Prism::Runtime::GenerationPublication> Publisher);

        [[nodiscard]] auto Load(Prism::AccountId Id) const noexcept
            -> std::shared_ptr<const Prism::Account::PolicySnapshot> override;

    private:
        const std::weak_ptr<Prism::Runtime::GenerationPublication> Publisher_;
    };

} // namespace Prism::Application
