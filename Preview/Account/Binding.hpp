/** @file Binding.hpp
 * @brief 唯一发布的材料、冻结策略与运行账本组合。
 */
#pragma once
#include <Preview/Account/Materials.hpp>
#include <Preview/Account/Policy.hpp>
#include <Preview/Account/Runtime.hpp>
namespace Preview::Account
{
    class AccountStore;
    /** @brief immutable 认证事实；所有拥有者 pin 同一组合，不查 runtime.currentPolicy。 */
    class AccountBinding final
    {
    public:
        [[nodiscard]] auto AccountId() const noexcept -> Preview::AccountId { return Materials_->AccountId(); }
        [[nodiscard]] auto Materials() const noexcept -> const std::shared_ptr<const AccountMaterials>& { return Materials_; }
        [[nodiscard]] auto Policy() const noexcept -> const std::shared_ptr<const PolicySnapshot>& { return Policy_; }
        [[nodiscard]] auto Runtime() const noexcept -> const std::shared_ptr<AccountRuntime>& { return Runtime_; }
    private:
        friend class AccountStore;
        struct CreateRequest final
        {
            std::shared_ptr<const AccountMaterials> Materials;
            std::shared_ptr<const PolicySnapshot> Policy;
            std::shared_ptr<AccountRuntime> Runtime;
        };
        explicit AccountBinding(CreateRequest Request) : Materials_(std::move(Request.Materials)),
            Policy_(std::move(Request.Policy)), Runtime_(std::move(Request.Runtime)) {}
        const std::shared_ptr<const AccountMaterials> Materials_;
        const std::shared_ptr<const PolicySnapshot> Policy_;
        const std::shared_ptr<AccountRuntime> Runtime_;
    };
}
