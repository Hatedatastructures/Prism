/** @file Binding.hpp
 * @brief 唯一发布的材料、冻结策略与运行账本组合。
 */
#pragma once
#include <Prism/Account/Materials.hpp>
#include <Prism/Account/Policy.hpp>
#include <Prism/Account/Runtime.hpp>

#include <memory>
#include <utility>
namespace Prism::Account
{
    class AccountStore;
    /** @brief 不可变认证事实；所有拥有者固定同一组合，不查 runtime.currentPolicy。 */
    class AccountBinding final
    {
    public:
        [[nodiscard]] auto AccountId() const noexcept -> Prism::AccountId
        {
            return Materials_->AccountId();
        }
        [[nodiscard]] auto Materials() const noexcept -> const std::shared_ptr<const AccountMaterials>&
        {
            return Materials_;
        }
        [[nodiscard]] auto Policy() const noexcept -> const std::shared_ptr<const PolicySnapshot>&
        {
            return Policy_;
        }
        [[nodiscard]] auto Runtime() const noexcept -> const std::shared_ptr<AccountRuntime>&
        {
            return Runtime_;
        }
        /** @brief 活动资源约束跟随正式发布；独立 store 尚未接发布器时使用其冻结策略。 */
        [[nodiscard]] auto ResourcePolicy() const noexcept -> std::shared_ptr<const PolicySnapshot>;

    private:
        friend class AccountStore;
        struct CreateRequest final
        {
            std::shared_ptr<const AccountMaterials> Materials;
            std::shared_ptr<const PolicySnapshot> Policy;
            std::shared_ptr<AccountRuntime> Runtime;
        };
        explicit AccountBinding(CreateRequest Request)
            : Materials_(std::move(Request.Materials)), Policy_(std::move(Request.Policy)),
              Runtime_(std::move(Request.Runtime))
        {
        }
        const std::shared_ptr<const AccountMaterials> Materials_;
        const std::shared_ptr<const PolicySnapshot> Policy_;
        const std::shared_ptr<AccountRuntime> Runtime_;
    };
} // namespace Prism::Account
