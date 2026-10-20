/** @file Binding.cpp
 * @brief 账户绑定的活动资源策略解析。
 */
#include <Prism/Account/Binding.hpp>

namespace Prism::Account
{
    auto AccountBinding::ResourcePolicy() const noexcept -> std::shared_ptr<const PolicySnapshot>
    {
        if (const auto Source = Runtime_->ResourcePolicySource())
            return Source->Load(AccountId());
        return Policy_;
    }
}
