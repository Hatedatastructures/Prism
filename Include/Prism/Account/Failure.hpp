/** @file Failure.hpp
 * @brief 账户失败的唯一Fault原因，保留额度种类而不从文字猜错误。
 */
#pragma once
#include <Prism/Foundation/Fault/Failure.hpp>
#include <system_error>
#include <string>
namespace Prism::Account
{
    enum class FailureReason : int
    {
        Revoked = 1, ConnectionQuota, StreamQuota, ByteQuota, RateLimited, Busy,
        RootSlots, PolicyViews, Accounts, Scopes, InvalidCredential, NotFound, PolicyMismatch, VersionExhausted,
    };
    namespace Detail
    {
        /** @brief category寿命覆盖全部Failure；message只用于冷诊断，热路径保存category/value。 */
        class AccountCategory final : public std::error_category
        {
        public:
            auto name() const noexcept -> const char* override { return "Prism.Account"; }
            auto message(int Value) const -> std::string override;
        };
        inline const AccountCategory AccountErrorCategory;
    }
    [[nodiscard]] auto MakeFailure(FailureReason Reason) noexcept -> Fault::Failure;
}
