/** @file Failure.hpp
 * @brief 账户失败的唯一Fault原因，保留额度种类而不从文字猜错误。
 */
#pragma once
#include <Preview/Foundation/Fault/Failure.hpp>
#include <system_error>
#include <string>
namespace Preview::Account
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
            auto name() const noexcept -> const char* override { return "Preview.Account"; }
            auto message(const int Value) const -> std::string override
            {
                switch (static_cast<FailureReason>(Value))
                {
                case FailureReason::Revoked: return "账户已撤销";
                case FailureReason::ConnectionQuota: return "账户连接额度已满";
                case FailureReason::StreamQuota: return "账户子流额度已满";
                case FailureReason::ByteQuota: return "账户字节额度已满";
                case FailureReason::RateLimited: return "账户速率额度已满";
                case FailureReason::Busy: return "账户原子操作正在被预约";
                case FailureReason::RootSlots: return "进程账户根槽已满";
                case FailureReason::PolicyViews: return "账户保留策略视图已满";
                case FailureReason::Accounts: return "账户运行账本登记已满";
                case FailureReason::Scopes: return "凭据域登记已满";
                case FailureReason::InvalidCredential: return "凭据输入无效";
                case FailureReason::NotFound: return "凭据或账户不存在";
                case FailureReason::PolicyMismatch: return "账户策略版本不匹配";
                case FailureReason::VersionExhausted: return "账户策略版本耗尽";
                }
                return "账户操作失败";
            }
        };
        inline const AccountCategory AccountErrorCategory;
    }
    [[nodiscard]] inline auto MakeFailure(const FailureReason Reason) noexcept -> Fault::Failure
    {
        auto Code = Fault::Code::ResourceUnavailable;
        if (Reason == FailureReason::Revoked) { Code = Fault::Code::Forbidden; }
        else if (Reason == FailureReason::RateLimited) { Code = Fault::Code::WouldBlock; }
        else if (Reason == FailureReason::InvalidCredential) { Code = Fault::Code::InvalidArgument; }
        else if (Reason == FailureReason::NotFound) { Code = Fault::Code::AuthFailed; }
        else if (Reason == FailureReason::PolicyMismatch) { Code = Fault::Code::Blocked; }
        return {Code, std::error_code(static_cast<int>(Reason), Detail::AccountErrorCategory)};
    }
}
