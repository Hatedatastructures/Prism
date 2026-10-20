/**
 * @file Failure.cpp
 * @brief 账户错误类别与失败映射实现。
 */
#include <Prism/Account/Failure.hpp>

namespace Prism::Account::Detail
{
    auto AccountCategory::message(const int Value) const -> std::string
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
} // namespace Prism::Account::Detail

namespace Prism::Account
{
    auto MakeFailure(const FailureReason Reason) noexcept -> Fault::Failure
    {
        auto Code = Fault::Code::ResourceUnavailable;
        if (Reason == FailureReason::Revoked) { Code = Fault::Code::Forbidden; }
        else if (Reason == FailureReason::RateLimited) { Code = Fault::Code::WouldBlock; }
        else if (Reason == FailureReason::InvalidCredential) { Code = Fault::Code::InvalidArgument; }
        else if (Reason == FailureReason::NotFound) { Code = Fault::Code::AuthFailed; }
        else if (Reason == FailureReason::PolicyMismatch) { Code = Fault::Code::Blocked; }
        return {Code, std::error_code(static_cast<int>(Reason), Detail::AccountErrorCategory)};
    }
} // namespace Prism::Account
