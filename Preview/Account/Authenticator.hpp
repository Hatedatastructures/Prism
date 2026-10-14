/** @file Authenticator.hpp
 * @brief 已编译scope的唯一认证前门，成功事实只保存在move-only lease/Binding。
 */
#pragma once
#include <Preview/Account/Store.hpp>
#include <algorithm>
#include <memory>
#include <string_view>
#include <expected>

namespace Preview
{
    using AuthenticationRequest = Account::AcquireRequest;
    using AuthenticationResult = std::expected<Account::AccountLease, Fault::Failure>;
    /** @brief 同步固定时间比较；不分配，不保存输入，所有秘密由各自材料owner管理。 */
    [[nodiscard]] inline auto ConstantTimeEqual(const std::string_view Left, const std::string_view Right) noexcept -> bool
    {
        auto Difference = static_cast<std::uint8_t>(Left.size() != Right.size());
        const auto Length = (std::max)(Left.size(), Right.size());
        for (std::size_t Index = 0U; Index < Length; ++Index)
        {
            std::uint8_t A = 0U, B = 0U;
            if (Index < Left.size()) { A = static_cast<std::uint8_t>(Left[Index]); }
            if (Index < Right.size()) { B = static_cast<std::uint8_t>(Right[Index]); }
            Difference = static_cast<std::uint8_t>(Difference | (A ^ B));
        }
        return Difference == 0U;
    }
    /** @brief 输入只借用到同步返回，成功lease拥有所有事实；取消/额度/错误是Failure值。 */
    class Authenticator
    {
    public:
        virtual ~Authenticator() = default;
        [[nodiscard]] virtual auto InspectCredential(const Account::CredentialView& Credential) const noexcept -> std::expected<bool, Fault::Failure> = 0;
        [[nodiscard]] virtual auto Authenticate(const AuthenticationRequest& Request) const noexcept -> AuthenticationResult = 0;
    };
    /** @brief 冷装配得到固定scope ordinal，热没有目录版本忙等或realm字符串查找。 */
    class DirectoryAuthenticator final : public Authenticator
    {
    public:
        explicit DirectoryAuthenticator(Account::CredentialIndexView View) noexcept : View_(std::move(View)) {}
        [[nodiscard]] auto InspectCredential(const Account::CredentialView& Credential) const noexcept -> std::expected<bool, Fault::Failure> override
        { return View_.InspectCredential(Credential); }
        [[nodiscard]] auto Authenticate(const AuthenticationRequest& Request) const noexcept -> AuthenticationResult override
        { return View_.TryAcquire(Request); }
    private:
        Account::CredentialIndexView View_;
    };
    class RejectAuthenticator final : public Authenticator
    {
    public:
        [[nodiscard]] auto InspectCredential(const Account::CredentialView&) const noexcept -> std::expected<bool, Fault::Failure> override { return false; }
        [[nodiscard]] auto Authenticate(const AuthenticationRequest&) const noexcept -> AuthenticationResult override
        { return std::unexpected(Fault::Failure{Fault::Code::AuthFailed}); }
    };
    using SharedAuthenticator = std::shared_ptr<Authenticator>;
}
