/** @file Authenticator.hpp
 * @brief 已编译 scope 的唯一认证前门；成功事实只保存在仅可移动的租约或 Binding 中。
 */
#pragma once
#include <Prism/Account/Store.hpp>

#include <cstddef>
#include <memory>
#include <string_view>
#include <utility>
#include <expected>

namespace Prism
{
    using AuthenticationRequest = Account::AcquireRequest;
    using AuthenticationResult = std::expected<Account::AccountLease, Fault::Failure>;
    /** @brief 同步固定时间比较；不分配，不保存输入，所有秘密由各自材料owner管理。 */
    [[nodiscard]] auto ConstantTimeEqual(std::string_view Left, std::string_view Right) noexcept -> bool;
    /** @brief 输入只借用到同步返回，成功lease拥有所有事实；取消/额度/错误是Failure值。 */
    class Authenticator
    {
    public:
        virtual ~Authenticator() = default;
        [[nodiscard]] virtual auto InspectCredential(const Account::CredentialView& Credential) const noexcept -> std::expected<bool, Fault::Failure> = 0;
        [[nodiscard]] virtual auto Authenticate(const AuthenticationRequest& Request) const noexcept -> AuthenticationResult = 0;
    };
    /** @brief 冷装配时确定固定 scope 序号；热路径不等待目录版本，也不查找 realm 字符串。 */
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
