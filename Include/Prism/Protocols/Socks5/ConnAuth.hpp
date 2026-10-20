/**
 * @file ConnAuth.hpp
 * @brief SOCKS5 RFC1929 认证 owner
 * @details 解析用户名/密码子协商、调用协议认证器并持有认证产生的
 *          AccountLease。租约和身份状态随 Conn 生命周期存活。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

#include <Prism/Account/Credential.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Socks5/ConnTransport.hpp>

namespace Prism::Socks5
{

    /**
     * @class ConnAuth
     * @brief SOCKS5 用户名/密码认证状态和账户租约 owner
     * @tparam Memory 会话内存策略
     */
    template <Prism::Memory::Restrict Memory>
    class ConnAuth final
    {
    public:
        /**
         * @brief 读取 RFC1929 凭据并完成认证
         * @param Transport 已拥有底层连接和预读缓冲的传输 owner
         * @param Auth 唯一拥有认证器；只通过 typed Authenticate 取得租约。
         * @return 认证结果；读写失败为 IoError，凭据失败为 BadAuth
         */
        [[nodiscard]] auto UserpassAuth(
            ConnTransport<Memory> &Transport,
            const Prism::SharedAuthenticator& Auth)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            std::array<std::uint8_t, 2> Head{};
            const auto HeadRead = co_await Transport.ReadExact(std::span<std::uint8_t>(Head));
            if (HeadRead.Failure.Failed())
            {
                co_return std::unexpected(HeadRead.Failure);
            }
            if (Head[0] != 0x01)
            {
                co_return std::unexpected(
                    Prism::Protocol::Common::FailureFromProtocolError(Error::BadAuth));
            }

            std::vector<std::uint8_t> UserBytes(Head[1]);
            const auto UserRead = co_await Transport.ReadExact(UserBytes);
            if (UserRead.Failure.Failed())
            {
                co_return std::unexpected(UserRead.Failure);
            }
            std::array<std::uint8_t, 1> PasswordLength{};
            const auto PasswordLengthRead = co_await Transport.ReadExact(
                std::span<std::uint8_t>(PasswordLength));
            if (PasswordLengthRead.Failure.Failed())
            {
                co_return std::unexpected(PasswordLengthRead.Failure);
            }
            std::vector<std::uint8_t> PasswordBytes(PasswordLength[0]);
            const auto PasswordRead = co_await Transport.ReadExact(PasswordBytes);
            if (PasswordRead.Failure.Failed())
            {
                co_return std::unexpected(PasswordRead.Failure);
            }

            const std::string UserValue(UserBytes.begin(), UserBytes.end());
            const std::string PasswordValue(PasswordBytes.begin(), PasswordBytes.end());
            bool Authenticated = !UserValue.empty() && !PasswordValue.empty();
            Prism::Fault::Failure AuthenticationFailure = Authenticated
                ? Prism::Fault::Failure{}
                : Prism::Protocol::Common::FailureFromProtocolError(Error::BadAuth);
            if (Authenticated && Auth)
            {
                auto AuthenticationResult = Auth->Authenticate(
                    Prism::AuthenticationRequest{
                        .AccountId = {},
                        .Identity = UserValue,
                        .Credential = Prism::Account::CredentialView::Password(PasswordValue),
                        .Rate = {}});
                Authenticated = static_cast<bool>(AuthenticationResult);
                if (Authenticated)
                {
                    AuthLease_ = std::move(*AuthenticationResult);
                    AccountId_ = AuthLease_.AccountId();
                    Identity_ = std::string(AuthLease_.Identity());
                    DisplayIdentity_ = std::string(AuthLease_.DisplayIdentity());
                }
                else
                {
                    AuthenticationFailure = AuthenticationResult.error();
                    if (AuthenticationFailure.Code != Prism::Fault::Code::AuthFailed &&
                        !AuthenticationFailure.Native)
                    {
                        AuthenticationFailure =
                            Prism::Protocol::Common::FailureFromProtocolError(Error::BadAuth);
                    }
                }
            }
            else
            {
                Authenticated = false;
                AuthenticationFailure =
                    Prism::Protocol::Common::FailureFromProtocolError(Error::BadAuth);
            }

            const std::array<std::uint8_t, 2> Response{
                0x01, Authenticated ? std::uint8_t{0x00} : std::uint8_t{0x01}};
            const auto ResponseWrite = co_await Transport.SendBytes(Response);
            if (ResponseWrite.Failure.Failed())
            {
                if (AuthenticationFailure.Failed())
                    co_return std::unexpected(AuthenticationFailure);
                co_return std::unexpected(ResponseWrite.Failure);
            }
            if (!Authenticated)
            {
                co_return std::unexpected(AuthenticationFailure);
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        [[nodiscard]] auto TakeAuthLease() -> Prism::Account::AccountLease
        {
            return std::move(AuthLease_);
        }

        [[nodiscard]] auto AccountId() const noexcept -> Prism::AccountId
        {
            return AccountId_;
        }

        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        {
            return Identity_;
        }

        [[nodiscard]] auto DisplayIdentity() const noexcept -> std::string_view
        {
            return DisplayIdentity_;
        }

    private:
        Prism::Account::AccountLease AuthLease_{};
        Prism::AccountId AccountId_{};
        std::string Identity_{};
        std::string DisplayIdentity_{};
    };

} // namespace Prism::Socks5
