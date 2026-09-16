/**
 * @file Authenticator.hpp
 * @brief 账户认证回调类型
 * @details 认证只消费值语义请求并返回带租约的结果；回调不拥有协议或 I/O
 *          对象，目录认证器仅持有调用方提供的目录指针。
 */
#pragma once

#include "Directory.hpp"

#include <Preview/Foundation/Authenticator.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>

namespace Preview::Account
{

    enum class AuthFailure : std::uint8_t
    {
        None = 0,
        Unavailable,
        NotFound,
        Revoked,
        ConnectionQuota,
        RateLimited,
        InvalidCredential,
    };

    struct AuthenticationRequest
    {
        CredentialView Credential;
        RateRequest Rate{};
    };

    struct AuthenticationResult
    {
        bool Accepted{false};
        Preview::AccountId AccountId;
        AccountLease Lease;
        AuthFailure Failure{AuthFailure::None};
    };

    using AuthenticatorCallback =
        std::function<AuthenticationResult(const AuthenticationRequest &)>;

    class DirectoryAuthenticator final
    {
    public:
        explicit DirectoryAuthenticator(const AccountDirectory *Directory) : Directory_(Directory)
        {
        }

        [[nodiscard]] auto Authenticate(const AuthenticationRequest &Request) const
            -> AuthenticationResult
        {
            AuthenticationResult Result;
            if (!Directory_)
            {
                Result.Failure = AuthFailure::Unavailable;
                return Result;
            }
            if (!Request.Credential.IsValid())
            {
                Result.Failure = AuthFailure::InvalidCredential;
                return Result;
            }

            auto Acquired = Directory_->TryAcquire(
                AccountDirectory::AcquireRequest{Request.Credential, Request.Rate});
            if (!Acquired)
            {
                Result.Failure = ToAuthFailure(Acquired.Failure);
                return Result;
            }

            Result.Accepted = true;
            Result.AccountId = Acquired.Record->AccountId();
            Result.Lease = std::move(Acquired.Lease);
            Result.Failure = AuthFailure::None;
            return Result;
        }

    private:
        [[nodiscard]] static auto ToAuthFailure(AcquireFailure Failure) noexcept -> AuthFailure
        {
            switch (Failure)
            {
            case AcquireFailure::NotFound:
                return AuthFailure::NotFound;
            case AcquireFailure::Revoked:
                return AuthFailure::Revoked;
            case AcquireFailure::ConnectionQuota:
                return AuthFailure::ConnectionQuota;
            case AcquireFailure::RateLimited:
                return AuthFailure::RateLimited;
            case AcquireFailure::InvalidCredential:
                return AuthFailure::InvalidCredential;
            case AcquireFailure::None:
                return AuthFailure::Unavailable;
            }
            return AuthFailure::Unavailable;
        }

        const AccountDirectory *Directory_{nullptr};
    };

    class Authenticator final
    {
    public:
        explicit Authenticator(AuthenticatorCallback Callback) : Callback_(std::move(Callback))
        {
        }

        [[nodiscard]] auto Authenticate(const AuthenticationRequest &Request) const
            -> AuthenticationResult
        {
            if (!Request.Credential.IsValid())
            {
                return AuthenticationResult{false, {}, {}, AuthFailure::InvalidCredential};
            }
            if (!Callback_)
            {
                return AuthenticationResult{false, {}, {}, AuthFailure::Unavailable};
            }
            auto Result = Callback_(Request);
            if (!Result.Accepted)
            {
                Result.AccountId = {};
                Result.Lease.Release();
                if (Result.Failure == AuthFailure::None)
                {
                    Result.Failure = AuthFailure::Unavailable;
                }
                return Result;
            }
            if (!Result.AccountId || !Result.Lease)
            {
                Result.Accepted = false;
                Result.AccountId = {};
                Result.Lease.Release();
                Result.Failure = AuthFailure::Unavailable;
            }
            else
            {
                Result.Failure = AuthFailure::None;
            }
            return Result;
        }

    private:
        AuthenticatorCallback Callback_;
    };

    /**
     * @class ProtocolAuthenticator
     * @brief 将 typed 账户目录桥接到旧协议构造边界
     * @details 协议头目前仍要求 Preview::Authenticator，但该桥只实现
     *          typed Authenticate；旧 Check 入口明确拒绝，不创建旧 Lease。
     */
    class ProtocolAuthenticator final : public Preview::Authenticator
    {
    public:
        explicit ProtocolAuthenticator(std::shared_ptr<const AccountDirectory> Directory)
            : Directory_(std::move(Directory))
        {
        }

        [[nodiscard]] auto Check(std::string_view, std::string_view) const
            -> Preview::AuthResult override
        {
            return {};
        }

        [[nodiscard]] auto Authenticate(const Preview::AuthenticationRequest &Request) const
            -> Preview::AuthenticationResult override
        {
            Preview::AuthenticationResult Result;
            if (!Directory_)
            {
                Result.Failure = Preview::AuthFailure::Unavailable;
                return Result;
            }

            auto Acquired = DirectoryAuthenticator(Directory_.get()).Authenticate(
                AuthenticationRequest{Request.Credential, Request.Rate});
            if (!Acquired.Accepted)
            {
                Result.Failure = ToProtocolFailure(Acquired.Failure);
                return Result;
            }

            Result.Accepted = true;
            Result.AccountId = Acquired.AccountId;
            Result.Lease = std::move(Acquired.Lease);
            Result.Identity = std::string(Request.Identity);
            if (Result.Identity.empty() &&
                Request.Credential.Kind() == Preview::Account::CredentialKind::Uuid)
            {
                constexpr char Hex[] = "0123456789abcdef";
                Result.Identity.reserve(Request.Credential.Size() * 2U);
                for (const auto Byte : Request.Credential.Bytes())
                {
                    const auto Value = std::to_integer<std::uint8_t>(Byte);
                    Result.Identity.push_back(Hex[(Value >> 4U) & 0x0fU]);
                    Result.Identity.push_back(Hex[Value & 0x0fU]);
                }
            }
            return Result;
        }

    private:
        [[nodiscard]] static auto ToProtocolFailure(AuthFailure Failure) noexcept
            -> Preview::AuthFailure
        {
            switch (Failure)
            {
            case AuthFailure::None:
                return Preview::AuthFailure::None;
            case AuthFailure::Unavailable:
                return Preview::AuthFailure::Unavailable;
            case AuthFailure::NotFound:
                return Preview::AuthFailure::NotFound;
            case AuthFailure::Revoked:
                return Preview::AuthFailure::Revoked;
            case AuthFailure::ConnectionQuota:
                return Preview::AuthFailure::ConnectionQuota;
            case AuthFailure::RateLimited:
                return Preview::AuthFailure::RateLimited;
            case AuthFailure::InvalidCredential:
                return Preview::AuthFailure::InvalidCredential;
            }
            return Preview::AuthFailure::Unavailable;
        }

        std::shared_ptr<const AccountDirectory> Directory_;
    };

} // namespace Preview::Account
