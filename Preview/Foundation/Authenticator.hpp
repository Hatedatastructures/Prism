/**
 * @file Authenticator.hpp
 * @brief Preview 运行时认证契约
 * @details 运行时认证使用值语义请求和 Preview::Account::AccountLease。
 *          旧 Check 接口仅保留给纯 codec/旧测试入口，不参与新协议运行时。
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <Preview/Account/Directory.hpp>
#include <Preview/Foundation/Utility/Account/Directory.hpp>

namespace Preview
{

    /** @brief Foundation 层 typed 认证失败原因。 */
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

    /**
     * @class LegacyAuthLease
     * @brief 旧 Check 结果的兼容容器
     * @details 仅为未迁移的纯 codec 调用方提供 emplace；新 runtime 结果不使用该类型。
     */
    class LegacyAuthLease final
    {
    public:
        LegacyAuthLease() = default;

        LegacyAuthLease(const LegacyAuthLease &) = delete;
        auto operator=(const LegacyAuthLease &) -> LegacyAuthLease & = delete;
        LegacyAuthLease(LegacyAuthLease &&) noexcept = default;
        auto operator=(LegacyAuthLease &&) noexcept -> LegacyAuthLease & = default;

        void emplace(Preview::Account::Lease Value)
        {
            Legacy_ = std::move(Value);
        }

        [[nodiscard]] explicit operator bool() const noexcept
        {
            return static_cast<bool>(Typed_) || static_cast<bool>(Legacy_);
        }

        /** @brief 仅允许旧结果向新的 typed 结果移动，旧租约在转换时释放。 */
        operator Preview::Account::AccountLease() && noexcept
        {
            Legacy_.reset();
            return std::move(Typed_);
        }

    private:
        Preview::Account::AccountLease Typed_{};
        std::optional<Preview::Account::Lease> Legacy_{};
    };

    /**
     * @brief 对两个字节序列执行不依赖内容的比较
     * @param Left 左侧字节序列
     * @param Right 右侧字节序列
     * @return 长度和内容均相同返回 true
     * @details 比较完整的较长序列，不在第一个差异处提前返回，支持二进制凭据。
     */
    [[nodiscard]] inline auto ConstantTimeEqual(std::string_view Left, std::string_view Right) noexcept
        -> bool
    {
        const auto Length = (std::max)(Left.size(), Right.size());
        std::uint8_t Difference = static_cast<std::uint8_t>(Left.size() != Right.size());
        for (std::size_t I = 0; I < Length; ++I)
        {
            const auto L = I < Left.size()
                               ? static_cast<std::uint8_t>(static_cast<unsigned char>(Left[I]))
                               : std::uint8_t{0};
            const auto R = I < Right.size()
                               ? static_cast<std::uint8_t>(static_cast<unsigned char>(Right[I]))
                               : std::uint8_t{0};
            Difference = static_cast<std::uint8_t>(Difference | (L ^ R));
        }
        return Difference == 0;
    }

    /**
     * @struct AuthResult
     * @brief 旧纯 codec 认证结果
     * @details 该结果只服务旧 Check 调用方；新运行时必须使用 AuthenticationResult。
     */
    struct AuthResult
    {
        bool Ok{false};
        std::string Identity{};
        LegacyAuthLease Lease{};
    };

    /**
     * @struct AuthenticationRequest
     * @brief Preview 运行时认证请求
     * @details Credential 只借用握手缓冲；认证器在调用期间消费它，不保存视图。
     */
    struct AuthenticationRequest
    {
        Preview::AccountId AccountId{};
        std::string_view Identity{};
        Preview::Account::CredentialView Credential{};
        Preview::Account::RateRequest Rate{};
    };

    /**
     * @struct AuthenticationResult
     * @brief Preview 运行时认证结果
     * @details 租约为唯一运行时账户配额所有权，移动到协议/会话边界后由该边界释放。
     */
    struct AuthenticationResult
    {
        bool Accepted{false};
        Preview::AccountId AccountId{};
        Preview::Account::AccountLease Lease{};
        std::string Identity{};
        Preview::AuthFailure Failure{Preview::AuthFailure::None};
    };

    /**
     * @class Authenticator
     * @brief 协议认证器抽象接口
     * @details 新协议必须调用 Authenticate。Check 仅为旧纯 codec 测试保留。
     */
    class Authenticator
    {
    public:
        virtual ~Authenticator() = default;

        /**
         * @brief 旧字符串认证入口
         * @param Identity 非敏感身份文本
         * @param Secret 旧 codec 凭据文本
         * @return 旧认证结果
         */
        [[nodiscard]] virtual auto Check(std::string_view Identity, std::string_view Secret) const
            -> AuthResult = 0;

        /**
         * @brief 值语义运行时认证入口
         * @param Request typed 认证请求
         * @return 新账户模型认证结果
         * @note 默认实现只兼容旧 Check，不能产生 AccountLease；新目录认证器应覆盖它。
         */
        [[nodiscard]] virtual auto Authenticate(const AuthenticationRequest &Request) const
            -> AuthenticationResult
        {
            AuthenticationResult Result;
            if (!Request.Credential.IsValid())
            {
                Result.Failure = Preview::AuthFailure::InvalidCredential;
                return Result;
            }
            const auto Bytes = Request.Credential.Bytes();
            const std::string_view Secret(reinterpret_cast<const char *>(Bytes.data()), Bytes.size());
            const auto Legacy = Check(Request.Identity, Secret);
            if (!Legacy.Ok)
            {
                Result.Failure = Preview::AuthFailure::NotFound;
                return Result;
            }
            Result.Accepted = true;
            Result.AccountId = Request.AccountId;
            Result.Identity = Legacy.Identity;
            return Result;
        }
    };

    /**
     * @class DirectoryAuthenticator
     * @brief 新账户目录认证器适配
     * @details 目录只接收 CredentialView，成功后返回 AccountId 和 AccountLease。
     */
    class DirectoryAuthenticator final : public Authenticator
    {
    public:
        explicit DirectoryAuthenticator(const Preview::Account::AccountDirectory *Directory)
            : Directory_(Directory)
        {
        }

        [[nodiscard]] auto Check(std::string_view Identity, std::string_view Secret) const
            -> AuthResult override
        {
            auto Result = Authenticate(AuthenticationRequest{
                .AccountId = {},
                .Identity = Identity,
                .Credential = Preview::Account::CredentialView::Password(Secret),
                .Rate = {}});
            if (!Result.Accepted)
            {
                return {};
            }
            return AuthResult{true, std::move(Result.Identity), {}};
        }

        [[nodiscard]] auto Authenticate(const AuthenticationRequest &Request) const
            -> AuthenticationResult override
        {
            AuthenticationResult Result;
            if (!Directory_)
            {
                Result.Failure = Preview::AuthFailure::Unavailable;
                return Result;
            }
            if (!Request.Credential.IsValid())
            {
                Result.Failure = Preview::AuthFailure::InvalidCredential;
                return Result;
            }

            auto Acquired = Directory_->TryAcquire(
                Preview::Account::AccountDirectory::AcquireRequest{Request.Credential, Request.Rate});
            if (!Acquired)
            {
                Result.Failure = ToAuthFailure(Acquired.Failure);
                return Result;
            }

            Result.Accepted = true;
            Result.AccountId = Acquired.Record->AccountId();
            Result.Identity = std::string(Request.Identity);
            Result.Lease = std::move(Acquired.Lease);
            return Result;
        }

    private:
        [[nodiscard]] static auto ToAuthFailure(Preview::Account::AcquireFailure Failure) noexcept
            -> Preview::AuthFailure
        {
            switch (Failure)
            {
            case Preview::Account::AcquireFailure::NotFound:
                return Preview::AuthFailure::NotFound;
            case Preview::Account::AcquireFailure::Revoked:
                return Preview::AuthFailure::Revoked;
            case Preview::Account::AcquireFailure::ConnectionQuota:
                return Preview::AuthFailure::ConnectionQuota;
            case Preview::Account::AcquireFailure::RateLimited:
                return Preview::AuthFailure::RateLimited;
            case Preview::Account::AcquireFailure::InvalidCredential:
                return Preview::AuthFailure::InvalidCredential;
            case Preview::Account::AcquireFailure::None:
                return Preview::AuthFailure::Unavailable;
            }
            return Preview::AuthFailure::Unavailable;
        }

        const Preview::Account::AccountDirectory *Directory_{nullptr};
    };

    /**
     * @class StaticAuthenticator
     * @brief 静态认证器
     * @details 旧入口比较 identity + Secret；typed 入口比较 identity 和 CredentialView 字节。
     */
    class StaticAuthenticator final : public Authenticator
    {
    public:
        explicit StaticAuthenticator(std::string Identity, std::string Secret)
            : Identity_(std::move(Identity)), Secret_(std::move(Secret))
        {
        }

        [[nodiscard]] auto Check(std::string_view Identity, std::string_view Secret) const
            -> AuthResult override
        {
            if (!ConstantTimeEqual(Identity, Identity_) || !ConstantTimeEqual(Secret, Secret_))
            {
                return {};
            }
            return AuthResult{true, std::string(Identity), {}};
        }

        [[nodiscard]] auto Authenticate(const AuthenticationRequest &Request) const
            -> AuthenticationResult override
        {
            AuthenticationResult Result;
            if (!Request.Credential.IsValid())
            {
                Result.Failure = Preview::AuthFailure::InvalidCredential;
                return Result;
            }
            const auto IdentityMatches = Identity_.empty() || ConstantTimeEqual(Request.Identity, Identity_);
            const auto Bytes = Request.Credential.Bytes();
            const std::string_view Secret(reinterpret_cast<const char *>(Bytes.data()), Bytes.size());
            if (!IdentityMatches || !ConstantTimeEqual(Secret, Secret_))
            {
                Result.Failure = Preview::AuthFailure::NotFound;
                return Result;
            }
            Result.Accepted = true;
            Result.AccountId = Request.AccountId;
            Result.Identity = std::string(Request.Identity);
            return Result;
        }

    private:
        std::string Identity_;
        std::string Secret_;
    };

    /**
     * @class RejectAuthenticator
     * @brief 总是拒绝的认证器
     */
    class RejectAuthenticator final : public Authenticator
    {
    public:
        [[nodiscard]] auto Check(std::string_view, std::string_view) const -> AuthResult override
        {
            return {};
        }

        [[nodiscard]] auto Authenticate(const AuthenticationRequest &) const
            -> AuthenticationResult override
        {
            AuthenticationResult Result;
            Result.Failure = Preview::AuthFailure::NotFound;
            return Result;
        }
    };

    /// 认证器共享指针（持有者负责生命周期）
    using SharedAuthenticator = std::shared_ptr<Authenticator>;

} // namespace Preview
