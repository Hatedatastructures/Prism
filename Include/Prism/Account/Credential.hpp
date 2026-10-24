/**
 * @file Credential.hpp
 * @brief 账户凭据视图与安全所有权
 * @details CredentialView 不拥有数据；Credential 通过 SecureBytes 持有材料。
 */
#pragma once

#include "SecureBytes.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace Prism::Account
{

    enum class CredentialKind : std::uint8_t
    {
        Unknown = 0,
        Password,
        Uuid,
        Psk,
        Token,
        Extension,
    };

    using UuidBytes = std::array<std::byte, 16>;

    class CredentialView final
    {
    public:
        CredentialView() = default;

        CredentialView(CredentialKind Kind, std::span<const std::byte> Bytes) noexcept
            : Kind_(Kind), Bytes_(Bytes)
        {
        }

        [[nodiscard]] static auto Password(std::string_view Value) noexcept -> CredentialView
        {
            return FromText(CredentialKind::Password, Value);
        }

        [[nodiscard]] static auto Uuid(const UuidBytes &Value) noexcept -> CredentialView
        {
            return {CredentialKind::Uuid, std::span<const std::byte>(Value)};
        }

        [[nodiscard]] static auto Psk(std::string_view Value) noexcept -> CredentialView
        {
            return FromText(CredentialKind::Psk, Value);
        }

        [[nodiscard]] static auto Token(std::string_view Value) noexcept -> CredentialView
        {
            return FromText(CredentialKind::Token, Value);
        }

        [[nodiscard]] static auto Extension(std::string_view Value) noexcept -> CredentialView
        {
            return FromText(CredentialKind::Extension, Value);
        }

        [[nodiscard]] auto Kind() const noexcept -> CredentialKind
        {
            return Kind_;
        }

        [[nodiscard]] auto Bytes() const noexcept -> std::span<const std::byte>
        {
            return Bytes_;
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Bytes_.size();
        }

        [[nodiscard]] auto IsValid() const noexcept -> bool;

        [[nodiscard]] auto Redacted() const noexcept -> std::string_view
        {
            return "[redacted]";
        }

    private:
        [[nodiscard]] static auto FromText(CredentialKind Kind, std::string_view Value) noexcept
            -> CredentialView
        {
            const auto *Data = reinterpret_cast<const std::byte *>(Value.data());
            return {Kind, std::span<const std::byte>(Data, Value.size())};
        }

        CredentialKind Kind_{CredentialKind::Unknown};
        std::span<const std::byte> Bytes_{};
    };

    class Credential final
    {
    public:
        Credential(CredentialKind Kind, SecureBytes Bytes);

        [[nodiscard]] static auto Password(std::string_view Value) -> Credential
        {
            return Credential(CredentialKind::Password, SecureBytes(Value));
        }

        [[nodiscard]] static auto Uuid(const UuidBytes &Value) -> Credential
        {
            return Credential(CredentialKind::Uuid, SecureBytes(std::span<const std::byte>(Value)));
        }

        [[nodiscard]] static auto Psk(std::string_view Value) -> Credential
        {
            return Credential(CredentialKind::Psk, SecureBytes(Value));
        }

        [[nodiscard]] static auto Token(std::string_view Value) -> Credential
        {
            return Credential(CredentialKind::Token, SecureBytes(Value));
        }

        [[nodiscard]] static auto Extension(std::string_view Value) -> Credential
        {
            return Credential(CredentialKind::Extension, SecureBytes(Value));
        }

        Credential(const Credential &) = delete;
        auto operator=(const Credential &) -> Credential & = delete;
        Credential(Credential &&) noexcept = default;
        auto operator=(Credential &&) noexcept -> Credential & = default;

        [[nodiscard]] auto Kind() const noexcept -> CredentialKind
        {
            return Kind_;
        }

        [[nodiscard]] auto View() const noexcept -> CredentialView
        {
            return {Kind_, Bytes_.View()};
        }

        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return View().IsValid();
        }

        [[nodiscard]] auto Matches(CredentialView Candidate) const noexcept -> bool
        {
            return ConstantTimeEqual(View(), Candidate);
        }

        [[nodiscard]] auto Redacted() const noexcept -> std::string_view
        {
            return Bytes_.Redacted();
        }

        [[nodiscard]] static auto ConstantTimeEqual(CredentialView Left, CredentialView Right) noexcept
            -> bool;

    private:
        CredentialKind Kind_;
        SecureBytes Bytes_;
    };

} // namespace Prism::Account
