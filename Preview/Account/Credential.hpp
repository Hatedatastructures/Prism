/**
 * @file Credential.hpp
 * @brief 账户凭据视图与安全所有权
 * @details CredentialView 不拥有数据；Credential 通过 SecureBytes 持有材料。
 */
#pragma once

#include "SecureBytes.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace Preview::Account
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

        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            switch (Kind_)
            {
            case CredentialKind::Password:
            case CredentialKind::Psk:
            case CredentialKind::Token:
            case CredentialKind::Extension:
                return !Bytes_.empty();
            case CredentialKind::Uuid:
                return Bytes_.size() == UuidBytes{}.size();
            case CredentialKind::Unknown:
                return false;
            }
            return false;
        }

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
        Credential(CredentialKind Kind, SecureBytes Bytes)
            : Kind_(Kind), Bytes_(std::move(Bytes))
        {
            if (!View().IsValid())
            {
                throw std::invalid_argument("invalid account credential");
            }
        }

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
            -> bool
        {
            const auto Length = (std::max)(Left.Size(), Right.Size());
            std::uint8_t Difference = static_cast<std::uint8_t>(Left.Kind() != Right.Kind());
            Difference = static_cast<std::uint8_t>(Difference | !Left.IsValid() | !Right.IsValid());
            Difference = static_cast<std::uint8_t>(Difference | (Left.Size() != Right.Size()));
            for (std::size_t Index = 0; Index < Length; ++Index)
            {
                const auto LeftByte = Index < Left.Size()
                                          ? std::to_integer<std::uint8_t>(Left.Bytes()[Index])
                                          : std::uint8_t{0};
                const auto RightByte = Index < Right.Size()
                                           ? std::to_integer<std::uint8_t>(Right.Bytes()[Index])
                                           : std::uint8_t{0};
                Difference = static_cast<std::uint8_t>(Difference | (LeftByte ^ RightByte));
            }
            return Difference == 0;
        }

    private:
        CredentialKind Kind_;
        SecureBytes Bytes_;
    };

} // namespace Preview::Account
