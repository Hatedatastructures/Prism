/**
 * @file Credential.cpp
 * @brief 账户凭据验证与比较实现。
 */
#include <Prism/Account/Credential.hpp>

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace Prism::Account
{
    auto CredentialView::IsValid() const noexcept -> bool
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

    Credential::Credential(const CredentialKind Kind, SecureBytes Bytes)
        : Kind_(Kind), Bytes_(std::move(Bytes))
    {
        if (!View().IsValid())
        {
            throw std::invalid_argument("invalid account credential");
        }
    }

    auto Credential::ConstantTimeEqual(const CredentialView Left, const CredentialView Right) noexcept
        -> bool
    {
        const auto Length = (std::max)(Left.Size(), Right.Size());
        std::uint8_t Difference = static_cast<std::uint8_t>(Left.Kind() != Right.Kind());
        Difference = static_cast<std::uint8_t>(Difference | !Left.IsValid() | !Right.IsValid());
        Difference = static_cast<std::uint8_t>(Difference | (Left.Size() != Right.Size()));
        for (std::size_t Index = 0; Index < Length; ++Index)
        {
            std::uint8_t LeftByte = 0U, RightByte = 0U;
            if (Index < Left.Size()) { LeftByte = std::to_integer<std::uint8_t>(Left.Bytes()[Index]); }
            if (Index < Right.Size()) { RightByte = std::to_integer<std::uint8_t>(Right.Bytes()[Index]); }
            Difference = static_cast<std::uint8_t>(Difference | (LeftByte ^ RightByte));
        }
        return Difference == 0;
    }
} // namespace Prism::Account
