/**
 * @file SecureBytes.cpp
 * @brief 账户秘密材料的安全存储实现。
 */
#include <Prism/Account/SecureBytes.hpp>

#include <Prism/Foundation/Utility/Crypto/SecretScope.hpp>

#include <cstring>
#include <utility>

namespace Prism::Account
{
    SecureBytes::SecureBytes(const std::string_view Value) : Bytes_(Value.size())
    {
        if (!Value.empty())
        {
            std::memcpy(Bytes_.data(), Value.data(), Value.size());
        }
    }

    SecureBytes::SecureBytes(const std::span<const std::byte> Value)
        : Bytes_(Value.begin(), Value.end())
    {
    }

    SecureBytes::~SecureBytes()
    {
        Clear();
    }

    SecureBytes::SecureBytes(SecureBytes&& Other) noexcept : Bytes_(std::move(Other.Bytes_))
    {
    }

    auto SecureBytes::operator=(SecureBytes&& Other) noexcept -> SecureBytes&
    {
        if (this != &Other)
        {
            Clear();
            Bytes_ = std::move(Other.Bytes_);
        }
        return *this;
    }

    auto SecureBytes::Clear() noexcept -> void
    {
        const Crypto::SecretScope Cleanup(std::span(
            reinterpret_cast<std::uint8_t*>(Bytes_.data()), Bytes_.size()));
        Bytes_.clear();
    }
} // namespace Prism::Account
