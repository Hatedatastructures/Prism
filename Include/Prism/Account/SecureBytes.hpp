/**
 * @file SecureBytes.hpp
 * @brief 账户秘密材料的受控字节存储
 * @details 所有权独占，析构前清零内容；公开描述只返回固定的脱敏文本。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace Prism::Account
{

    class SecureBytes final
    {
    public:
        SecureBytes() = default;

        explicit SecureBytes(std::string_view Value);

        explicit SecureBytes(std::span<const std::byte> Value);

        ~SecureBytes();

        SecureBytes(const SecureBytes &) = delete;
        auto operator=(const SecureBytes &) -> SecureBytes & = delete;

        SecureBytes(SecureBytes &&Other) noexcept;

        auto operator=(SecureBytes &&Other) noexcept -> SecureBytes &;

        [[nodiscard]] auto View() const noexcept -> std::span<const std::byte>
        {
            return Bytes_;
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Bytes_.size();
        }

        [[nodiscard]] auto Redacted() const noexcept -> std::string_view
        {
            return "[redacted]";
        }

    private:
        auto Clear() noexcept -> void;

        std::vector<std::byte> Bytes_;
    };

} // namespace Prism::Account
