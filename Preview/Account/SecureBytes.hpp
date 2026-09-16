/**
 * @file SecureBytes.hpp
 * @brief 账户秘密材料的受控字节存储
 * @details 所有权独占，析构前清零内容；公开描述只返回固定的脱敏文本。
 */
#pragma once

#include <cstddef>
#include <cstring>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace Preview::Account
{

    class SecureBytes final
    {
    public:
        SecureBytes() = default;

        explicit SecureBytes(std::string_view Value) : Bytes_(Value.size())
        {
            if (!Value.empty())
            {
                std::memcpy(Bytes_.data(), Value.data(), Value.size());
            }
        }

        explicit SecureBytes(std::span<const std::byte> Value) : Bytes_(Value.begin(), Value.end())
        {
        }

        ~SecureBytes()
        {
            Clear();
        }

        SecureBytes(const SecureBytes &) = delete;
        auto operator=(const SecureBytes &) -> SecureBytes & = delete;

        SecureBytes(SecureBytes &&Other) noexcept : Bytes_(std::move(Other.Bytes_))
        {
        }

        auto operator=(SecureBytes &&Other) noexcept -> SecureBytes &
        {
            if (this != &Other)
            {
                Clear();
                Bytes_ = std::move(Other.Bytes_);
            }
            return *this;
        }

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
        void Clear() noexcept
        {
            volatile std::byte *Data = Bytes_.data();
            for (std::size_t Index = 0; Index < Bytes_.size(); ++Index)
            {
                Data[Index] = std::byte{0};
            }
            Bytes_.clear();
        }

        std::vector<std::byte> Bytes_;
    };

} // namespace Preview::Account
