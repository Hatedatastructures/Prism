/** @file DomainName.hpp @brief 固定容量 DNS 名称，拥有规范化后的 ASCII 标签。 */
#pragma once
#include <Prism/Foundation/Fault/Failure.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string_view>
namespace Prism::Network
{
    /** @brief 同步值对象；输入只在 Parse 调用期借用，无 executor、取消或关闭资源。 */
    class DomainName final
    {
    public:
        static constexpr std::size_t Capacity = 253;
        [[nodiscard]] static auto Parse(std::string_view Text) noexcept
            -> std::expected<DomainName, Prism::Fault::Failure>;
        [[nodiscard]] auto View() const & noexcept -> std::string_view
        { return {Bytes_.data(), Size_}; }
        auto View() const && -> std::string_view = delete;
        auto operator==(const DomainName&) const -> bool = default;
    private:
        DomainName() = default;
        std::array<char, Capacity> Bytes_{};
        std::uint16_t Size_{0};
    };
}
