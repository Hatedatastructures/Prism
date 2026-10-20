/** @file HostText.hpp @brief 固定容量的目标显示文本，禁止借用临时值跨越异步边界。 */
#pragma once
#include <Prism/Net/Host.hpp>
#include <array>
#include <cstddef>
#include <string_view>
namespace Prism::Network
{
    class HostText final
    {
    public:
        [[nodiscard]] auto View() const & noexcept -> std::string_view { return {Bytes_.data(), Size_}; }
        auto View() const && -> std::string_view = delete;
    private:
        friend auto ToText(const Host&) noexcept -> HostText;
        std::array<char, DomainName::Capacity> Bytes_{};
        std::size_t Size_{0};
    };
    /** @brief 同步生成拥有文本；IPv6 固定为八组十六进制，无堆分配且不参与解析决策。 */
    [[nodiscard]] auto ToText(const Host& Input) noexcept -> HostText;
}
