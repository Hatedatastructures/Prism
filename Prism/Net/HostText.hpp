/** @file HostText.hpp @brief 固定容量的目标显示文本，禁止借用临时值跨越异步边界。 */
#pragma once
#include <Prism/Net/Host.hpp>
#include <charconv>
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
    [[nodiscard]] inline auto ToText(const Host& Input) noexcept -> HostText
    {
        HostText Result;
        auto* Cursor = Result.Bytes_.data();
        auto* End = Cursor + Result.Bytes_.size();
        if (const auto* Domain = std::get_if<DomainName>(&Input.Get()))
            Cursor = std::copy(Domain->View().begin(), Domain->View().end(), Cursor);
        else if (const auto* V4 = std::get_if<Ipv4Bytes>(&Input.Get()))
        {
            for (std::size_t Index = 0; Index < 4; ++Index)
            {
                if (Index != 0) *Cursor++ = '.';
                Cursor = std::to_chars(Cursor, End, V4->Bytes[Index]).ptr;
            }
        }
        else if (const auto* V6 = std::get_if<Ipv6Bytes>(&Input.Get()))
        {
            for (std::size_t Index = 0; Index < 16; Index += 2)
            {
                if (Index != 0) *Cursor++ = ':';
                const auto Word = static_cast<unsigned>(V6->Bytes[Index]) * 256U + V6->Bytes[Index + 1];
                Cursor = std::to_chars(Cursor, End, Word, 16).ptr;
            }
        }
        Result.Size_ = static_cast<std::size_t>(Cursor - Result.Bytes_.data());
        return Result;
    }
}
