/**
 * @file Name.hpp
 * @brief DNS 压缩域名的固定容量、无分配读取原语。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

namespace Prism::Network::Dns::Detail
{
    /** @brief 拥有解压后的 DNS 名称；空名称表示根，借用只持续至值销毁或修改。 */
    struct DecodedName final
    {
        std::array<char, 253> Bytes{};
        std::size_t Size{0};

        [[nodiscard]] auto View() const & noexcept -> std::string_view
        {
            return {Bytes.data(), Size};
        }

        auto View() const && -> std::string_view = delete;
    };

    /** @brief 同步读取状态；所有偏移都属于借用的同一完整 DNS 报文。 */
    struct NameCursor final
    {
        std::span<const std::uint8_t> Data;
        std::size_t Offset{0};
    };

    /** @brief 压缩指针的有界跳转预算；向前和自引用指针直接拒绝。 */
    inline constexpr std::size_t MaxNameJumps = 128;

    /** @brief 追加一个标签，保留根名称并限制标签和完整展开名称的大小。 */
    [[nodiscard]] inline auto AppendLabel(DecodedName &Name,
                                           const std::span<const std::uint8_t> Label) noexcept -> bool
    {
        std::size_t Separator = 0;
        if (Name.Size != 0)
        {
            Separator = 1;
        }
        if (Label.empty() || Label.size() > 63 ||
            Label.size() + Separator > Name.Bytes.size() - Name.Size)
        {
            return false;
        }
        if (Separator != 0)
        {
            Name.Bytes[Name.Size++] = '.';
        }
        for (const auto Byte : Label)
        {
            if (Byte == 0 || Byte == '.' || Byte < 0x21 || Byte > 0x7E)
            {
                return false;
            }
            auto Character = static_cast<char>(Byte);
            if (Character >= 'A' && Character <= 'Z')
            {
                Character = static_cast<char>(Character + 'a' - 'A');
            }
            Name.Bytes[Name.Size++] = Character;
        }
        return true;
    }

    /**
     * @brief 读取完整域名；仅成功时推进原游标，无动态分配或异常。
     * @param Cursor 同步借用完整报文；输出拥有展开后的名字，不借用输入字节。
     * @return 越界、保留标签编码、过长名称、错误指针返回 ProtocolError。
     * @details 无 executor、取消或关闭资源；完整报文至少应包含当前名字的终结字节。
     */
    [[nodiscard]] inline auto ReadName(NameCursor &Cursor) noexcept
        -> std::expected<DecodedName, Fault::Failure>
    {
        const auto Invalid = std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
        auto Current = Cursor.Offset;
        auto Next = Cursor.Offset;
        std::size_t Jumps = 0;
        bool Jumped = false;
        DecodedName Name;
        while (Current < Cursor.Data.size())
        {
            const auto Length = Cursor.Data[Current];
            if ((Length & 0xC0u) == 0xC0u)
            {
                if (Cursor.Data.size() - Current < 2 || ++Jumps > MaxNameJumps)
                {
                    return Invalid;
                }
                const auto Destination = (static_cast<std::size_t>(Length & 0x3Fu) << 8) |
                                         Cursor.Data[Current + 1];
                if (Destination >= Current)
                {
                    return Invalid;
                }
                if (!Jumped)
                {
                    Next = Current + 2;
                    Jumped = true;
                }
                Current = Destination;
                continue;
            }
            if ((Length & 0xC0u) != 0)
            {
                return Invalid;
            }
            if (Length == 0)
            {
                if (!Jumped)
                {
                    Next = Current + 1;
                }
                Cursor.Offset = Next;
                return Name;
            }
            if (Cursor.Data.size() - Current - 1 < Length ||
                !AppendLabel(Name, Cursor.Data.subspan(Current + 1, Length)))
            {
                return Invalid;
            }
            Current += static_cast<std::size_t>(Length) + 1;
        }
        return Invalid;
    }
}
