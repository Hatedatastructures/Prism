/**
 * @file Varint.hpp
 * @brief QPACK/HPACK 前缀整数编解码辅助
 * @details 只处理前缀整数，不持有 QPACK 表或连接状态。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace Preview::Http3::Qpack::Detail
{

    /**
     * @brief 解码前缀整数
     * @param In 输入字节
     * @param PrefixBits 前缀位宽
     * @param Value 输出整数
     * @param Consumed 输出消耗字节数
     * @return 是否解码成功
     */
    [[nodiscard]] inline auto ReadVarint(std::span<const std::uint8_t> In,
                                          std::uint8_t PrefixBits,
                                          std::uint64_t &Value,
                                          std::size_t &Consumed) -> bool
    {
        if (In.empty() || PrefixBits == 0 || PrefixBits > 8)
        {
            return false;
        }
        const std::uint64_t PrefixMask = (1ULL << PrefixBits) - 1;
        std::uint64_t Result = In[0] & PrefixMask;
        std::size_t Offset = 1;
        if (Result < PrefixMask)
        {
            Value = Result;
            Consumed = Offset;
            return true;
        }
        std::uint64_t Shift = 0;
        while (Offset < In.size())
        {
            const auto Byte = In[Offset++];
            const auto Chunk = static_cast<std::uint64_t>(Byte & 0x7F);
            if (Shift >= 64 || Chunk > (std::numeric_limits<std::uint64_t>::max() - Result) >> Shift)
            {
                return false;
            }
            Result += Chunk << Shift;
            if ((Byte & 0x80) == 0)
            {
                Value = Result;
                Consumed = Offset;
                return true;
            }
            Shift += 7;
            if (Shift >= 63)
            {
                return false;
            }
        }
        return false;
    }

    /**
     * @brief 编码前缀整数
     * @param Out 输出缓冲
     * @param PrefixBits 前缀位宽
     * @param Value 待编码整数
     * @param PrefixPattern 前缀模式
     * @return 写入字节数；缓冲不足返回 0
     */
    [[nodiscard]] inline auto WriteVarint(std::span<std::uint8_t> Out,
                                           std::uint8_t PrefixBits,
                                           std::uint64_t Value,
                                           std::uint8_t PrefixPattern) -> std::size_t
    {
        if (PrefixBits == 0 || PrefixBits > 8)
        {
            return 0;
        }
        const std::uint64_t PrefixMask = (1ULL << PrefixBits) - 1;
        std::size_t Count = 0;
        if (Value < PrefixMask)
        {
            if (Out.empty())
            {
                return 0;
            }
            Out[0] = static_cast<std::uint8_t>(PrefixPattern | Value);
            return 1;
        }
        if (Out.empty())
        {
            return 0;
        }
        Out[0] = static_cast<std::uint8_t>(PrefixPattern | PrefixMask);
        Count = 1;
        auto Rest = Value - PrefixMask;
        while (Rest >= 128)
        {
            if (Out.size() <= Count)
            {
                return 0;
            }
            Out[Count++] = static_cast<std::uint8_t>((Rest & 0x7F) | 0x80);
            Rest >>= 7;
        }
        if (Out.size() <= Count)
        {
            return 0;
        }
        Out[Count++] = static_cast<std::uint8_t>(Rest);
        return Count;
    }

} // namespace Preview::Http3::Qpack::Detail
