/**
 * @file Encoder.hpp
 * @brief QPACK 头块编码器
 * @details 使用静态表值/名称引用和 Huffman 字面量编码；输出缓冲由
 *          调用方提供，短字段优先使用栈缓冲。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

#include <preview/Protocols/Http3/Detail/Varint.hpp>
#include <preview/Protocols/Http3/Huffman.hpp>
#include <preview/Protocols/Http3/StaticTable.hpp>

namespace Preview::Http3::Qpack
{

    namespace Detail
    {

        /**
         * @brief 写一个 Huffman 字符串（长度前缀 + 编码字节）
         * @param out 输出缓冲区
         * @param Offset 当前写入偏移
         * @param value 待写入字符串
         * @param PrefixBits 长度前缀位宽（3 或 7）
         * @param HuffFlag 长度前缀的模式位
         * @return 是否写入成功
         */
        [[nodiscard]] inline auto WriteStringPrefixed(std::span<std::uint8_t> out, std::size_t &Offset,
                                                        std::string_view value, std::uint8_t PrefixBits,
                                                        std::uint8_t HuffFlag) -> bool
        {
            std::array<std::uint8_t, 255> stack{};
            std::array<std::uint8_t, 16> LenBuf{};
            std::vector<std::uint8_t> heap;
            std::size_t EncN = 0;
            const std::uint8_t *EncData = nullptr;
            if (value.size() * 4 <= stack.size())
            {
                EncN = HuffmanEncodeTo(value, stack);
                if (EncN == 0 && !value.empty())
                {
                    return false;
                }
                EncData = stack.data();
            }
            else
            {
                if (!HuffmanEncodeImpl(value, heap))
                {
                    return false;
                }
                EncN = heap.size();
                EncData = heap.data();
            }
            const auto LenN = Detail::WriteVarint(LenBuf, PrefixBits, EncN, HuffFlag);
            if (LenN == 0 || out.size() < Offset + LenN + EncN)
            {
                return false;
            }
            std::memcpy(out.data() + Offset, LenBuf.data(), LenN);
            Offset += LenN;
            if (EncN > 0)
            {
                std::memcpy(out.data() + Offset, EncData, EncN);
                Offset += EncN;
            }
            return true;
        }

    } // namespace Detail

    /**
     * @brief 编码 QPACK 头块前缀
     * @param out 输出缓冲区
     * @return 写入字节数
     */
    [[nodiscard]] inline auto EncodePrefix(std::span<std::uint8_t> out) -> std::size_t
    {
        if (out.size() < 2)
        {
            return 0;
        }
        out[0] = 0x00;
        out[1] = 0x00;
        return 2;
    }

    /**
     * @brief 编码一个 QPACK 头字段
     * @param Name 字段名
     * @param value 字段值
     * @param out 输出缓冲区
     * @return 写入字节数；失败返回 0
     */
    [[nodiscard]] inline auto EncodeLiteral(std::string_view Name, std::string_view value,
                                             std::span<std::uint8_t> out) -> std::size_t
    {
        if (const auto *Entry = Detail::LookupEncoderName(Name))
        {
            for (std::size_t I = 0; I < Entry->ValueCount; ++I)
            {
                const auto &Value = Detail::EncoderValues[Entry->ValueOffset + I];
                if (Value.value == value)
                {
                    return Detail::WriteVarint(out, 6, Value.index, 0xC0);
                }
            }
            if (Entry->ValueCount == 0 && value.empty())
            {
                return Detail::WriteVarint(out, 6, Entry->FirstIndex, 0xC0);
            }
            std::size_t Offset = Detail::WriteVarint(out, 4, Entry->FirstIndex, 0x50);
            if (Offset == 0 || !Detail::WriteStringPrefixed(out, Offset, value, 7, 0x80))
            {
                return 0;
            }
            return Offset;
        }

        std::size_t Offset = 0;
        if (!Detail::WriteStringPrefixed(out, Offset, Name, 3, 0x20 | 0x08) ||
            !Detail::WriteStringPrefixed(out, Offset, value, 7, 0x80))
        {
            return 0;
        }
        return Offset;
    }

} // namespace Preview::Http3::Qpack
