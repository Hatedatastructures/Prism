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

#include <Preview/Protocols/Http3/Detail/Varint.hpp>
#include <Preview/Protocols/Http3/Huffman.hpp>
#include <Preview/Protocols/Http3/StaticTable.hpp>

namespace Preview::Http3::Qpack
{

    namespace Detail
    {

        struct EncoderBuffer
        {
            explicit EncoderBuffer(std::span<std::uint8_t> OutputValue)
                : Output(OutputValue)
            {
            }

            [[nodiscard]] auto AppendVarint(
                std::uint64_t Value,
                std::uint8_t PrefixBits,
                std::uint8_t PrefixPattern) -> bool
            {
                std::array<std::uint8_t, 16> Encoded{};
                const auto EncodedLength = Detail::WriteVarint(
                    Encoded,
                    PrefixBits,
                    Value,
                    PrefixPattern);
                if (EncodedLength == 0 || Offset > Output.size() ||
                    EncodedLength > Output.size() - Offset)
                {
                    return false;
                }
                std::memcpy(Output.data() + Offset, Encoded.data(), EncodedLength);
                Offset += EncodedLength;
                return true;
            }

            [[nodiscard]] auto AppendString(
                std::string_view Value,
                std::uint8_t PrefixBits,
                std::uint8_t HuffFlag) -> bool
            {
                std::array<std::uint8_t, 255> Stack{};
                std::array<std::uint8_t, 16> LengthBuffer{};
                std::vector<std::uint8_t> Heap;
                std::size_t EncodedLength = 0;
                const std::uint8_t *EncodedData = nullptr;
                if (Value.size() <= Stack.size() / 4)
                {
                    EncodedLength = HuffmanEncodeTo(Value, Stack);
                    if (EncodedLength == 0 && !Value.empty())
                    {
                        return false;
                    }
                    EncodedData = Stack.data();
                }
                else
                {
                    if (!HuffmanEncodeImpl(Value, Heap))
                    {
                        return false;
                    }
                    EncodedLength = Heap.size();
                    EncodedData = Heap.data();
                }
                const auto LengthPrefix = Detail::WriteVarint(
                    LengthBuffer,
                    PrefixBits,
                    EncodedLength,
                    HuffFlag);
                if (LengthPrefix == 0 || Offset > Output.size() ||
                    LengthPrefix > Output.size() - Offset ||
                    EncodedLength > Output.size() - Offset - LengthPrefix)
                {
                    return false;
                }
                std::memcpy(Output.data() + Offset, LengthBuffer.data(), LengthPrefix);
                Offset += LengthPrefix;
                if (EncodedLength > 0)
                {
                    std::memcpy(Output.data() + Offset, EncodedData, EncodedLength);
                    Offset += EncodedLength;
                }
                return true;
            }

            std::span<std::uint8_t> Output;
            std::size_t Offset{0};
        };

    } // namespace Detail

    /**
     * @brief 编码 QPACK 头块前缀
     * @param Output 输出缓冲区
     * @return 写入字节数
     */
    [[nodiscard]] inline auto EncodePrefix(std::span<std::uint8_t> Output) -> std::size_t
    {
        if (Output.size() < 2)
        {
            return 0;
        }
        Output[0] = 0x00;
        Output[1] = 0x00;
        return 2;
    }

    /**
     * @brief 编码一个 QPACK 头字段
     * @param Name 字段名
     * @param Value 字段值
     * @param Output 输出缓冲区
     * @return 写入字节数；失败返回 0
     */
    [[nodiscard]] inline auto EncodeLiteral(
        std::string_view Name,
        std::string_view Value,
        std::span<std::uint8_t> Output) -> std::size_t
    {
        Detail::EncoderBuffer Encoder(Output);
        if (const auto *Entry = Detail::LookupEncoderName(Name))
        {
            for (std::size_t I = 0; I < Entry->ValueCount; ++I)
            {
                const auto &StaticValue = Detail::EncoderValues[Entry->ValueOffset + I];
                if (StaticValue.value == Value)
                {
                    if (!Encoder.AppendVarint(StaticValue.index, 6, 0xC0))
                    {
                        return 0;
                    }
                    return Encoder.Offset;
                }
            }
            if (Entry->ValueCount == 0 && Value.empty())
            {
                if (!Encoder.AppendVarint(Entry->FirstIndex, 6, 0xC0))
                {
                    return 0;
                }
                return Encoder.Offset;
            }
            if (!Encoder.AppendVarint(Entry->FirstIndex, 4, 0x50) ||
                !Encoder.AppendString(Value, 7, 0x80))
            {
                return 0;
            }
            return Encoder.Offset;
        }

        if (!Encoder.AppendString(Name, 3, 0x20 | 0x08) ||
            !Encoder.AppendString(Value, 7, 0x80))
        {
            return 0;
        }
        return Encoder.Offset;
    }

} // namespace Preview::Http3::Qpack
