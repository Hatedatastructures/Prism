/**
 * @file Http3Codec.cpp
 * @brief QPACK 编码、解码与 wire 解析实现。
 */
#include <Prism/Protocols/Http3/Decoder.hpp>
#include <Prism/Protocols/Http3/Encoder.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Prism/Protocols/Http3/Detail/Varint.hpp>
#include <Prism/Protocols/Http3/HeaderLimits.hpp>
#include "Detail/StaticTable.hpp"
#include <Prism/Protocols/HttpCompression/Huffman.hpp>
#include <Prism/Foundation/Memory/Container.hpp>

namespace Prism::Http3::Qpack
{
    namespace Detail
    {
        [[nodiscard]] auto ReadVarint(
            std::span<const std::uint8_t> Input,
            std::uint8_t PrefixBits) -> std::optional<DecodedInteger>
        {
            if (Input.empty() || PrefixBits == 0 || PrefixBits > 8)
            {
                return std::nullopt;
            }
            const std::uint64_t PrefixMask = (1ULL << PrefixBits) - 1;
            std::uint64_t Result = Input[0] & PrefixMask;
            std::size_t Offset = 1;
            if (Result < PrefixMask)
            {
                return DecodedInteger{Result, Offset};
            }
            std::uint64_t Shift = 0;
            while (Offset < Input.size())
            {
                const auto Byte = Input[Offset++];
                const auto Chunk = static_cast<std::uint64_t>(Byte & 0x7F);
                if (Shift >= 64 || Chunk > (std::numeric_limits<std::uint64_t>::max() - Result) >> Shift)
                {
                    return std::nullopt;
                }
                Result += Chunk << Shift;
                if ((Byte & 0x80) == 0)
                {
                    return DecodedInteger{Result, Offset};
                }
                Shift += 7;
                if (Shift > 63)
                {
                    return std::nullopt;
                }
            }
            return std::nullopt;
        }

        [[nodiscard]] auto WriteVarint(
            std::span<std::uint8_t> Output,
            EncodedInteger Integer) -> std::size_t
        {
            const auto PrefixBits = Integer.PrefixBits;
            const auto Value = Integer.Value;
            const auto PrefixPattern = Integer.PrefixPattern;
            if (PrefixBits == 0 || PrefixBits > 8)
            {
                return 0;
            }
            const std::uint64_t PrefixMask = (1ULL << PrefixBits) - 1;
            if ((static_cast<std::uint64_t>(PrefixPattern) & PrefixMask) != 0)
            {
                return 0;
            }
            std::size_t Count = 0;
            if (Value < PrefixMask)
            {
                if (Output.empty())
                {
                    return 0;
                }
                Output[0] = static_cast<std::uint8_t>(PrefixPattern | Value);
                return 1;
            }
            if (Output.empty())
            {
                return 0;
            }
            Output[0] = static_cast<std::uint8_t>(PrefixPattern | PrefixMask);
            Count = 1;
            auto Rest = Value - PrefixMask;
            while (Rest >= 128)
            {
                if (Output.size() <= Count)
                {
                    return 0;
                }
                Output[Count++] = static_cast<std::uint8_t>((Rest & 0x7F) | 0x80);
                Rest >>= 7;
            }
            if (Output.size() <= Count)
            {
                return 0;
            }
            Output[Count++] = static_cast<std::uint8_t>(Rest);
            return Count;
        }

        /**
         * @brief 解析字面量名称
         * @param Input 输入字节序列
         * @param Offset 当前解析偏移（退出时已前进）
         * @param Output 解析出的名称
         * @return 是否解析成功
         */
        [[nodiscard]] auto ParseName(
            std::span<const std::uint8_t> Input,
            std::size_t &Offset,
            std::string &Output) -> bool
        {
            if (Offset >= Input.size())
            {
                return false;
            }
            const bool Huffman = (Input[Offset] & 0x08) != 0;
            const auto Integer = ReadVarint(Input.subspan(Offset), 3);
            if (!Integer)
            {
                return false;
            }
            Offset += Integer->Consumed;
            const auto Length = Integer->Value;
            if (Length > Input.size() - Offset)
            {
                return false;
            }
            if (Length > HeaderLimits::MaxFieldBytes)
            {
                return false;
            }
            std::array<std::uint8_t, 255> stack{};
            if (Huffman)
            {
                std::size_t Estimate = stack.size() + 1;
                if (Length <= stack.size() / 2)
                {
                    Estimate = static_cast<std::size_t>(Length) * 2;
                }
                if (Estimate <= stack.size())
                {
                    std::size_t OutputLength = 0;
                    if (!Prism::HttpCompression::HuffmanDecodeTo(
                            Input.subspan(Offset, static_cast<std::size_t>(Length)),
                            stack,
                            OutputLength))
                    {
                        return false;
                    }
                    if (OutputLength > HeaderLimits::MaxFieldBytes)
                    {
                        return false;
                    }
                    Offset += static_cast<std::size_t>(Length);
                    Output.assign(reinterpret_cast<const char *>(stack.data()), OutputLength);
                    return true;
                }
                std::vector<std::uint8_t> Heap;
                if (!Prism::HttpCompression::HuffmanDecode(
                        Input.subspan(Offset, static_cast<std::size_t>(Length)),
                        Heap))
                {
                    return false;
                }
                if (Heap.size() > HeaderLimits::MaxFieldBytes)
                {
                    return false;
                }
                Offset += static_cast<std::size_t>(Length);
                Output.assign(reinterpret_cast<const char *>(Heap.data()), Heap.size());
                return true;
            }
            Offset += static_cast<std::size_t>(Length);
            Output.assign(
                reinterpret_cast<const char *>(Input.data() + Offset - static_cast<std::ptrdiff_t>(Length)),
                static_cast<std::size_t>(Length));
            return true;
        }

        /**
         * @brief 解析字面量值
         * @param Input 输入字节序列
         * @param Offset 当前解析偏移（退出时已前进）
         * @param Output 解析出的值
         * @return 是否解析成功
         */
        [[nodiscard]] auto ParseValue(
            std::span<const std::uint8_t> Input,
            std::size_t &Offset,
            std::string &Output) -> bool
        {
            if (Offset >= Input.size())
            {
                return false;
            }
            const bool Huffman = (Input[Offset] & 0x80) != 0;
            const auto Integer = ReadVarint(Input.subspan(Offset), 7);
            if (!Integer)
            {
                return false;
            }
            Offset += Integer->Consumed;
            const auto Length = Integer->Value;
            if (Length > Input.size() - Offset)
            {
                return false;
            }
            if (Length > HeaderLimits::MaxFieldBytes)
            {
                return false;
            }
            std::array<std::uint8_t, 255> stack{};
            if (Huffman)
            {
                std::size_t Estimate = stack.size() + 1;
                if (Length <= stack.size() / 2)
                {
                    Estimate = static_cast<std::size_t>(Length) * 2;
                }
                if (Estimate <= stack.size())
                {
                    std::size_t OutputLength = 0;
                    if (!Prism::HttpCompression::HuffmanDecodeTo(
                            Input.subspan(Offset, static_cast<std::size_t>(Length)),
                            stack,
                            OutputLength))
                    {
                        return false;
                    }
                    if (OutputLength > HeaderLimits::MaxFieldBytes)
                    {
                        return false;
                    }
                    Offset += static_cast<std::size_t>(Length);
                    Output.assign(reinterpret_cast<const char *>(stack.data()), OutputLength);
                    return true;
                }
                std::vector<std::uint8_t> Heap;
                if (!Prism::HttpCompression::HuffmanDecode(
                        Input.subspan(Offset, static_cast<std::size_t>(Length)),
                        Heap))
                {
                    return false;
                }
                if (Heap.size() > HeaderLimits::MaxFieldBytes)
                {
                    return false;
                }
                Offset += static_cast<std::size_t>(Length);
                Output.assign(reinterpret_cast<const char *>(Heap.data()), Heap.size());
                return true;
            }
            Offset += static_cast<std::size_t>(Length);
            Output.assign(
                reinterpret_cast<const char *>(Input.data() + Offset - static_cast<std::ptrdiff_t>(Length)),
                static_cast<std::size_t>(Length));
            return true;
        }

    } // namespace Detail

    auto Detail::LookupEncoderName(const std::string_view Name)
        -> const Detail::EncoderNameEntry *
    {
        for (const auto &Entry : Detail::EncoderNames)
        {
            if (Entry.Name == Name)
            {
                return &Entry;
            }
        }
        return nullptr;
    }

    /**
     * @brief 解码一个 QPACK 头块
     * @param Data 编码数据（不含 HTTP/3 帧头）
     * @param MemoryResource 内存资源
     * @return 解码出的头字段列表；失败返回空
     */
    [[nodiscard]] auto DecodeHeaderBlock(
        std::span<const std::uint8_t> Data,
        const Prism::Memory::ResourcePointer MemoryResource)
        -> Prism::Memory::Vector<HeaderField>
    {
        Prism::Memory::Vector<HeaderField> Fields(MemoryResource);
        if (Data.size() > HeaderLimits::MaxHeaderSectionBytes)
        {
            return Fields;
        }
        Fields.reserve(8);
        const auto Fail = [&]() -> Prism::Memory::Vector<HeaderField>
        {
            Fields.clear();
            return std::move(Fields);
        };
        std::size_t Offset = 0;
        const auto RequiredCount = Detail::ReadVarint(Data.subspan(Offset), 8);
        if (!RequiredCount)
        {
            return Fail();
        }
        Offset += RequiredCount->Consumed;
        if (RequiredCount->Value != 0)
        {
            return Fail();
        }

        if (Offset > Data.size())
        {
            return Fail();
        }
        const auto Base = Detail::ReadVarint(Data.subspan(Offset), 7);
        if (!Base)
        {
            return Fail();
        }
        Offset += Base->Consumed;
        if (Base->Value != 0)
        {
            return Fail();
        }

        while (Offset < Data.size())
        {
            if (Fields.size() >= HeaderLimits::MaxHeaderFields)
            {
                return Fail();
            }
            const auto First = Data[Offset];
            if ((First & 0x80) != 0)
            {
                if ((First & 0x40) == 0)
                {
                    return Fail();
                }
                const auto Index = Detail::ReadVarint(Data.subspan(Offset), 6);
                if (!Index)
                {
                    return Fail();
                }
                Offset += Index->Consumed;
                if (Index->Value >= Detail::StaticTable.size())
                {
                    return Fail();
                }
                HeaderField Field{};
                Field.Name.assign(Detail::StaticTable[Index->Value].Name);
                Field.value.assign(Detail::StaticTable[Index->Value].value);
                Fields.push_back(std::move(Field));
            }
            else if ((First & 0xC0) == 0x40)
            {
                if ((First & 0x10) == 0)
                {
                    return Fail();
                }
                const auto Index = Detail::ReadVarint(Data.subspan(Offset), 4);
                if (!Index)
                {
                    return Fail();
                }
                Offset += Index->Consumed;
                if (Index->Value >= Detail::StaticTable.size())
                {
                    return Fail();
                }
                HeaderField Field{};
                Field.Name.assign(Detail::StaticTable[Index->Value].Name);
                if (!Detail::ParseValue(Data, Offset, Field.value))
                {
                    return Fail();
                }
                Fields.push_back(std::move(Field));
            }
            else if ((First & 0xE0) == 0x20)
            {
                HeaderField Field{};
                if (!Detail::ParseName(Data, Offset, Field.Name) ||
                    !Detail::ParseValue(Data, Offset, Field.value))
                {
                    return Fail();
                }
                Fields.push_back(std::move(Field));
            }
            else if ((First & 0xE0) == 0x00)
            {
                return Fail();
            }
            else
            {
                return Fail();
            }
        }
        return Fields;
    }

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
                    Encoded, EncodedInteger{PrefixBits, Value, PrefixPattern});
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
                    EncodedLength = Prism::HttpCompression::HuffmanEncodeTo(Value, Stack);
                    if (EncodedLength == 0 && !Value.empty())
                    {
                        return false;
                    }
                    EncodedData = Stack.data();
                }
                else
                {
                    if (!Prism::HttpCompression::HuffmanEncode(Value, Heap))
                    {
                        return false;
                    }
                    EncodedLength = Heap.size();
                    EncodedData = Heap.data();
                }
                const auto LengthPrefix = Detail::WriteVarint(
                    LengthBuffer, EncodedInteger{PrefixBits, EncodedLength, HuffFlag});
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
    [[nodiscard]] auto EncodePrefix(std::span<std::uint8_t> Output) -> std::size_t
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
    [[nodiscard]] auto EncodeLiteral(
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

} // namespace Prism::Http3::Qpack
