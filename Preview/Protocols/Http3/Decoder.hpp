/**
 * @file Decoder.hpp
 * @brief QPACK 头块解码器
 * @details 解析静态表索引、静态表名称引用和字面量字段。动态表
 *          指令按当前 Preview 支持范围拒绝。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Protocols/Http3/Detail/Varint.hpp>
#include <Preview/Protocols/Http3/Huffman.hpp>
#include <Preview/Protocols/Http3/StaticTable.hpp>

namespace Preview::Http3::Qpack
{

    inline constexpr std::size_t MaxHeaderBlockBytes = 64 * 1024;
    inline constexpr std::size_t MaxHeaderFields = 128;
    inline constexpr std::size_t MaxFieldBytes = 16 * 1024;

    /**
     * @struct HeaderField
     * @brief 解码出的头字段
     */
    struct HeaderField
    {
        std::string Name;
        std::string value; ///< 保留兼容公共字段名
    };

    namespace Detail
    {

        /**
         * @brief 解析字面量名称
         * @param Input 输入字节序列
         * @param Offset 当前解析偏移（退出时已前进）
         * @param Output 解析出的名称
         * @return 是否解析成功
         */
        [[nodiscard]] inline auto ParseName(
            std::span<const std::uint8_t> Input,
            std::size_t &Offset,
            std::string &Output) -> bool
        {
            if (Offset >= Input.size())
            {
                return false;
            }
            const bool Huffman = (Input[Offset] & 0x08) != 0;
            std::uint64_t Length = 0;
            std::size_t Consumed = 0;
            if (!ReadVarint(Input.subspan(Offset), 3, Length, Consumed))
            {
                return false;
            }
            Offset += Consumed;
            if (Length > Input.size() - Offset)
            {
                return false;
            }
            if (Length > MaxFieldBytes)
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
                    if (!HuffmanDecodeTo(
                            Input.subspan(Offset, static_cast<std::size_t>(Length)),
                            stack,
                            OutputLength))
                    {
                        return false;
                    }
                    if (OutputLength > MaxFieldBytes)
                    {
                        return false;
                    }
                    Offset += static_cast<std::size_t>(Length);
                    Output.assign(reinterpret_cast<const char *>(stack.data()), OutputLength);
                    return true;
                }
                std::vector<std::uint8_t> Heap;
                if (!HuffmanDecodeImpl(
                        Input.subspan(Offset, static_cast<std::size_t>(Length)),
                        Heap))
                {
                    return false;
                }
                if (Heap.size() > MaxFieldBytes)
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
        [[nodiscard]] inline auto ParseValue(
            std::span<const std::uint8_t> Input,
            std::size_t &Offset,
            std::string &Output) -> bool
        {
            if (Offset >= Input.size())
            {
                return false;
            }
            const bool Huffman = (Input[Offset] & 0x80) != 0;
            std::uint64_t Length = 0;
            std::size_t Consumed = 0;
            if (!ReadVarint(Input.subspan(Offset), 7, Length, Consumed))
            {
                return false;
            }
            Offset += Consumed;
            if (Length > Input.size() - Offset)
            {
                return false;
            }
            if (Length > MaxFieldBytes)
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
                    if (!HuffmanDecodeTo(
                            Input.subspan(Offset, static_cast<std::size_t>(Length)),
                            stack,
                            OutputLength))
                    {
                        return false;
                    }
                    if (OutputLength > MaxFieldBytes)
                    {
                        return false;
                    }
                    Offset += static_cast<std::size_t>(Length);
                    Output.assign(reinterpret_cast<const char *>(stack.data()), OutputLength);
                    return true;
                }
                std::vector<std::uint8_t> Heap;
                if (!HuffmanDecodeImpl(
                        Input.subspan(Offset, static_cast<std::size_t>(Length)),
                        Heap))
                {
                    return false;
                }
                if (Heap.size() > MaxFieldBytes)
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

    /**
     * @brief 解码一个 QPACK 头块
     * @param Data 编码数据（不含 HTTP/3 帧头）
     * @param MemoryResource 内存资源
     * @return 解码出的头字段列表；失败返回空
     */
    [[nodiscard]] inline auto DecodeHeaderBlock(
        std::span<const std::uint8_t> Data,
        const Preview::Memory::ResourcePointer MemoryResource)
        -> Preview::Memory::Vector<HeaderField>
    {
        Preview::Memory::Vector<HeaderField> Fields(MemoryResource);
        if (Data.size() > MaxHeaderBlockBytes)
        {
            return Fields;
        }
        Fields.reserve(8);
        const auto Fail = [&]() -> Preview::Memory::Vector<HeaderField>
        {
            Fields.clear();
            return std::move(Fields);
        };
        std::size_t Offset = 0;
        std::uint64_t RequiredCount = 0;
        std::size_t Consumed = 0;
        if (!Detail::ReadVarint(Data.subspan(Offset), 8, RequiredCount, Consumed))
        {
            return Fail();
        }
        Offset += Consumed;
        if (RequiredCount != 0)
        {
            return Fail();
        }

        std::uint64_t Base = 0;
        if (Offset > Data.size())
        {
            return Fail();
        }
        if (!Detail::ReadVarint(Data.subspan(Offset), 7, Base, Consumed))
        {
            return Fail();
        }
        Offset += Consumed;
        if (Base != 0)
        {
            return Fail();
        }

        while (Offset < Data.size())
        {
            if (Fields.size() >= MaxHeaderFields)
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
                std::uint64_t Index = 0;
                if (!Detail::ReadVarint(Data.subspan(Offset), 6, Index, Consumed))
                {
                    return Fail();
                }
                Offset += Consumed;
                if (Index >= Detail::StaticTable.size())
                {
                    return Fail();
                }
                HeaderField Field{};
                Field.Name.assign(Detail::StaticTable[Index].Name);
                Field.value.assign(Detail::StaticTable[Index].value);
                Fields.push_back(std::move(Field));
            }
            else if ((First & 0xC0) == 0x40)
            {
                if ((First & 0x10) == 0)
                {
                    return Fail();
                }
                std::uint64_t Index = 0;
                if (!Detail::ReadVarint(Data.subspan(Offset), 4, Index, Consumed))
                {
                    return Fail();
                }
                Offset += Consumed;
                if (Index >= Detail::StaticTable.size())
                {
                    return Fail();
                }
                HeaderField Field{};
                Field.Name.assign(Detail::StaticTable[Index].Name);
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

} // namespace Preview::Http3::Qpack
