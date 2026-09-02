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
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Protocols/Http3/Detail/Varint.hpp>
#include <preview/Protocols/Http3/Huffman.hpp>
#include <preview/Protocols/Http3/StaticTable.hpp>

namespace Preview::Http3::Qpack
{

    /**
     * @struct HeaderField
     * @brief 解码出的头字段
     */
    struct HeaderField
    {
        std::string Name;
        std::string value;
    };

    namespace Detail
    {

        /**
         * @brief 解析字面量名称
         * @param in 输入字节序列
         * @param Offset 当前解析偏移（退出时已前进）
         * @param out 解析出的名称
         * @return 是否解析成功
         */
        [[nodiscard]] inline auto ParseName(std::span<const std::uint8_t> in, std::size_t &Offset,
                                             std::string &out) -> bool
        {
            if (Offset >= in.size())
            {
                return false;
            }
            const bool Huffman = (in[Offset] & 0x08) != 0;
            std::uint64_t Len = 0;
            std::size_t Consumed = 0;
            if (!ReadVarint(in.subspan(Offset), 3, Len, Consumed))
            {
                return false;
            }
            Offset += Consumed;
            if (Len > in.size() - Offset)
            {
                return false;
            }
            std::array<std::uint8_t, 255> stack{};
            std::vector<std::uint8_t> heap;
            if (Huffman)
            {
                const auto Est = Len <= stack.size() / 2 ? static_cast<std::size_t>(Len) * 2 : stack.size() + 1;
                if (Est <= stack.size())
                {
                    std::size_t OutN = 0;
                    if (!HuffmanDecodeTo(in.subspan(Offset, static_cast<std::size_t>(Len)), stack, OutN))
                    {
                        return false;
                    }
                    Offset += static_cast<std::size_t>(Len);
                    out.assign(reinterpret_cast<const char *>(stack.data()), OutN);
                    return true;
                }
                if (!HuffmanDecodeImpl(in.subspan(Offset, static_cast<std::size_t>(Len)), heap))
                {
                    return false;
                }
                Offset += static_cast<std::size_t>(Len);
                out.assign(reinterpret_cast<const char *>(heap.data()), heap.size());
                return true;
            }
            Offset += static_cast<std::size_t>(Len);
            out.assign(reinterpret_cast<const char *>(in.data() + Offset - static_cast<std::ptrdiff_t>(Len)),
                       static_cast<std::size_t>(Len));
            return true;
        }

        /**
         * @brief 解析字面量值
         * @param in 输入字节序列
         * @param Offset 当前解析偏移（退出时已前进）
         * @param out 解析出的值
         * @return 是否解析成功
         */
        [[nodiscard]] inline auto ParseValue(std::span<const std::uint8_t> in, std::size_t &Offset,
                                              std::string &out) -> bool
        {
            if (Offset >= in.size())
            {
                return false;
            }
            const bool Huffman = (in[Offset] & 0x80) != 0;
            std::uint64_t Len = 0;
            std::size_t Consumed = 0;
            if (!ReadVarint(in.subspan(Offset), 7, Len, Consumed))
            {
                return false;
            }
            Offset += Consumed;
            if (Len > in.size() - Offset)
            {
                return false;
            }
            std::array<std::uint8_t, 255> stack{};
            std::vector<std::uint8_t> heap;
            if (Huffman)
            {
                const auto Est = Len <= stack.size() / 2 ? static_cast<std::size_t>(Len) * 2 : stack.size() + 1;
                if (Est <= stack.size())
                {
                    std::size_t OutN = 0;
                    if (!HuffmanDecodeTo(in.subspan(Offset, static_cast<std::size_t>(Len)), stack, OutN))
                    {
                        return false;
                    }
                    Offset += static_cast<std::size_t>(Len);
                    out.assign(reinterpret_cast<const char *>(stack.data()), OutN);
                    return true;
                }
                if (!HuffmanDecodeImpl(in.subspan(Offset, static_cast<std::size_t>(Len)), heap))
                {
                    return false;
                }
                Offset += static_cast<std::size_t>(Len);
                out.assign(reinterpret_cast<const char *>(heap.data()), heap.size());
                return true;
            }
            Offset += static_cast<std::size_t>(Len);
            out.assign(reinterpret_cast<const char *>(in.data() + Offset - static_cast<std::ptrdiff_t>(Len)),
                       static_cast<std::size_t>(Len));
            return true;
        }

    } // namespace Detail

    /**
     * @brief 解码一个 QPACK 头块
     * @param Data 编码数据（不含 HTTP/3 帧头）
     * @param mr 内存资源
     * @return 解码出的头字段列表；失败返回空
     */
    [[nodiscard]] inline auto DecodeHeaderBlock(std::span<const std::uint8_t> Data,
                                                 const Preview::Memory::ResourcePointer mr)
        -> Preview::Memory::Vector<HeaderField>
    {
        Preview::Memory::Vector<HeaderField> fields(mr);
        fields.reserve(8);
        const auto Fail = [&]() -> Preview::Memory::Vector<HeaderField>
        {
            fields.clear();
            return std::move(fields);
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
            const auto First = Data[Offset];
            if ((First & 0x80) != 0)
            {
                if ((First & 0x40) == 0)
                {
                    return Fail();
                }
                std::uint64_t index = 0;
                if (!Detail::ReadVarint(Data.subspan(Offset), 6, index, Consumed))
                {
                    return Fail();
                }
                Offset += Consumed;
                if (index >= Detail::StaticTable.size())
                {
                    return Fail();
                }
                HeaderField hf{};
                hf.Name.assign(Detail::StaticTable[index].Name);
                hf.value.assign(Detail::StaticTable[index].value);
                fields.push_back(std::move(hf));
            }
            else if ((First & 0xC0) == 0x40)
            {
                if ((First & 0x10) == 0)
                {
                    return Fail();
                }
                std::uint64_t index = 0;
                if (!Detail::ReadVarint(Data.subspan(Offset), 4, index, Consumed))
                {
                    return Fail();
                }
                Offset += Consumed;
                if (index >= Detail::StaticTable.size())
                {
                    return Fail();
                }
                HeaderField hf{};
                hf.Name.assign(Detail::StaticTable[index].Name);
                if (!Detail::ParseValue(Data, Offset, hf.value))
                {
                    return Fail();
                }
                fields.push_back(std::move(hf));
            }
            else if ((First & 0xE0) == 0x20)
            {
                HeaderField hf{};
                if (!Detail::ParseName(Data, Offset, hf.Name) || !Detail::ParseValue(Data, Offset, hf.value))
                {
                    return Fail();
                }
                fields.push_back(std::move(hf));
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
        return fields;
    }

} // namespace Preview::Http3::Qpack
