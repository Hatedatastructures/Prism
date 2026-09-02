/**
 * @file Qpack.hpp
 * @brief QPACK 编解码兼容聚合入口
 * @details 静态表、动态表能力声明、Decoder、Encoder 与 Huffman
 *          原语分别位于职责头文件；现有调用方继续包含本文件即可。
 */

#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <preview/Protocols/Http3/Decoder.hpp>
#include <preview/Protocols/Http3/DynamicTable.hpp>
#include <preview/Protocols/Http3/Encoder.hpp>
#include <preview/Protocols/Http3/Huffman.hpp>

namespace Preview::Http3::Qpack
{

    /**
     * @brief HPACK Huffman 解码
     * @param in 编码数据
     * @param out 解码输出
     * @return 是否成功
     */
    [[nodiscard]] inline auto HuffmanDecode(std::span<const std::uint8_t> in,
                                             std::vector<std::uint8_t> &out) -> bool
    {
        return Detail::HuffmanDecodeImpl(in, out);
    }

    /**
     * @brief HPACK Huffman 编码
     * @param in 明文数据
     * @param out 编码输出
     * @return 是否成功
     */
    [[nodiscard]] inline auto HuffmanEncode(std::string_view in, std::vector<std::uint8_t> &out) -> bool
    {
        return Detail::HuffmanEncodeImpl(in, out);
    }

} // namespace Preview::Http3::Qpack
