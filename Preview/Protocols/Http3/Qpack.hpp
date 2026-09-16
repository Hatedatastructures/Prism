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

#include <Preview/Protocols/Http3/Decoder.hpp>
#include <Preview/Protocols/Http3/DynamicTable.hpp>
#include <Preview/Protocols/Http3/Encoder.hpp>
#include <Preview/Protocols/Http3/Huffman.hpp>

namespace Preview::Http3::Qpack
{

    /**
     * @brief HPACK Huffman 解码
     * @param Input 编码数据
     * @param Output 解码输出（成功时追加；失败时回滚本次追加）
     * @return 是否成功
     */
    [[nodiscard]] inline auto HuffmanDecode(
        std::span<const std::uint8_t> Input,
        std::vector<std::uint8_t> &Output) -> bool
    {
        return Detail::HuffmanDecodeImpl(Input, Output);
    }

    /**
     * @brief HPACK Huffman 编码
     * @param Input 明文数据
     * @param Output 编码输出（追加写入）
     * @return 是否成功
     */
    [[nodiscard]] inline auto HuffmanEncode(
        std::string_view Input,
        std::vector<std::uint8_t> &Output) -> bool
    {
        return Detail::HuffmanEncodeImpl(Input, Output);
    }

} // namespace Preview::Http3::Qpack
