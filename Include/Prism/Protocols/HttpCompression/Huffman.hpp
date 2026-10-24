/**
 * @file Huffman.hpp
 * @brief HTTP/2 与 HTTP/3 共用的 RFC 7541 Huffman 编解码接口。
 * @details 输入按调用期间借用；解码失败时回滚追加输出，定长接口以返回值
 *          报告写入长度，缓冲不足或 wire 数据无效时返回失败。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace Prism::HttpCompression
{
    /** @brief 解码 RFC 7541 Huffman 字节并追加输出，失败时恢复原输出长度。 */
    [[nodiscard]] auto HuffmanDecode(
        std::span<const std::uint8_t> Input,
        std::vector<std::uint8_t> &Output) -> bool;

    /** @brief 将 Huffman 字节解码到调用方缓冲，失败时将 OutN 置零。 */
    [[nodiscard]] auto HuffmanDecodeTo(
        std::span<const std::uint8_t> Input,
        std::span<std::uint8_t> Output,
        std::size_t &OutN) -> bool;

    /** @brief 将文本编码到调用方缓冲，缓冲不足时返回零。 */
    [[nodiscard]] auto HuffmanEncodeTo(
        std::string_view Input,
        std::span<std::uint8_t> Output) -> std::size_t;

    /** @brief 编码 RFC 7541 Huffman 字节并追加输出。 */
    [[nodiscard]] auto HuffmanEncode(
        std::string_view Input,
        std::vector<std::uint8_t> &Output) -> bool;
}
