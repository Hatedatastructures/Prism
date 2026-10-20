/**
 * @file Varint.hpp
 * @brief QPACK/HPACK 前缀整数编解码辅助
 * @details 只处理前缀整数，不持有 QPACK 表或连接状态。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace Prism::Http3::Qpack::Detail
{
    /** @brief 同一前缀整数的值与已消费字节；失败不发布部分解析状态。 */
    struct DecodedInteger final
    {
        std::uint64_t Value;
        std::size_t Consumed;
    };

    /** @brief 一个 QPACK wire 整数的值、前缀位宽与控制位。 */
    struct EncodedInteger final
    {
        std::uint8_t PrefixBits;
        std::uint64_t Value;
        std::uint8_t PrefixPattern;
    };

    /**
     * @brief 解码前缀整数
     * @param In 输入字节
     * @param PrefixBits 前缀位宽
     * @return 完整值与消耗字节；空、截断或溢出返回 nullopt。
     * @details 同步借输入直至返回，不分配；无取消、半关闭或 executor，caller 拥有 wire。
     * @note 对 PrefixBits=8，UINT64_MAX 的合法编码包含第 10 个
     *       continuation 字节，其有效位位于 shift=63。
     */
    [[nodiscard]] auto ReadVarint(
        std::span<const std::uint8_t> Input,
        std::uint8_t PrefixBits) -> std::optional<DecodedInteger>;

    /**
     * @brief 编码前缀整数
     * @param Output 输出缓冲
     * @param Integer 待编码的完整前缀整数。
     * @return 写入字节数；缓冲不足返回 0
     * @note PrefixPattern 的低 PrefixBits 位必须为 0；PrefixBits=8 时，
     *       UINT64_MAX 需要第 10 个 continuation 字节。
     */
    [[nodiscard]] auto WriteVarint(
        std::span<std::uint8_t> Output,
        EncodedInteger Integer) -> std::size_t;

} // namespace Prism::Http3::Qpack::Detail
