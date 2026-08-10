/**
 * @file qpack.hpp
 * @brief QPACK 头压缩编解码（RFC 9204 静态表 + HPACK huffman）
 * @details 实现 Hysteria2 HTTP/3 认证所需的 QPACK 解码/编码：
 *          1. 静态表 99 项（RFC 9204 附录 A）
 *          2. HPACK huffman 编解码（RFC 7541 附录 B，257 符号）
 *          3. 无动态表（mihomo 客户端 qpack 实现同样无动态表）
 *          仅支持认证请求的 HEADERS 帧解析，不做通用 HTTP/3 处理。
 */

#pragma once

#include <prism/foundation/memory/container.hpp>

#include <cstdint>
#include <span>
#include <string_view>

namespace psm::protocol::hysteria2::qpack
{

    /**
     * @struct header_field
     * @brief 解码出的头字段
     */
    struct header_field
    {
        memory::string name;
        memory::string value;
    };

    /**
     * @brief 解码一个 QPACK 头块
     * @param data 编码数据（不含 HTTP/3 帧头，仅 QPACK 块）
     * @param mr 内存资源
     * @return 解码出的头字段列表；失败返回空（无法区分空与失败，
     *         调用方应结合编码格式校验）
     * @details 仅支持静态表索引与字面量（无动态表），与 mihomo
     *          metacubex/qpack 客户端编码器对应。
     */
    [[nodiscard]] auto decode_header_block(std::span<const std::uint8_t> data,
                                           memory::resource_pointer mr)
        -> memory::vector<header_field>;

    /**
     * @brief 编码一个头字段为 QPACK 字面量（无名称引用）
     * @param name 字段名
     * @param value 字段值
     * @param out 输出缓冲区
     * @return 写入字节数
     * @details 服务端响应编码用：:status / Hysteria-UDP / Hysteria-CC-RX /
     *          Hysteria-Padding 均为自定义字段，静态表无对应条目，
     *          统一按字面量（huffman）编码。
     */
    [[nodiscard]] auto encode_literal(std::string_view name, std::string_view value,
                                      std::span<std::uint8_t> out) -> std::size_t;

    /**
     * @brief 编码 QPACK 头块前缀（Required Insert Count=0, Delta Base=0）
     * @param out 输出缓冲区
     * @return 写入字节数
     */
    [[nodiscard]] auto encode_prefix(std::span<std::uint8_t> out) -> std::size_t;

    /**
     * @brief HPACK huffman 解码
     * @param in 编码数据
     * @param out 解码输出
     * @return 是否成功
     */
    [[nodiscard]] auto huffman_decode(std::span<const std::uint8_t> in,
                                      memory::vector<std::uint8_t> &out) -> bool;

    /**
     * @brief HPACK huffman 编码
     * @param in 明文数据
     * @param out 编码输出
     * @return 是否成功
     */
    [[nodiscard]] auto huffman_encode(std::string_view in, memory::vector<std::uint8_t> &out) -> bool;

} // namespace psm::protocol::hysteria2::qpack
