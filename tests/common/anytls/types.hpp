/**
 * @file types.hpp
 * @brief AnyTLS 协议基础类型
 * @details AnyTLS 是 TLS 之上的代理协议（对齐 mihomo transport/anytls）：
 *          - 认证：TLS 握手后首帧 = [SHA-256(password) 32B][PadLen 2B BE][Padding]
 *          - 数据：内部多路复用（session 帧）
 *          本测试库实现纯逻辑认证编解码（不含真实 TLS 传输）。
 * @note 参考 AnyTLS 协议规范。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace psmtest::anytls
{

    /// 认证密码哈希长度（SHA-256）
    inline constexpr std::size_t password_hash_len = 32;

    /// 认证帧 Padding 长度字段大小（2 字节大端）
    inline constexpr std::size_t pad_len_field_size = 2;

    /// 认证帧固定开销（hash 32 + padlen 2）
    inline constexpr std::size_t auth_frame_hdrlen = password_hash_len + pad_len_field_size;

} // namespace psmtest::anytls
