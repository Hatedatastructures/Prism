/**
 * @file Types.hpp
 * @brief AnyTLS 协议基础类型
 * @details AnyTLS 是 TLS 之上的代理协议（对齐 mihomo transport/anytls）：
 *          - 认证：TLS 握手后首帧 = [SHA-256(password) 32B][PadLen 2B BE][Padding]
 *          - 数据：内部多路复用（Session 帧）
 *          本测试库实现纯逻辑认证编解码（不含真实 TLS 传输）。
 * @note 参考 AnyTLS 协议规范。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace Preview::Anytls
{

    /// 认证密码哈希长度（SHA-256）
    inline constexpr std::size_t PasswordHashLen = 32;

    /// 认证帧 Padding 长度字段大小（2 字节大端）
    inline constexpr std::size_t PadLenFieldSize = 2;

    /// 认证帧固定开销（Hash 32 + padlen 2）
    inline constexpr std::size_t AuthFrameHdrlen = PasswordHashLen + PadLenFieldSize;

} // namespace Preview::Anytls
