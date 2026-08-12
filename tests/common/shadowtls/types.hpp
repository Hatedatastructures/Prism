/**
 * @file types.hpp
 * @brief ShadowTLS v3 协议基础类型
 * @details ShadowTLS v3 是 TLS 会话复用伪装方案：
 *          - 客户端把认证 HMAC 塞进 ClientHello 的 session_id（Tier 1）
 *          - 服务端校验 session_id 后放行（Tier 2 为完整 TLS 握手）
 *          - 握手后数据流用 HMAC 帧认证（serverRandom + "C"/"S" 标签）
 *          本测试库实现纯逻辑帧编解码与认证（不含真实 TLS 传输）。
 * @note 参考 sing-shadowtls v3 协议规范。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace psmtest::shadowtls
{

    /// TLS 记录头长度
    inline constexpr std::size_t tls_hdrsize = 5;

    /// 握手类型：ClientHello
    inline constexpr std::uint8_t hs_type_clienthello = 1;

    /// ClientHello random 长度
    inline constexpr std::size_t tls_rnd_size = 32;

    /// session_id 长度（ShadowTLS 固定 32 字节）
    inline constexpr std::size_t tls_session_id_sz = 32;

    /// HMAC 截断长度（4 字节）
    inline constexpr std::size_t hmac_size = 4;

    /// ClientHello 内 session_id 起始偏移（1+3+2+32+1）
    inline constexpr std::size_t session_id_start = 1 + 3 + 2 + tls_rnd_size + 1;

    /// 首包认证标签：客户端 "C"，服务端 "S"
    inline constexpr char tag_client = 'C';
    inline constexpr char tag_server = 'S';

} // namespace psmtest::shadowtls
