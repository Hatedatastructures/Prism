/**
 * @file Types.hpp
 * @brief ShadowTLS v3 协议基础类型
 * @details ShadowTLS v3 是 TLS 会话复用伪装方案：
 *          - 客户端把认证 HMAC 塞进 ClientHello 的 SessionId（Tier 1）
 *          - 服务端校验 SessionId 后放行（Tier 2 为完整 TLS 握手）
 *          - 握手后数据流用 HMAC 帧认证（serverRandom + "C"/"S" 标签）
 *          本测试库实现纯逻辑帧编解码与认证（不含真实 TLS 传输）。
 * @note 参考 sing-shadowtls v3 协议规范。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace Preview::Shadowtls
{

    /// ShadowTLS 客户端认证配置
    struct ClientConfig
    {
        /// 客户端认证密码；保留空字符串默认值
        std::string password;
    };

    /// ShadowTLS 服务端认证配置
    struct ServerConfig
    {
        /// 服务端认证密码；保留空字符串默认值
        std::string password;
    };

    /// TLS 记录头长度
    inline constexpr std::size_t TlsHdrsize = 5;

    /// 握手类型：ClientHello
    inline constexpr std::uint8_t HsTypeClienthello = 1;

    /// ClientHello random 长度
    inline constexpr std::size_t TlsRndSize = 32;

    /// SessionId 长度（ShadowTLS 固定 32 字节）
    inline constexpr std::size_t TlsSessionIdSz = 32;

    /// HMAC 截断长度（4 字节）
    inline constexpr std::size_t HmacSize = 4;

    /// TLS application-data 记录类型
    inline constexpr std::uint8_t TlsContentApplicationData = 23;

    /// ShadowTLS v3 记录版本（TLS 1.2 wire 版本）
    inline constexpr std::uint8_t TlsRecordVersionMajor = 3;
    inline constexpr std::uint8_t TlsRecordVersionMinor = 3;

    /// 单个 application-data 记录的最大明文长度
    inline constexpr std::size_t MaxTlsPlaintext = 16 * 1024;

    /// ClientHello 内 SessionId 起始偏移（1+3+2+32+1）
    inline constexpr std::size_t SessionIdStart = 1 + 3 + 2 + TlsRndSize + 1;

    /// 首包认证标签：客户端 "C"，服务端 "S"
    inline constexpr char TagClient = 'C';
    inline constexpr char TagServer = 'S';

    /// application-data HMAC 链的初始种子模式
    enum class RecordSeed : std::uint8_t
    {
        /// HMAC(password, serverRandom + direction)
        Directional,
        /// ShadowTLS v3 外层 TLS 握手 flight 使用 HMAC(password, serverRandom)
        ServerRandomOnly,
    };

} // namespace Preview::Shadowtls
