/**
 * @file Types.hpp
 * @brief Restls 协议基础类型
 * @details Restls 是 TLS 探测抵抗伪装方案（对齐 restls-Client-go）：
 *          - 服务端使用 BLAKE3 keyed 派生 ServerMask，保护首个 TLS 记录；
 *          - 每条应用数据记录包含 8 字节 auth_mac 和 4 字节 XOR mask；
 *          - 方向标签固定为 Server-to-Client 或 Client-to-Server。
 *          本测试库实现纯逻辑认证编解码，不包含真实 TLS 传输。
 * @note 参考 restls-Client-go 协议规范。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace Preview::Restls
{

    /// 握手阶段 MAC 长度（ServerMask，保持现有导出名称兼容）
    inline constexpr std::size_t HsMaclen = 16;

    /// 应用数据 MAC 长度（auth_mac，保持现有导出名称兼容）
    inline constexpr std::size_t AppdataMaclen = 8;

    /// XOR 掩码长度（保持现有导出名称兼容）
    inline constexpr std::size_t MaskLen = 4;

    /// 认证头总长度，等于 auth_mac 加 XOR mask
    inline constexpr std::size_t AuthHdrlen = AppdataMaclen + MaskLen;

    /// TLS 记录头长度
    inline constexpr std::size_t TlsHdrlen = 5;

    /// TLS ApplicationData 记录类型
    inline constexpr std::uint8_t TlsApplicationData = 0x17;

    /// 单个 Restls 记录的明文上限（不含认证头）
    inline constexpr std::size_t MaxDataLength = 16 * 1024;

    /// 单个 Restls TLS 记录的最大负载长度
    inline constexpr std::size_t MaxRecordPayload = AuthHdrlen + MaxDataLength;

    /// ActNoop 命令
    inline constexpr std::uint8_t CmdTypeNoop = 0x00;

    /// ActResponse 命令
    inline constexpr std::uint8_t CmdTypeResponse = 0x01;

    /// 服务端到客户端的方向标签
    inline constexpr std::string_view DirToclient = "Server-to-Client";
    /// 客户端到服务端的方向标签
    inline constexpr std::string_view DirToserver = "Client-to-Server";

    /// BLAKE3 DeriveKey 使用的固定上下文
    inline constexpr std::string_view SecretCtx = "restls-traffic-key";

    /// 数据流方向；枚举值参与认证输入，数值保持现有 wire 语义
    enum class FlowDirection : std::uint8_t
    {
        /// 服务端 → 客户端
        ToClient,
        /// 客户端 → 服务端
        ToServer,
    };

    /**
     * @struct Handover
     * @brief Restls 握手完成后交给数据传输层的所有 wire 状态
     * @details 对齐生产握手输出：首个服务端加密记录需要先应用 ServerMask，
     * 首个客户端 ApplicationData 的 auth_mac 需要包含 ClientFinished。
     */
    struct Handover final
    {
        std::array<std::uint8_t, 32> ServerRandom{}; ///< TLS ServerHello random
        std::vector<std::uint8_t> ClientFinished;     ///< 首个客户端加密记录
        std::vector<std::uint8_t> FirstEncrypted;     ///< 首个服务端加密记录
    };

} // namespace Preview::Restls
