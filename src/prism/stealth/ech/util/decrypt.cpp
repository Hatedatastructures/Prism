/**
 * @file decrypt.cpp
 * @brief ECH 解密实现
 * @details 使用 HPKE 解密 ECH outer payload。
 *
 * **当前状态**：框架已实现，HPKE 解密逻辑待完善。
 * 需要实现 HPKE SetupBaseS 和 AEAD Open 操作。
 */
#include <prism/stealth/ech/util/decrypt.hpp>
#include <prism/trace.hpp>

namespace psm::stealth::ech
{
    auto decrypt_ech_payload(
        std::span<const std::byte> outer_payload,
        std::string_view ech_key) -> decrypt_result
    {
        decrypt_result result;

        // ECH outer 格式检查
        // 最小长度: version(2) + config_id(1) + enc_len(2) + payload_len(2) = 7
        if (outer_payload.size() < 7)
        {
            result.error = fault::code::ech_payload_invalid;
            trace::debug("[ECH] Payload too small: {} bytes", outer_payload.size());
            return result;
        }

        // 检查 version 是否为 TLS 1.3 (0xfe 0x0d)
        const auto version = static_cast<std::uint16_t>(
            (static_cast<std::uint8_t>(outer_payload[0]) << 8) |
            static_cast<std::uint8_t>(outer_payload[1]));
        if (version != 0xfe0d)
        {
            result.error = fault::code::ech_version_mismatch;
            trace::debug("[ECH] Version mismatch: expected 0xfe0d, got 0x{:04x}", version);
            return result;
        }

        // TODO: 实现 HPKE 解密
        // 1. 提取 config_id，匹配配置
        // 2. 提取 enc（KEM encapsulated key）
        // 3. 使用 ech_key 解码私钥
        // 4. 执行 HPKE SetupBaseS：使用私钥和 enc 计算 shared secret
        // 5. 使用 AEAD Open 解密 payload
        // 6. 解析 inner ClientHello

        trace::debug("[ECH] Decryption not implemented, ech_key configured");

        // 当前返回失败（未实现）
        result.error = fault::code::not_supported;
        return result;
    }
} // namespace psm::stealth::ech