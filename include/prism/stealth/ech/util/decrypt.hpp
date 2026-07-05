/**
 * @file decrypt.hpp
 * @brief ECH 解密接口
 * @details 使用 HPKE (Hybrid Public Key Encryption) 解密 ECH outer payload，
 * 获取 inner ClientHello。
 */
#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/proto/protocol/tls/types.hpp>

#include <span>


namespace psm::stealth::ech
{

    using hello_features = protocol::tls::hello_features;
    /**
     * @struct decrypt_result
     * @brief ECH 解密结果
     */
    struct decrypt_result
    {
        bool valid{false};                          ///< 解密是否成功
        hello_features inner_features; ///< 解密后的 inner 特征
        memory::vector<std::byte> inner_client_hello; ///< 解密后的 inner ClientHello 原始字节
        fault::code error{fault::code::success};    ///< 错误码
    };

    /**
     * @brief 解密 ECH outer payload
     * @param outer_payload ECH outer payload（从 ClientHello 扩展提取）
     * @param ech_key ECH 配置密钥（base64 编码）
     * @return 解密结果
     * @details 使用 HPKE 解密流程：
     * 1. 解析 ECH outer 结构（version, config_id, enc, payload）
     * 2. 使用 ECH 私钥和 enc 计算 shared secret
     * 3. 使用 AEAD 解密 payload，获取 inner ClientHello
     * 4. 解析 inner ClientHello，提取真实 SNI
     *
     * ECH outer 格式：
     * version: 2 bytes (0xfe 0x0d for TLS 1.3)
     * config_id: 1 byte
     * enc: variable (KEM encapsulated key)
     * payload: variable (encrypted inner)
     */
    [[nodiscard]] auto decrypt_ech_payload(std::span<const std::byte> outer_payload, std::string_view ech_key)
        -> decrypt_result;

} // namespace psm::stealth::ech