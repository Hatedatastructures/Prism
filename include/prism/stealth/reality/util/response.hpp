/**
 * @file response.hpp
 * @brief TLS 1.3 ServerHello 生成器
 * @details 生成 Reality 协议所需的 TLS 1.3 服务端握手消息，
 * 包括 ServerHello、ChangeCipherSpec（兼容性）和加密的握手记录，
 * 用于构造完整的 TLS 握手响应发送给客户端
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <prism/fault/code.hpp>
#include <prism/memory/container.hpp>
#include <prism/protocol/tls/types.hpp>

namespace psm::stealth::reality
{
    using hello_features = protocol::tls::hello_features;
    // psm::protocol 命名空间中的类型已使用完整限定名，无需 using 声明

    struct key_material;

    /**
     * @struct hello_request
     * @brief generate_shello 的输入参数集
     * @details 将 ServerHello 生成所需的六项参数打包为单一结构体，
     * 遵守函数参数不超过 3 个的编码规范
     */
    struct hello_request
    {
        const hello_features &client_hello;            ///< 解析后的 ClientHello 信息
        std::span<const std::uint8_t> server_eph_pub; ///< 服务端临时 X25519 公钥
        const key_material &handshake_keys;            ///< 握手阶段密钥材料
        std::span<const std::uint8_t> dest_certificate; ///< 目标网站的 DER 格式证书
        std::span<const std::uint8_t> chello_msg;      ///< 完整的 ClientHello 消息字节
        std::span<const std::uint8_t> auth_key = {};       ///< HKDF 派生的认证密钥，用于签名
    };

    /**
     * @struct encrypt_params
     * @brief encrypt_record 的输入参数集
     * @details 将 TLS 1.3 记录加密所需的五项参数打包为单一结构体，
     * 遵守函数参数不超过 3 个的编码规范
     */
    struct encrypt_params
    {
        std::span<const std::uint8_t> key;       ///< 加密密钥
        std::span<const std::uint8_t> iv;        ///< 初始化向量
        std::uint64_t sequence = 0;              ///< 序列号，用于生成 nonce
        std::uint8_t content_type = 0;           ///< 内容类型
        std::span<const std::uint8_t> plaintext; ///< 明文数据
    };

    /**
     * @struct shello_result
     * @brief ServerHello 生成结果
     * @details 包含 TLS 握手响应的各阶段消息和记录
     */
    struct shello_result
    {
        memory::vector<std::uint8_t> shello_msg;              // ServerHello 握手消息（含 handshake header）
        memory::vector<std::uint8_t> shello_record;           // ServerHello TLS 记录（含 record header）
        memory::vector<std::uint8_t> ccs_record;              // ChangeCipherSpec 兼容性记录
        memory::vector<std::uint8_t> enc_hs_record;           // 加密后的握手记录（EncryptedExtensions + Certificate + CertificateVerify + Finished）
        memory::vector<std::uint8_t> enc_hs_plain;            // 加密前握手记录明文
    };

    /**
     * @brief 生成 ServerHello 及完整握手响应
     * @details 构造 ServerHello 消息、ChangeCipherSpec 兼容性记录和加密的
     * 握手记录（含伪造的 Certificate、CertificateVerify 和 Finished），
     * 使用目标网站的真实证书构造伪造证书用于 Reality 认证
     * @param req ServerHello 生成所需的全部输入参数
     * @return 错误码和生成结果
     */
    [[nodiscard]] auto generate_shello(const hello_request &req)
        -> std::pair<fault::code, shello_result>;

    /**
     * @brief 构造 TLS 记录
     * @details 将载荷数据包装为标准 TLS 记录格式：
     * [ContentType 1B][Version 2B][Length 2B][Payload]
     * @param content_type 内容类型
     * @param payload 记录载荷
     * @return 编码后的 TLS 记录字节
     */
    [[nodiscard]] auto make_record(std::uint8_t content_type, std::span<const std::uint8_t> payload)
        -> memory::vector<std::uint8_t>;

    /**
     * @brief 加密 TLS 1.3 记录
     * @details 使用 AEAD 加密明文数据，构造加密后的 TLS 记录。
     * nonce 由 IV 和序列号异或生成，加密后追加 content type 和 AEAD tag
     * @param params 加密所需的全部输入参数（密钥、IV、序列号、内容类型、明文）
     * @return 错误码和加密后的密文（含 record header）
     */
    [[nodiscard]] auto encrypt_record(const encrypt_params &params)
        -> std::pair<fault::code, memory::vector<std::uint8_t>>;
} // namespace psm::stealth::reality
