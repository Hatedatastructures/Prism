/**
 * @file AuthCrypto.hpp
 * @brief VMess 认证使用的密码学原语
 * @details 提供摘要、字节视图、KDF padding、AES-GCM、AES-ECB 与帧掩码哈希。
 *          本头不拥有 VMess KDF 链、AuthID 格式或认证头 wire。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

namespace Prism::Vmess::detail
{

    /**
     * @brief HMAC-SHA256 单次
     * @param Key 输入密钥
     * @param Data 输入数据
     * @return 32 字节摘要
     */
    [[nodiscard]] auto HmacSha256(
        std::span<const std::uint8_t> Key,
        std::span<const std::uint8_t> Data)
        -> std::array<std::uint8_t, 32>;

    /**
     * @brief MD5 摘要（16 字节）
     * @param Data 输入数据
     * @return 16 字节摘要
     */
    [[nodiscard]] auto Md5(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 16>;

    /**
     * @brief SHA-256 摘要（32 字节）
     * @param Data 输入数据
     * @return 32 字节摘要
     */
    [[nodiscard]] auto Sha256(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 32>;

    /**
     * @brief 路径转字节视图（支持 string_view / span / array）
     * @tparam Path 路径类型
     * @param Object 路径对象
     * @return 只读字节视图
     */
    template <typename Path>
    [[nodiscard]] inline auto AsBytes(const Path &Object) -> std::span<const std::uint8_t>
    {
        if constexpr (std::is_convertible_v<Path, std::string_view>)
        {
            const std::string_view StringView(Object);
            return {reinterpret_cast<const std::uint8_t *>(StringView.data()), StringView.size()};
        }
        else
        {
            return std::span<const std::uint8_t>(Object);
        }
    }

    /**
     * @brief 路径填充到 64 字节块
     * @param Path 路径字节
     * @param Mask 异或掩码（0x36 / 0x5C）
     * @return 64 字节填充块
     */
    [[nodiscard]] auto XorPad(
        std::span<const std::uint8_t> Path,
        std::uint8_t Mask)
        -> std::array<std::uint8_t, 64>;

    /**
     * @brief AES-GCM 加密输入
     */
    struct SealInput
    {
        std::span<const std::uint8_t> Key;
        std::span<const std::uint8_t> Nonce;
        std::span<const std::uint8_t> Plain;
        std::span<const std::uint8_t> Aad;
    };

    /**
     * @brief AES-GCM 解密输入
     */
    struct OpenInput
    {
        std::span<const std::uint8_t> Key;
        std::span<const std::uint8_t> Nonce;
        std::span<const std::uint8_t> Cipher;
        std::span<const std::uint8_t> Aad;
    };

    [[nodiscard]] auto ValidAesGcmInput(const SealInput &Input) noexcept -> bool;

    [[nodiscard]] auto ValidAesGcmInput(const OpenInput &Input) noexcept -> bool;

    /**
     * @brief AES-128-GCM 加密（带 AAD）
     * @param Input 加密输入
     * @return 密文 + 16 字节 tag；失败返回空
     */
    [[nodiscard]] auto AesGcmSeal(const SealInput &Input) -> std::vector<std::uint8_t>;

    /**
     * @brief AES-128-GCM 解密（带 AAD）
     * @param Input 解密输入
     * @return 明文；失败返回空
     */
    [[nodiscard]] auto AesGcmOpen(const OpenInput &Input) -> std::vector<std::uint8_t>;

    /**
     * @brief FNV-1a 32 位
     * @param Data 输入数据
     * @return 32 位哈希
     */
    [[nodiscard]] auto Fnv1a32(std::span<const std::uint8_t> Data) -> std::uint32_t;

    /**
     * @brief AES-128-ECB 无填充加密
     */
    [[nodiscard]] auto AesEcbEncrypt(std::span<const std::uint8_t, 16> Key,
                                             std::span<const std::uint8_t, 16> Plain)
        -> std::array<std::uint8_t, 16>;

    /**
     * @brief AES-128-ECB 无填充解密
     */
    [[nodiscard]] auto AesEcbDecrypt(std::span<const std::uint8_t, 16> Key,
                                             std::span<const std::uint8_t, 16> Cipher)
        -> std::array<std::uint8_t, 16>;

} // namespace Prism::Vmess::detail
