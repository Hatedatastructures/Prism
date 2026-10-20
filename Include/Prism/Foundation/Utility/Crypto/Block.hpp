/**
 * @file Block.hpp
 * @brief AES-ECB 单块加解密的显式失败值接口。
 * @details 输入与密钥只借用至返回；结果拥有一个 16 字节块。
 *          无取消、半关闭、最终连接关闭或 executor 行为。
 */
#pragma once

#include <Prism/Foundation/Utility/Crypto/Operation.hpp>
#include <openssl/evp.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace Prism::Crypto
{
    namespace Detail
    {
        /** @brief 根据完整密钥长度选择 AES-ECB 算法，非法长度不创建上下文。 */
        [[nodiscard]] auto EcbCipher(std::size_t Length) noexcept -> const EVP_CIPHER *;
    }

    /**
     * @brief 将一个完整块加密为拥有型结果；成功算法为无填充 AES-128/192/256-ECB。
     * @return 非法密钥长度返回 InvalidArgument；分配或各阶段失败保留原生错误。
     * @details 上下文由本调用释放，临时块在所有返回路径擦除。
     */
    [[nodiscard]] auto EcbEncrypt(std::span<const std::uint8_t, 16> Input,
        std::span<const std::uint8_t> Key)
        -> std::expected<std::array<std::uint8_t, 16>, Fault::Failure>;

    /**
     * @brief 解密一个完整 AES-ECB 块；借用、拥有和关闭契约同 EcbEncrypt。
     * @return 长度非法返回 InvalidArgument，各原生阶段失败立即返回 Failure。
     */
    [[nodiscard]] auto EcbDecrypt(std::span<const std::uint8_t, 16> Input,
        std::span<const std::uint8_t> Key)
        -> std::expected<std::array<std::uint8_t, 16>, Fault::Failure>;
}
