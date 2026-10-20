/**
 * @file Hkdf.hpp
 * @brief SHA、HMAC 与 TLS 1.3 HKDF 的同步值结果接口。
 * @details 所有输入仅借用到返回，输出由调用者或 expected 值拥有。
 *          不分配动态输出，不执行取消、半关闭或最终连接关闭，无 executor 约束。
 */
#pragma once

#include <Prism/Foundation/Utility/Crypto/Operation.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

namespace Prism::Crypto
{
    /** @brief SHA-256 固定摘要字节数。 */
    constexpr std::size_t Sha256Len = 32;
    /** @brief SHA-512 固定摘要字节数。 */
    constexpr std::size_t Sha512Len = 64;

    /**
     * @brief 计算 HMAC-SHA256；输入同步借用，成功值拥有 32 字节摘要。
     * @return 原生运算失败时返回 Failure，不提供伪造摘要。
     */
    [[nodiscard]] auto HmacSha256(std::span<const std::uint8_t> Key,
        std::span<const std::uint8_t> Data)
        -> std::expected<std::array<std::uint8_t, Sha256Len>, Fault::Failure>;

    /** @brief 计算 HMAC-SHA512；借用与错误契约同 HmacSha256，结果拥有 64 字节。 */
    [[nodiscard]] auto HmacSha512(std::span<const std::uint8_t> Key,
        std::span<const std::uint8_t> Data)
        -> std::expected<std::array<std::uint8_t, Sha512Len>, Fault::Failure>;

    /**
     * @brief 提取 HKDF-SHA256 伪随机密钥；空盐按 RFC 5869 使用 32 字节零盐。
     * @return 成功值拥有 PRK；任何 HMAC 失败直接向上返回，不继续派生。
     */
    [[nodiscard]] auto HkdfExtract(const std::span<const std::uint8_t> Salt,
                                        const std::span<const std::uint8_t> IKM)
        -> std::expected<std::array<std::uint8_t, Sha256Len>, Fault::Failure>;

    /** @brief 一次 HKDF 扩展所借用的完整 PRK 和域分离信息。 */
    struct HkdfExpandInput final
    {
        std::span<const std::uint8_t> Prk; ///< 至少 32 字节，完整参与 HMAC。
        std::span<const std::uint8_t> Info; ///< 上下文原始字节，不隐式截断。
    };

    /**
     * @brief 将 HKDF-SHA256 派生结果写入调用者拥有的缓冲区。
     * @details 输出与输入不得重叠，全部借用只持续到返回；上下文最多 514 字节，最大输出 8160 字节。
     *          参数拒绝不写输出；原生失败擦除输出，调用者必须丢弃它。
     * @return Success 或完整 Failure；无取消、关闭与 executor 行为。
     */
    [[nodiscard]] auto HkdfExpand(HkdfExpandInput Input,
        std::span<std::uint8_t> Output) -> Fault::Failure;

    /** @brief TLS 1.3 扩展标签的领域输入；输出长度以目标 span 为唯一事实。 */
    struct ExpandParams final
    {
        std::span<const std::uint8_t> Secret; ///< 借用的输入密钥。
        std::string_view Label; ///< 不含 tls13 前缀的标签。
        std::span<const std::uint8_t> Context; ///< 借用的上下文摘要。
    };

    /**
     * @brief 编码 RFC 8446 标签并派生到调用者缓冲区；借用、失败和关闭契约同 HkdfExpand。
     * @return 标签、上下文或输出超限时拒绝；底层失败原样返回。
     */
    [[nodiscard]] auto ExpandLabel(ExpandParams Params,
        std::span<std::uint8_t> Output) -> Fault::Failure;

    /** @brief 顺序参与一个 SHA-256 摘要的分段输入；描述表及各段均同步借用。 */
    struct HashInput final
    {
        explicit HashInput(const std::span<const std::span<const std::uint8_t>> Input) noexcept : Segments(Input) {}
        std::span<const std::span<const std::uint8_t>> Segments;
    };

    /**
     * @brief 顺序计算多段 SHA-256，无拼接、无动态分配，成功值拥有摘要。
     * @return 任一初始化、更新或收尾失败返回 Failure；无取消、关闭和 executor。
     */
    [[nodiscard]] auto Sha256(HashInput Input)
        -> std::expected<std::array<std::uint8_t, Sha256Len>, Fault::Failure>;

    /** @brief 单段 SHA-256；输入同步借用，成功值拥有摘要，失败与多段版本一致。 */
    [[nodiscard]] inline auto Sha256(const std::span<const std::uint8_t> Data)
        -> std::expected<std::array<std::uint8_t, Sha256Len>, Fault::Failure>
    {
        const std::array<std::span<const std::uint8_t>, 1> Segments{Data};
        return Sha256(HashInput{Segments});
    }
}
