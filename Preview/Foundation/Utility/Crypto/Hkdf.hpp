/**
 * @file Hkdf.hpp
 * @brief SHA、HMAC 与 TLS 1.3 HKDF 的同步值结果接口。
 * @details 所有输入仅借用到返回，输出由调用者或 expected 值拥有。
 *          不分配动态输出，不执行取消、半关闭或最终连接关闭，无 executor 约束。
 */
#pragma once

#include <Preview/Foundation/Utility/Crypto/Operation.hpp>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string_view>

namespace Preview::Crypto
{
    /** @brief SHA-256 固定摘要字节数。 */
    constexpr std::size_t Sha256Len = 32;
    /** @brief SHA-512 固定摘要字节数。 */
    constexpr std::size_t Sha512Len = 64;

    /**
     * @brief 计算 HMAC-SHA256；输入同步借用，成功值拥有 32 字节摘要。
     * @return 原生运算失败时返回 Failure，不提供伪造摘要。
     */
    [[nodiscard]] inline auto HmacSha256(const std::span<const std::uint8_t> Key,
                                       const std::span<const std::uint8_t> Data)
        -> std::expected<std::array<std::uint8_t, Sha256Len>, Fault::Failure>
    {
        std::array<std::uint8_t, Sha256Len> Result{};
        const SecretScope Cleanup{Result};
        unsigned int Length = 0;
        ERR_clear_error();
        if (!HMAC(EVP_sha256(), Key.data(), Key.size(), Data.data(),
                  Data.size(), Result.data(), &Length) || Length != Result.size())
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
        }
        return Result;
    }

    /** @brief 计算 HMAC-SHA512；借用与错误契约同 HmacSha256，结果拥有 64 字节。 */
    [[nodiscard]] inline auto HmacSha512(const std::span<const std::uint8_t> Key,
                                       const std::span<const std::uint8_t> Data)
        -> std::expected<std::array<std::uint8_t, Sha512Len>, Fault::Failure>
    {
        std::array<std::uint8_t, Sha512Len> Result{};
        const SecretScope Cleanup{Result};
        unsigned int Length = 0;
        ERR_clear_error();
        if (!HMAC(EVP_sha512(), Key.data(), Key.size(), Data.data(),
                  Data.size(), Result.data(), &Length) || Length != Result.size())
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
        }
        return Result;
    }

    /**
     * @brief 提取 HKDF-SHA256 伪随机密钥；空盐按 RFC 5869 使用 32 字节零盐。
     * @return 成功值拥有 PRK；任何 HMAC 失败直接向上返回，不继续派生。
     */
    [[nodiscard]] inline auto HkdfExtract(const std::span<const std::uint8_t> Salt,
                                        const std::span<const std::uint8_t> IKM)
        -> std::expected<std::array<std::uint8_t, Sha256Len>, Fault::Failure>
    {
        if (Salt.empty())
        {
            const std::array<std::uint8_t, Sha256Len> ZeroSalt{};
            return HmacSha256(ZeroSalt, IKM);
        }
        return HmacSha256(Salt, IKM);
    }

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
    [[nodiscard]] inline auto HkdfExpand(const HkdfExpandInput Input,
                                       const std::span<std::uint8_t> Output) -> Fault::Failure
    {
        if (Input.Prk.size() < Sha256Len || Input.Info.size() > 514 || Output.size() > 255 * Sha256Len)
        {
            return {Fault::Code::InvalidArgument, {}};
        }
        if (Output.empty())
        {
            return {};
        }
        ERR_clear_error();
        if (HKDF_expand(Output.data(), Output.size(), EVP_sha256(), Input.Prk.data(),
                        Input.Prk.size(), Input.Info.data(), Input.Info.size()) != 1)
        {
            const auto Failure = Detail::NativeFailure(Fault::Code::CryptoError);
            OPENSSL_cleanse(Output.data(), Output.size());
            return Failure;
        }
        return {};
    }

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
    [[nodiscard]] inline auto ExpandLabel(const ExpandParams Params,
                                        const std::span<std::uint8_t> Output) -> Fault::Failure
    {
        constexpr std::string_view Prefix = "tls13 ";
        if (Params.Label.size() > 255 - Prefix.size() || Params.Context.size() > 255 ||
            Output.size() > 255 * Sha256Len)
        {
            return {Fault::Code::InvalidArgument, {}};
        }
        std::array<std::uint8_t, 2 + 1 + 255 + 1 + 255> LabelBuffer{};
        const SecretScope Cleanup{LabelBuffer};
        std::size_t Position = 0;
        LabelBuffer[Position++] = static_cast<std::uint8_t>(Output.size() >> 8);
        LabelBuffer[Position++] = static_cast<std::uint8_t>(Output.size() & 0xFF);
        LabelBuffer[Position++] = static_cast<std::uint8_t>(Prefix.size() + Params.Label.size());
        std::memcpy(LabelBuffer.data() + Position, Prefix.data(), Prefix.size());
        Position += Prefix.size();
        if (!Params.Label.empty())
        {
            std::memcpy(LabelBuffer.data() + Position, Params.Label.data(), Params.Label.size());
            Position += Params.Label.size();
        }
        LabelBuffer[Position++] = static_cast<std::uint8_t>(Params.Context.size());
        if (!Params.Context.empty())
        {
            std::memcpy(LabelBuffer.data() + Position, Params.Context.data(), Params.Context.size());
            Position += Params.Context.size();
        }
        return HkdfExpand({Params.Secret, {LabelBuffer.data(), Position}}, Output);
    }

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
    [[nodiscard]] inline auto Sha256(const HashInput Input)
        -> std::expected<std::array<std::uint8_t, Sha256Len>, Fault::Failure>
    {
        SHA256_CTX Context{};
        const SecretScope ContextCleanup{
            {reinterpret_cast<std::uint8_t *>(&Context), sizeof(Context)}};
        std::array<std::uint8_t, Sha256Len> Output{};
        const SecretScope OutputCleanup{Output};
        ERR_clear_error();
        if (SHA256_Init(&Context) != 1)
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
        }
        for (const auto Segment : Input.Segments)
        {
            if (SHA256_Update(&Context, Segment.data(), Segment.size()) != 1)
            {
                return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
            }
        }
        if (SHA256_Final(Output.data(), &Context) != 1)
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
        }
        return Output;
    }

    /** @brief 单段 SHA-256；输入同步借用，成功值拥有摘要，失败与多段版本一致。 */
    [[nodiscard]] inline auto Sha256(const std::span<const std::uint8_t> Data)
        -> std::expected<std::array<std::uint8_t, Sha256Len>, Fault::Failure>
    {
        const std::array<std::span<const std::uint8_t>, 1> Segments{Data};
        return Sha256(HashInput{Segments});
    }
}
