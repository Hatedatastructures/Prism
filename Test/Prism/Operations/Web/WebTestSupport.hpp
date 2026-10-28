/**
 * @file WebTestSupport.hpp
 * @brief Operations Web 测试数据辅助函数。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <openssl/evp.h>

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace Prism::Testing::OperationsWeb
{
    /**
     * @brief 生成资源清单使用的小写 SHA-256 十六进制摘要。
     * @param Bytes 测试输入；仅在本次同步计算期间借用。
     * @return 成功时拥有 64 个十六进制字符，底层加密失败时保留原 Failure。
     */
    [[nodiscard]] inline auto Sha256Hex(const std::string_view Bytes)
        -> std::expected<std::string, Prism::Fault::Failure>
    {
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> Digest{};
        unsigned int DigestSize = 0;
        constexpr char EmptyInput = '\0';
        const auto *Input = Bytes.empty() ? &EmptyInput : Bytes.data();
        if (EVP_Digest(Input, Bytes.size(), Digest.data(), &DigestSize,
                EVP_sha256(), nullptr) != 1 || DigestSize != 32U)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::CryptoError});
        }

        constexpr std::string_view Hex = "0123456789abcdef";
        std::string Result;
        Result.reserve(DigestSize * 2);
        for (const auto Byte : std::span<const std::uint8_t>(Digest.data(), DigestSize))
        {
            Result.push_back(Hex[Byte >> 4]);
            Result.push_back(Hex[Byte & 15]);
        }
        return Result;
    }
}
