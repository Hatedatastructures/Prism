/**
 * @file Operation.cpp
 * @brief 原生密码学错误捕获与诊断格式化实现。
 */
#include <Prism/Foundation/Utility/Crypto/Operation.hpp>

#include <openssl/err.h>

#include <array>
#include <cstdint>

namespace Prism::Crypto::Detail
{
    auto NativeCategory::message(const int Value) const -> std::string
    {
        std::array<char, 256> Buffer{};
        ERR_error_string_n(static_cast<std::uint32_t>(Value), Buffer.data(), Buffer.size());
        return std::string{Buffer.data()};
    }

    auto NativeFailure(const Fault::Code Code) noexcept -> Fault::Failure
    {
        static const NativeCategory Category;
        const auto Native = ERR_peek_last_error();
        ERR_clear_error();
        return {Code, std::error_code{static_cast<int>(Native), Category}};
    }
} // namespace Prism::Crypto::Detail
