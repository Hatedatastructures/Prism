/**
 * @file Operation.hpp
 * @brief 密码学原生失败与临时秘密清理。
 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <openssl/err.h>
#include <Preview/Foundation/Utility/Crypto/SecretScope.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <system_error>

namespace Preview::Crypto::Detail
{
    /** @brief 保留 BoringSSL 错误编号的进程生命周期分类。 */
    class NativeCategory final : public std::error_category
    {
    public:
        /** @brief 标准库分类接口；返回静态名称。 */
        [[nodiscard]] auto name() const noexcept -> const char * override
        {
            return "Preview.Crypto.BoringSSL";
        }

        /** @brief 仅显式诊断时格式化原生错误；密码学热路径不调用。 */
        [[nodiscard]] auto message(const int Value) const -> std::string override
        {
            std::array<char, 256> Buffer{};
            ERR_error_string_n(static_cast<std::uint32_t>(Value), Buffer.data(), Buffer.size());
            return std::string{Buffer.data()};
        }
    };

    /** @brief 获取当前失败并清空已消费错误；仅紧接失败的原生调用使用。 */
    [[nodiscard]] inline auto NativeFailure(const Fault::Code Code) noexcept -> Fault::Failure
    {
        static const NativeCategory Category;
        const auto Native = ERR_peek_last_error();
        ERR_clear_error();
        return {Code, std::error_code{static_cast<int>(Native), Category}};
    }

}
