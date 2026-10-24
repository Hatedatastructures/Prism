/**
 * @file SecretScope.hpp
 * @brief 同步借用秘密缓冲区并在作用域结束可靠擦除。
 */
#pragma once

#include <cstdint>
#include <span>

namespace Prism::Crypto
{
    /**
     * @brief 借用一段秘密内存，在同步操作离开作用域时可靠擦除。
     * @details 不拥有输入内存、不分配；输入必须存活至析构。不可复制或转移。
     *          无取消、半关闭或 executor；最终擦除者是本作用域对象。
     */
    class SecretScope final
    {
    public:
        explicit SecretScope(const std::span<std::uint8_t> Bytes) noexcept : Bytes_(Bytes) {}
        SecretScope(const SecretScope &) = delete;
        auto operator=(const SecretScope &) -> SecretScope & = delete;

        ~SecretScope();

    private:
        std::span<std::uint8_t> Bytes_;
    };
}
