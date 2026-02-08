/**
 * @file compatible.hpp
 * @brief 错误码标准库兼容性支持
 * @details 提供 `ngx::gist::code` 与 `std::error_code` 和 `boost::system::error_code` 的兼容性实现。
 * 包含错误码分类、转换函数和特化，使自定义错误码能够无缝集成到标准错误处理体系。
 */
#pragma once

#include <forward-engine/gist/code.hpp>
#include <system_error>
#include <string>
#include <array>
#include <type_traits>
#include <boost/system/error_code.hpp>


namespace ngx::gist
{
    /**
     * @brief 获取缓存的错误消息
     * @details 返回预分配的错误消息字符串引用，避免重复构造和内存分配。
     * @param c 错误码
     * @return 错误消息字符串的常量引用
     */
    [[nodiscard]] inline const std::string &cached_message(code c) noexcept
    {
        constexpr auto code_count = static_cast<int>(code::_count);
        static const auto messages = []()
        {
            std::array<std::string, code_count> arr{};
            for (int i = 0; i < code_count; ++i)
            {
                arr[i] = std::string(describe(static_cast<code>(i)));
            }
            arr[code_count] = "unknown";
            return arr;
        }();

        if (const int index = static_cast<int>(c); index >= 0 && index < code_count)
        {
            return messages[index];
        }
        return messages[code_count];
    }

    /**
     * @brief `std::error_code` 分类
     * @details 用于与 `std::error_code` 体系对接，提供错误码到字符串的转换。
     */
    class gist_category : public std::error_category
    {
    public:
        /**
         * @brief 获取分类名称
         * @return 分类名称字符串 "ngx::gist"
         */
        [[nodiscard]] const char *name() const noexcept override
        {
            return "ngx::gist";
        }

        /**
         * @brief 获取错误码对应的消息
         * @param c 错误码整数值
         * @return 错误消息字符串
         */
        [[nodiscard]] std::string message(int c) const override
        {
            return cached_message(static_cast<code>(c));
        }
    };
    /**
     * @brief 获取状态分类单例
     * @return gist_category 单例引用
     */
    inline const std::error_category &category() noexcept
    {
        static gist_category instance;
        return instance;
    }

    /**
     * @brief 创建错误码
     * @param c 自定义错误码枚举
     * @return 对应的 std::error_code
     */
    inline std::error_code make_error_code(code c) noexcept
    {
        return {static_cast<int>(c), category()};
    }
}

namespace std
{
    /**
     * @brief 特化 is_error_code_enum
     * @details 标记 ngx::gist::code 为错误码枚举，启用与 std::error_code 的隐式转换。
     */
    template <>
    struct is_error_code_enum<ngx::gist::code> : std::true_type
    {
    };

    /**
     * @brief 特化 hash
     * @details 使 ngx::gist::code 可用于无序容器（std::unordered_set, std::unordered_map 等）。
     */
    template <>
    struct hash<ngx::gist::code>
    {
        [[nodiscard]] size_t operator()(const ngx::gist::code c) const noexcept
        {
            return hash<int>{}(static_cast<int>(c));
        }
    };
}

namespace boost::system
{
    /**
     * @brief 特化 is_error_code_enum
     * @details 标记 ngx::gist::code 为 Boost 错误码枚举，启用与 boost::system::error_code 的隐式转换。
     */
    template <>
    struct is_error_code_enum<ngx::gist::code> : std::true_type
    {
    };

    /**
     * @brief Boost 错误码分类
     * @details 提供与 Boost.System 错误码体系的兼容性。
     */
    class gist_category final : public error_category
    {
    public:
        /**
         * @brief 获取分类名称
         * @return 分类名称字符串 "ngx::gist"
         */
        [[nodiscard]] const char *name() const noexcept override
        {
            return "ngx::gist";
        }

        /**
         * @brief 获取错误码对应的消息
         * @param c 错误码整数值
         * @return 错误消息字符串
         */
        [[nodiscard]] std::string message(int c) const override
        {
            return ngx::gist::cached_message(static_cast<ngx::gist::code>(c));
        }
    };

    /**
     * @brief 获取 Boost 状态分类单例
     * @return gist_category 单例引用
     */
    inline const error_category &category() noexcept
    {
        static gist_category instance;
        return instance;
    }

    /**
     * @brief 创建 Boost 错误码
     * @param c 自定义错误码枚举
     * @return 对应的 boost::system::error_code
     */
    inline error_code make_error_code(const ngx::gist::code c) noexcept
    {
        return {static_cast<int>(c), category()};
    }
}