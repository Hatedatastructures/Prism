/**
 * @file compatible.hpp
 * @brief 错误码标准库兼容性支持
 * @details 提供 fault::code 与 std::error_code 和
 * boost::system::error_code 的双向兼容性实现，包括
 * 错误分类、哈希支持和隐式转换特化。
 * @note 该文件实现了 std 和 boost::system 命名空间中
 * 的特化，遵循标准库扩展规则。
 * @warning 修改此文件可能影响 ABI 兼容性。
 */
#pragma once

#include <prism/fault/code.hpp>
#include <system_error>
#include <string>
#include <array>
#include <type_traits>
#include <boost/system/error_code.hpp>

namespace psm::fault
{
    /**
     * @brief 获取缓存的错误消息
     * @param c 错误码枚举值
     * @return 错误消息字符串的常量引用，生命周期与程序相同
     * @details 返回预分配的错误消息引用，首次调用时分配并
     * 缓存，后续调用直接返回引用，无内存分配。
     * @note 首次调用有一次分配开销，后续调用为零开销。
     */
    [[nodiscard]] inline const std::string &cached_message(code c) noexcept
    {
        constexpr auto code_count = static_cast<std::size_t>(code::_count);
        static const auto messages = []()
        {
            std::array<std::string, code_count + 1> arr{};
            for (std::size_t i = 0; i < code_count; ++i)
            {
                arr[i] = std::string(describe(static_cast<code>(i)));
            }
            arr[code_count] = "unknown";
            return arr;
        }();

        if (const auto index = static_cast<std::size_t>(c); index < code_count)
        {
            return messages[index];
        }
        return messages[code_count];
    }

    /**
     * @class fault_category
     * @brief std::error_code 错误分类
     * @details 实现 std::error_category 接口，为 fault::code
     * 提供标准库错误分类支持。通过 category() 函数获取
     * 全局单例实例。
     * @warning 不要直接实例化，应通过 category() 获取单例。
     */
    class fault_category : public std::error_category
    {
    public:
        /**
         * @brief 获取分类名称
         * @return 分类名称字符串 "psm::fault"
         */
        [[nodiscard]] const char *name() const noexcept override
        {
            return "psm::fault";
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
    }; // class fault_category

    /**
     * @brief 获取状态分类单例
     * @return fault_category 单例引用，生命周期与程序相同
     * @details 首次调用时构造单例，C++11 保证线程安全。
     * @warning 不要在静态析构阶段使用返回的引用。
     */
    inline const std::error_category &category() noexcept
    {
        static fault_category instance;
        return instance;
    }

    /**
     * @brief 创建错误码
     * @param c 自定义错误码枚举值
     * @return 对应的标准错误码对象
     * @details 将 fault::code 枚举值转换为 std::error_code，
     * 配合 is_error_code_enum 特化支持隐式转换。
     * @note 通常不需要显式调用此函数。
     */
    inline std::error_code make_error_code(code c) noexcept
    {
        return {static_cast<int>(c), category()};
    }
} // namespace psm::fault

namespace std
{
    /**
     * @brief 特化 is_error_code_enum
     * @details 标记 fault::code 为错误码枚举，启用与
     * std::error_code 的隐式转换。
     */
    template <>
    struct is_error_code_enum<psm::fault::code> : std::true_type
    {
    };

    /**
     * @brief 特化 hash
     * @details 为 fault::code 提供 std::hash 特化，使其
     * 可用于无序容器。哈希实现委托给 std::hash<int>。
     */
    template <>
    struct hash<psm::fault::code>
    {
        /**
         * @brief 计算错误码的哈希值
         * @param c 错误码枚举值
         * @return 哈希值
         */
        [[nodiscard]] size_t operator()(const psm::fault::code c) const noexcept
        {
            return hash<int>{}(static_cast<int>(c));
        }
    };
} // namespace std

namespace boost::system
{
    /**
     * @brief 特化 is_error_code_enum
     * @details 标记 fault::code 为 Boost 错误码枚举，启用
     * 与 boost::system::error_code 的隐式转换。
     */
    template <>
    struct is_error_code_enum<psm::fault::code> : std::true_type
    {
    };

    /**
     * @class fault_category
     * @brief Boost 错误码分类
     * @details 实现 boost::system::error_category 接口，
     * 与标准库版本保持功能对等。通过 category() 获取
     * 全局单例。
     * @warning 不要直接实例化，应通过 category() 获取。
     */
    class fault_category final : public error_category
    {
    public:
        /**
         * @brief 获取分类名称
         * @return 分类名称字符串 "psm::fault"
         */
        [[nodiscard]] const char *name() const noexcept override
        {
            return "psm::fault";
        }

        /**
         * @brief 获取错误码对应的消息
         * @param c 错误码整数值
         * @return 错误消息字符串
         */
        [[nodiscard]] std::string message(int c) const override
        {
            return psm::fault::cached_message(static_cast<psm::fault::code>(c));
        }
    }; // class fault_category

    /**
     * @brief 获取 Boost 状态分类单例
     * @return fault_category 单例引用，生命周期与程序相同
     * @details 首次调用时构造单例，C++11 保证线程安全。
     * @warning 不要在静态析构阶段使用返回的引用。
     */
    inline const error_category &category() noexcept
    {
        static fault_category instance;
        return instance;
    }

    /**
     * @brief 创建 Boost 错误码
     * @param c 自定义错误码枚举值
     * @return 对应的 Boost 错误码对象
     * @details 将 fault::code 枚举值转换为
     * boost::system::error_code，配合特化支持隐式转换。
     */
    inline error_code make_error_code(const psm::fault::code c) noexcept
    {
        return {static_cast<int>(c), category()};
    }
} // namespace boost::system
