/**
 * @file compatible.hpp
 * @brief 错误码标准库兼容性支持
 * @details 提供 Fault::Code 与 std::error_code 和
 * boost::system::error_code 的双向兼容性实现，包括
 * 错误分类、哈希支持和隐式转换特化。
 * @note 该文件实现了 std 和 boost::system 命名空间中
 * 的特化，遵循标准库扩展规则。
 * @warning 修改此文件可能影响 ABI 兼容性。
 * @note 镜像自 include/prism/foundation/fault/，同步策略：锁定
 */
#pragma once

#include <common/Core/Fault/Code.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <string>
#include <system_error>
#include <type_traits>

namespace Preview::Fault
{

    /**
     * @brief 获取缓存的错误消息
     * @param c 错误码枚举值
     * @return 错误消息字符串的常量引用，生命周期与程序相同
     * @details 返回预分配的错误消息引用，首次调用时分配并
     * 缓存，后续调用直接返回引用，无内存分配。
     * @note 首次调用有一次分配开销，后续调用为零开销。
     */
    [[nodiscard]] inline auto CachedMessage(Code c) noexcept -> const std::string &
    {
        constexpr auto code_count = static_cast<std::size_t>(Code::_count);
        static const auto messages = []()
        {
            std::array<std::string, code_count + 1> arr{};
            for (std::size_t i = 0; i < code_count; ++i)
            {
                arr[i] = std::string(Describe(static_cast<Code>(i)));
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
     * @class FaultCategory
     * @brief std::error_code 错误分类
     * @details 实现 std::error_category 接口，为 Fault::Code
     * 提供标准库错误分类支持。通过 category() 函数获取
     * 全局单例实例。
     * @warning 不要直接实例化，应通过 category() 获取单例。
     */
    class FaultCategory : public std::error_category
    {
    public:
        /**
         * @brief 获取分类名称
         * @return 分类名称字符串 "Preview::fault"
         */
        [[nodiscard]] auto name() const noexcept -> const char * override
        {
            return "Preview::fault";
        }

        /**
         * @brief 获取错误码对应的消息
         * @param c 错误码整数值
         * @return 错误消息字符串
         */
        [[nodiscard]] auto message(int c) const -> std::string override
        {
            return CachedMessage(static_cast<Code>(c));
        }
    }; // class FaultCategory

    /**
     * @brief 获取状态分类单例
     * @return FaultCategory 单例引用，生命周期与程序相同
     * @details 首次调用时构造单例，C++11 保证线程安全。
     * @warning 不要在静态析构阶段使用返回的引用。
     */
    [[nodiscard]] inline auto category() noexcept -> const std::error_category &
    {
        static FaultCategory instance;
        return instance;
    }

} // namespace Preview::Fault

namespace Preview::Fault
{

    /**
     * @brief 创建错误码（std 路径 ADL 入口）
     * @param c 自定义错误码枚举值
     * @return 对应的标准错误码对象
     * @details 将 Fault::Code 枚举值转换为 std::error_code。
     * 留在 Preview::Fault 供 std::error_code 构造 ADL 查找。
     */
    [[nodiscard]] inline auto make_error_code(Code c) noexcept -> std::error_code
    {
        return {static_cast<int>(c), category()};
    }

} // namespace Preview::Fault

namespace std
{

    /**
     * @brief 特化 IsErrorCodeEnum
     * @details 标记 Fault::Code 为错误码枚举，启用与
     * std::error_code 的隐式转换。
     */
    template <>
    struct is_error_code_enum<Preview::Fault::Code> : std::true_type
    {
    };

    /**
     * @brief 特化 Hash
     * @details 为 Fault::Code 提供 std::hash 特化，使其
     * 可用于无序容器。哈希实现委托给 std::hash<int>。
     */
    template <>
    struct hash<Preview::Fault::Code>
    {
        /**
         * @brief 计算错误码的哈希值
         * @param c 错误码枚举值
         * @return 哈希值
         */
        [[nodiscard]] auto operator()(const Preview::Fault::Code c) const noexcept -> std::size_t
        {
            return std::hash<int>{}(static_cast<int>(c));
        }
    };
} // namespace std

namespace boost::system
{

    /**
     * @brief 特化 IsErrorCodeEnum
     * @details 标记 Fault::Code 为 Boost 错误码枚举，启用
     * 与 boost::system::error_code 的隐式转换。
     */
    template <>
    struct is_error_code_enum<Preview::Fault::Code> : std::true_type
    {
    };

    /**
     * @class FaultCategory
     * @brief Boost 错误码分类
     * @details 实现 boost::system::error_category 接口，
     * 与标准库版本保持功能对等。通过 Category() 获取
     * 全局单例。
     * @warning 不要直接实例化，应通过 category() 获取。
     */
    class FaultCategory final : public boost::system::error_category
    {
    public:
        /**
         * @brief 获取分类名称
         * @return 分类名称字符串 "Preview::fault"
         */
        [[nodiscard]] auto name() const noexcept -> const char * override
        {
            return "Preview::fault";
        }

        /**
         * @brief 获取错误码对应的消息
         * @param c 错误码整数值
         * @return 错误消息字符串
         */
        [[nodiscard]] auto message(int c) const -> std::string override
        {
            return Preview::Fault::CachedMessage(static_cast<Preview::Fault::Code>(c));
        }
    }; // class FaultCategory

    /**
     * @brief 获取 Boost 状态分类单例
     * @return FaultCategory 单例引用，生命周期与程序相同
     * @details 首次调用时构造单例，C++11 保证线程安全。
     * @warning 不要在静态析构阶段使用返回的引用。
     */
    [[nodiscard]] inline auto category() noexcept -> const boost::system::error_category &
    {
        static FaultCategory instance;
        return instance;
    }

    /**
     * @brief 创建 Boost 错误码
     * @param c 自定义错误码枚举值
     * @return 对应的 Boost 错误码对象
     * @details 将 Fault::Code 枚举值转换为
     * boost::system::error_code，配合特化支持隐式转换。
     */
    [[nodiscard]] inline auto make_error_code(const Preview::Fault::Code c) noexcept -> error_code
    {
        return {static_cast<int>(c), category()};
    }

} // namespace boost::system


