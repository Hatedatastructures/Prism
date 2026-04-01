/**
 * @file compatible.hpp
 * @brief 错误码标准库兼容性支持
 * @details 提供 psm::fault::code 与 std::error_code 和 boost::system::error_code
 * 的兼容性实现。该模块是错误码系统的桥梁，使自定义错误码能够无缝集成到
 * C++ 标准库和 Boost 错误处理体系。兼容性特性包括标准库集成，通过
 * std::is_error_code_enum 特化支持隐式转换到 std::error_code；Boost 集成，
 * 通过 boost::system::is_error_code_enum 特化支持隐式转换到 boost 错误码；
 * 哈希支持，通过 std::hash 特化使错误码可用于无序容器；独立的错误分类
 * fault_category 提供错误消息本地化。
 * 设计目标是零摩擦集成，用户代码无需显式转换即可与标准库错误处理协作；
 * 性能优化，使用缓存的错误消息避免重复分配；双向兼容，同时支持 C++ 标准
 * 库和 Boost 生态系统，确保跨库互操作性。
 * @note 该文件实现了 std 和 boost::system 命名空间中的特化，遵循标准库扩展规则。
 * @warning 修改此文件可能影响 ABI 兼容性，需谨慎处理。
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
     * @details 返回预分配的错误消息字符串引用，避免重复构造和内存分配。
     * 该函数是性能优化的关键，所有错误消息在首次调用时一次性分配并缓存，
     * 后续调用直接返回引用，无内存分配。静态局部变量初始化是线程安全的，
     * 由 C++11 标准保证。对于未知错误码返回 "unknown"。
     * @note 首次调用会有一次性内存分配开销，后续调用为零开销。
     * @warning 返回的引用是只读的，不要修改其内容。
     */
    [[nodiscard]] inline const std::string &cached_message(code c) noexcept
    {
        constexpr std::size_t code_count = static_cast<std::size_t>(code::_count);
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
     * @details 实现 std::error_category 接口，为 psm::fault::code 提供标准库
     * 错误分类支持。该类是错误码系统与 C++ 标准库错误处理体系之间的桥梁。
     * 核心职责包括分类标识，通过 name() 返回 "psm::fault" 标识错误来源；
     * 消息转换，通过 message() 将整数错误码转换为人类可读字符串；相等比较，
     * 继承的 == 运算符提供分类对象相等性比较。
     * 设计特性包括单例模式，通过 category() 函数返回全局单例实例，确保全局
     * 一致性；线程安全，std::error_category 成员函数要求线程安全，符合多线程
     * 环境使用；性能优化，message() 委托给 cached_message() 避免重复分配。
     * @note 该类遵循 std::error_category 约定，不添加额外状态。
     * @warning 不要直接实例化此类，应通过 category() 函数获取单例。
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
    };

    /**
     * @brief 获取状态分类单例
     * @return fault_category 单例引用，生命周期与程序相同
     * @details 返回 fault_category 的全局单例引用。该函数是标准库错误分类系统
     * 的入口点，提供统一错误分类访问接口。单例特性包括延迟初始化，首次调用时
     * 构造单例，后续调用直接返回引用；线程安全，C++11 保证静态局部变量初始化
     * 是线程安全的；零开销，返回引用，无拷贝开销。
     * 使用场景包括错误码构造，创建 std::error_code 对象时需要关联分类单例；
     * 分类比较，比较错误码是否属于 fault 分类；标准库集成，与 std::system_error
     * 等标准库组件协作。
     * @note 该单例用于所有需要 fault 错误分类的场景，确保全局一致性。
     * @warning 不要在静态析构阶段使用返回的引用，可能导致静态初始化顺序问题。
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
     * @details 将 psm::fault::code 枚举值转换为 std::error_code 对象。该函数
     * 启用自定义错误码与标准库错误处理系统的集成，是错误码兼容性的核心组件。
     * 转换机制包括错误值映射，枚举值安全转换为 int 类型，保持值语义不变；
     * 分类关联，与 fault_category 单例关联，标识错误来源；隐式转换，配合
     * std::is_error_code_enum 特化支持隐式转换，提供零摩擦集成。
     * 设计优势包括类型安全，编译时检查确保只有 psm::fault::code 枚举可以转换；
     * 零开销，转换过程无动态分配，仅涉及值复制和分类关联；双向兼容，生成的
     * std::error_code 可反向获取原始枚举值（通过 value()）。
     * @note 由于 std::is_error_code_enum 特化，通常不需要显式调用此函数。
     * @warning 转换后的错误码仅包含原始枚举值，不包含额外上下文信息。
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
     * @details 标记 psm::fault::code 为错误码枚举，启用与 std::error_code 的
     * 隐式转换。该特化是 C++ 标准库错误处理系统的关键集成点。作用机制包括
     * 类型标记，继承自 std::true_type，编译时标记 psm::fault::code 为错误码
     * 枚举类型；构造函数启用，使 std::error_code 构造函数能够接受 psm::fault::code
     * 参数；隐式转换，启用从 psm::fault::code 到 std::error_code 的隐式转换，
     * 提供零摩擦集成。
     * @note 该特化是 SFINAE 友好的，可用于模板元编程。
     * @warning 修改此特化可能破坏与标准库的兼容性。
     */
    template <>
    struct is_error_code_enum<psm::fault::code> : std::true_type
    {
    };

    /**
     * @brief 特化 hash
     * @details 为 psm::fault::code 提供 std::hash 特化，使其可用于无序容器，
     * 例如 std::unordered_set、std::unordered_map 等。该特化是标准库容器
     * 兼容性的关键部分。哈希算法采用简单委托，将枚举值转换为 int，委托给
     * std::hash<int>；确定性，相同的枚举值总是产生相同的哈希值；低碰撞，
     * 枚举值分布均匀，哈希碰撞概率低。
     * 标准符合性包括命名空间规则，根据 C++ 标准，hash 特化应定义在 std
     * 命名空间中；特化权限，遵循 [namespace.std] 条款，允许用户向 std 添加
     * 模板特化；接口约定，满足标准库对哈希函数的所有要求：确定性、不抛异常、
     * 一致性。
     * @note 哈希函数满足标准库对哈希的所有要求：确定性、不抛异常、一致性。
     * @warning 哈希值可能在不同程序运行间变化，如果 std::hash<int> 实现变化。
     */
    template <>
    struct hash<psm::fault::code>
    {
        /**
         * @brief 计算错误码的哈希值
         * @param c 错误码枚举值
         * @return 哈希值
         * @details 将 psm::fault::code 枚举值转换为哈希值，用于无序容器。
         * 哈希实现委托给 std::hash<int>，保证质量。
         * @note 哈希实现委托给 std::hash<int>，保证质量。
         * @warning 不要依赖哈希值的具体数值，仅用于容器内部组织。
         */
        [[nodiscard]] size_t operator()(const psm::fault::code c) const noexcept
        {
            return hash<int>{}(static_cast<int>(c));
        }
    };
}

namespace boost::system
{
    /**
     * @brief 特化 is_error_code_enum
     * @details 标记 psm::fault::code 为 Boost 错误码枚举，启用与
     * boost::system::error_code 的隐式转换。该特化是 Boost.System 错误处理
     * 系统的关键集成点。作用机制包括类型标记，继承自 std::true_type，编译时
     * 标记 psm::fault::code 为错误码枚举类型；构造函数启用，使 boost::system::
     * error_code 构造函数能够接受 psm::fault::code 参数；隐式转换，启用从
     * psm::fault::code 到 boost::system::error_code 的隐式转换，提供零摩擦集成。
     * 兼容性设计包括对称设计，与 std::is_error_code_enum 特化保持对称，提供
     * 一致的开发体验；双向互操作，支持 psm::fault::code 与 boost::system::
     * error_code 之间的双向转换；生态系统集成，确保项目错误码能够与使用 Boost
     * 的第三方库无缝协作。
     * @note 该特化使 psm::fault::code 能够与 Boost 生态系统的错误处理组件互操作。
     * @warning 修改此特化可能破坏与 Boost.System 的兼容性。
     */
    template <>
    struct is_error_code_enum<psm::fault::code> : std::true_type
    {
    };

    /**
     * @class fault_category
     * @brief Boost 错误码分类
     * @details 实现 boost::system::error_category 接口，为 psm::fault::code
     * 提供 Boost 错误分类支持。该类是错误码系统与 Boost.System 错误处理体系
     * 之间的桥梁。核心职责包括分类标识，通过 name() 返回 "psm::fault" 标识
     * 错误来源；消息转换，通过 message() 将整数错误码转换为人类可读字符串；
     * 相等比较，继承的 == 运算符提供分类对象相等性比较。
     * 设计特性包括单例模式，通过 category() 函数返回全局单例实例，确保全局
     * 一致性；线程安全，boost::system::error_category 成员函数要求线程安全，
     * 符合多线程环境使用；性能优化，message() 委托给 psm::fault::cached_message()
     * 避免重复分配。Boost 兼容性包括接口一致，实现与 std::error_category 相同
     * 的接口，保持开发一致性；无状态设计，不添加额外状态成员，遵循 Boost 分类
     * 设计模式；异常规范，成员函数遵循 Boost 异常规范，与 Boost.System 组件
     * 无缝协作。
     * @note 该类遵循 boost::system::error_category 约定，与标准库版本保持功能对等。
     * @warning 不要直接实例化此类，应通过 category() 函数获取单例。
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
    };

    /**
     * @brief 获取 Boost 状态分类单例
     * @return fault_category 单例引用，生命周期与程序相同
     * @details 返回 fault_category 的全局单例引用。该函数是 Boost.System 错误
     * 分类系统的入口点，提供统一错误分类访问接口。单例特性包括延迟初始化，
     * 首次调用时构造单例，后续调用直接返回引用；线程安全，C++11 保证静态
     * 局部变量初始化是线程安全的；零开销，返回引用，无拷贝开销。
     * 使用场景包括错误码构造，创建 boost::system::error_code 对象时需要关联
     * 分类单例；分类比较，比较错误码是否属于 fault 分类；Boost 集成，与 Boost
     * 生态系统的错误处理组件协作。
     * @note 该单例用于所有需要 fault 错误分类的 Boost 相关场景，确保全局一致性。
     * @warning 不要在静态析构阶段使用返回的引用，可能导致静态初始化顺序问题。
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
     * @details 将 psm::fault::code 枚举值转换为 boost::system::error_code 对象。
     * 该函数启用自定义错误码与 Boost.System 错误处理系统的集成，是 Boost
     * 兼容性的核心组件。转换机制包括错误值映射，枚举值安全转换为 int 类型，
     * 保持值语义不变；分类关联，与 fault_category 单例关联，标识错误来源；
     * 隐式转换，配合 boost::system::is_error_code_enum 特化支持隐式转换，
     * 提供零摩擦集成。
     * 设计优势包括类型安全，编译时检查确保只有 psm::fault::code 枚举可以转换；
     * 零开销，转换过程无动态分配，仅涉及值复制和分类关联；双向兼容，生成的
     * boost::system::error_code 可反向获取原始枚举值（通过 value()）。
     * @note 由于 boost::system::is_error_code_enum 特化，通常不需要显式调用此函数。
     * @warning 转换后的错误码仅包含原始枚举值，不包含额外上下文信息。
     */
    inline error_code make_error_code(const psm::fault::code c) noexcept
    {
        return {static_cast<int>(c), category()};
    }
}
