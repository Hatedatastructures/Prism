/**
 * @file compatible.hpp
 * @brief 错误码标准库兼容性支持
 * @details 提供 `ngx::gist::code` 与 `std::error_code` 和 `boost::system::error_code` 的兼容性实现。该模块是错误码系统的桥梁，使自定义错误码能够无缝集成到 `C++` 标准库和 `Boost` 错误处理体系。
 * 
 * 兼容性特性：
 * @details - 标准库集成：`std::is_error_code_enum` 特化，支持隐式转换到 `std::error_code`；
 * @details - `Boost` 集成：`boost::system::is_error_code_enum` 特化，支持隐式转换到 `boost::system::error_code`；
 * @details - 哈希支持：`std::hash` 特化，使错误码可用于无序容器；
 * @details - 分类系统：独立的错误分类（`gist_category`）提供错误消息本地化。
 * 
 * 设计目标：
 * @details - 零摩擦集成：用户代码无需显式转换即可与标准库错误处理协作；
 * @details - 性能优化：使用缓存的错误消息避免重复分配
 * @details - 双向兼容：同时支持 `C++` 标准库和 `Boost` 生态系统，确保跨库互操作性。
 * 
 * 架构定位：
 * @details - 标准库扩展：在 `std` 命名空间中特化 `is_error_code_enum` 和 `hash`，遵循标准库扩展规则；
 * @details - `Boost` 适配：在 `boost::system` 命名空间中提供相应特化，保持与 `Boost.System` 的兼容性；
 * @details - 错误码桥接：作为 `ngx::gist::code` 与第三方错误处理系统之间的适配层。
 * 
 * @note 该文件实现了 `std` 和 `boost::system` 命名空间中的特化，遵循标准库扩展规则。
 * @warning 修改此文件可能影响 `ABI` 兼容性，需谨慎处理。
 * ```
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
     * @param c 错误码枚举值
     * @return `const std::string&` 错误消息字符串的常量引用，生命周期与程序相同
     * @note 首次调用会有一次性内存分配开销，后续调用为零开销。
     * @warning 返回的引用是只读的，不要修改其内容。
     * @throws 无异常（函数标记为 `noexcept`，但首次调用时 `std::string` 构造可能抛出 `std::bad_alloc`）
     * @details 返回预分配的错误消息字符串引用，避免重复构造和内存分配。该函数是性能优化的关键
     * 
     * 性能特性：
     * @details - 初始化时分配：所有错误消息在首次调用时一次性分配并缓存；
     * @details - 零运行时分配：后续调用直接返回引用，无内存分配；
     * @details - 线程安全：静态局部变量初始化是线程安全的（C++11 保证）。
     * 
     * ```
     * // 使用示例：获取错误消息
     * ngx::gist::code ec = ngx::gist::code::connection_refused;
     * const std::string& msg = ngx::gist::cached_message(ec);
     * trace::error("Connection failed: {}", msg);
     * // 性能对比：使用缓存 vs 动态构造
     * auto start = std::chrono::high_resolution_clock::now();
     * for (int i = 0; i < 1000; ++i) 
     * {
     *     const auto& cached = ngx::gist::cached_message(ec);  // 零分配
     * }
     * auto end = std::chrono::high_resolution_clock::now();
     * // 缓存版本比动态构造 std::string(describe(ec)) 快几个数量级
     * ```
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
     * @class gist_category
     * @brief `std::error_code` 错误分类
     * @details 实现 `std::error_category` 接口，为 `ngx::gist::code` 提供标准库错误分类支持。该类是错误码系统与 `C++` 标准库错误处理体系之间的桥梁。
     * 
     * 核心职责：
     * @details - 分类标识：通过 `name()` 返回 "ngx::gist" 标识错误来源；
     * @details - 消息转换：通过 `message()` 将整数错误码转换为人类可读字符串；
     * @details - 相等比较：继承的 `==` 运算符提供分类对象相等性比较。
     * 
     * 设计特性：
     * @details - 单例模式：通过 `category()` 函数返回全局单例实例，确保全局一致性；
     * @details - 线程安全：`std::error_category` 成员函数要求线程安全，符合多线程环境使用；
     * @details - 性能优化：`message()` 委托给 `cached_message()` 避免重复分配。
     * 
     * 标准符合性：
     * @details - 接口完整：完整实现 `std::error_category` 要求的纯虚函数；
     * @details - 无状态设计：不添加额外状态成员，遵循标准库分类设计模式；
     * @details - 异常规范：成员函数遵循标准库异常规范，`name()` 为 `noexcept`，`message()` 可能抛出 `std::bad_alloc`。
     * 
     * @note 该类遵循 `std::error_category` 约定，不添加额外状态。
     * @warning 不要直接实例化此类，应通过 `category()` 函数获取单例。
     * @throws 无异常（所有成员函数标记为 `noexcept` 或仅可能抛出 `std::bad_alloc`）
     * 
     * ```
     * // 使用示例：获取分类单例
     * const std::error_category& cat = ngx::gist::category();
     * std::cout << "Category name: " << cat.name() << std::endl;
     * // 使用示例：创建标准错误码
     * std::error_code ec(static_cast<int>(ngx::gist::code::io_error), cat);
     * std::cout << "Error message: " << ec.message() << std::endl;
     * // 使用示例：分类比较
     * if (ec.category() == ngx::gist::category()) 
     * {
     *     std::cout << "Error belongs to gist category" << std::endl;
     * }
     * ```
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
     * @details 返回 `gist_category` 的全局单例引用。该函数是标准库错误分类系统的入口点，提供统一错误分类访问接口。
     * 
     * 单例特性：
     * @details - 延迟初始化：首次调用时构造单例，后续调用直接返回引用；
     * @details - 线程安全：`C++11` 保证静态局部变量初始化是线程安全的；
     * @details - 零开销：返回引用，无拷贝开销
     * 
     * 设计考虑：
     * @details - 全局一致性：确保整个项目使用相同的错误分类实例；
     * @details - 生命周期管理：单例生命周期与程序相同，避免重复构造和销毁；
     * @details - 异常安全：首次调用可能抛出 `std::bad_alloc`，后续调用保证不抛异常。
     * 
     * 使用场景：
     * @details - 错误码构造：创建 `std::error_code` 对象时需要关联分类单例；
     * @details - 分类比较：比较错误码是否属于 `gist` 分类；
     * @details - 标准库集成：与 `std::system_error` 等标准库组件协作。
     * 
     * @return `const std::error_category&` `gist_category` 单例引用，生命周期与程序相同
     * @note 该单例用于所有需要 `gist` 错误分类的场景，确保全局一致性。
     * @warning 不要在静态析构阶段使用返回的引用，可能导致静态初始化顺序问题。
     * @throws 无异常（函数标记为 `noexcept`，但单例构造可能抛出 `std::bad_alloc`）
     * 
     * ```
     * // 使用示例：获取分类单例
     * const auto& cat = ngx::gist::category();
     * // 使用示例：创建标准错误码
     * std::error_code ec(42, cat);  // 自定义错误码 42
     * // 使用示例：检查分类
     * if (ec.category() == ngx::gist::category()) {
     *     std::cout << "This is a gist error" << std::endl;
     * }
     * ```
     */
    inline const std::error_category &category() noexcept
    {
        static gist_category instance;
        return instance;
    }

    /**
     * @brief 创建错误码
     * @details 将 `ngx::gist::code` 枚举值转换为 `std::error_code` 对象。该函数启用自定义错误码与标准库错误处理系统的集成，是错误码兼容性的核心组件。
     * 
     * 转换机制：
     * @details - 错误值映射：枚举值安全转换为 `int` 类型，保持值语义不变；
     * @details - 分类关联：与 `gist_category` 单例关联，标识错误来源；
     * @details - 隐式转换：配合 `std::is_error_code_enum` 特化支持隐式转换，提供零摩擦集成。
     * 
     * 使用场景：
     * @details - 显式创建：直接调用 `make_error_code()` 创建 `std::error_code` 对象；
     * @details - 隐式转换：依赖 `std::is_error_code_enum` 特化自动转换枚举值为错误码；
     * @details - 标准库集成：与 `std::system_error`、`std::error_code` 构造函数等标准库组件协作。
     * 
     * 设计优势：
     * @details - 类型安全：编译时检查确保只有 `ngx::gist::code` 枚举可以转换；
     * @details - 零开销：转换过程无动态分配，仅涉及值复制和分类关联；
     * @details - 双向兼容：生成的 `std::error_code` 可反向获取原始枚举值（通过 `value()`）。
     * 
     * @param c 自定义错误码枚举值
     * @return `std::error_code` 对应的标准错误码对象
     * @note 由于 `std::is_error_code_enum` 特化，通常不需要显式调用此函数。
     * @warning 转换后的错误码仅包含原始枚举值，不包含额外上下文信息。
     * @throws 无异常（函数标记为 `noexcept`）
     * 
     * ```
     * // 使用示例：显式创建错误码
     * std::error_code ec = ngx::gist::make_error_code(ngx::gist::code::timeout);
     * // 使用示例：隐式转换（更常用）
     * std::error_code ec2 = ngx::gist::code::connection_refused;
     * // 使用示例：抛出系统异常
     * if (some_error_condition) {
     *     throw std::system_error(ngx::gist::code::io_error);
     * }
     * ```
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
     * @details 标记 `ngx::gist::code` 为错误码枚举，启用与 `std::error_code` 的隐式转换。该特化是 `C++` 标准库错误处理系统的关键集成点。
     * 
     * 作用机制：
     * @details - 类型标记：继承自 `std::true_type`，编译时标记 `ngx::gist::code` 为错误码枚举类型；
     * @details - 构造函数启用：使 `std::error_code` 构造函数能够接受 `ngx::gist::code` 参数；
     * @details - 隐式转换：启用从 `ngx::gist::code` 到 `std::error_code` 的隐式转换，提供零摩擦集成。
     * @note 该特化是 `SFINAE` 友好的，可用于模板元编程。
     * @warning 修改此特化可能破坏与标准库的兼容性。
     * 
     * ```
     * // 使用示例：隐式转换（依赖此特化）
     * std::error_code ec = ngx::gist::code::success;  // 隐式调用 make_error_code
     * // 使用示例：编译时检查
     * static_assert(std::is_error_code_enum<ngx::gist::code>::value);
     * // 使用示例：SFINAE 应用
     * template<typename T, typename = std::enable_if_t<std::is_error_code_enum<T>::value>>
     * void handle_error(T ec) {
     *     std::error_code std_ec = ec;  // 依赖隐式转换
     *     // 处理错误...
     * }
     * ```
     */
    template <>
    struct is_error_code_enum<ngx::gist::code> : std::true_type
    {
    };

    /**
     * @brief 特化 hash
     * @details 为 `ngx::gist::code` 提供 `std::hash` 特化，使其可用于无序容器（`std::unordered_set`、`std::unordered_map` 等）。该特化是标准库容器兼容性的关键部分。
     * 
     * 哈希算法：
     * @details - 简单委托：将枚举值转换为 `int`，委托给 `std::hash<int>`；
     * @details - 确定性：相同的枚举值总是产生相同的哈希值；
     * @details - 低碰撞：枚举值分布均匀，哈希碰撞概率低。
     * 
     * 标准符合性：
     * @details - 命名空间规则：根据 `C++` 标准，`hash` 特化应定义在 `std` 命名空间中；
     * @details - 特化权限：遵循 `[namespace.std]` 条款，允许用户向 `std` 添加模板特化；
     * @details - 接口约定：满足标准库对哈希函数的所有要求：确定性、不抛异常、一致性。
     * 
     * 设计特性：
     * @details - 零开销：委托给 `std::hash<int>`，无额外性能开销；
     * @details - 高质量哈希：依赖标准库提供的 `int` 哈希实现，保证哈希质量；
     * @details - 异常安全：函数标记为 `noexcept`，保证不抛出异常。
     * 
     * @note 哈希函数满足标准库对哈希的所有要求：确定性、不抛异常、一致性。
     * @warning 哈希值可能在不同程序运行间变化（如果 `std::hash<int>` 实现变化）。
     * @throws 无异常（函数标记为 `noexcept`）
     * 
     * ```
     * // 使用示例：无序集合
     * std::unordered_set<ngx::gist::code> error_set;
     * error_set.insert(ngx::gist::code::io_error);
     * error_set.insert(ngx::gist::code::timeout);
     * // 使用示例：无序映射
     * std::unordered_map<ngx::gist::code, std::string> error_messages;
     * error_messages[ngx::gist::code::connection_refused] = "Connection refused";
     * // 使用示例：哈希值计算
     * std::hash<ngx::gist::code> hasher;
     * size_t h = hasher(ngx::gist::code::success);
     * std::cout << "Hash of success: " << h << std::endl;
     * ```
     */
    template <>
    struct hash<ngx::gist::code>
    {
        /**
         * @brief 计算错误码的哈希值
         * @details 将 `ngx::gist::code` 枚举值转换为哈希值，用于无序容器。
         * @param c 错误码枚举值
         * @return `size_t` 哈希值
         * @note 哈希实现委托给 `std::hash<int>`，保证质量。
         * @warning 不要依赖哈希值的具体数值，仅用于容器内部组织。
         * @throws 无异常（函数标记为 `noexcept`）
         */
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
     * @details 标记 `ngx::gist::code` 为 `Boost` 错误码枚举，启用与 `boost::system::error_code` 的隐式转换。该特化是 `Boost.System` 错误处理系统的关键集成点。
     * 
     * 作用机制：
     * @details - 类型标记：继承自 `std::true_type`，编译时标记 `ngx::gist::code` 为错误码枚举类型；
     * @details - 构造函数启用：使 `boost::system::error_code` 构造函数能够接受 `ngx::gist::code` 参数；
     * @details - 隐式转换：启用从 `ngx::gist::code` 到 `boost::system::error_code` 的隐式转换，提供零摩擦集成。
     * 
     * 兼容性设计：
     * @details - 对称设计：与 `std::is_error_code_enum` 特化保持对称，提供一致的开发体验；
     * @details - 双向互操作：支持 `ngx::gist::code` 与 `boost::system::error_code` 之间的双向转换；
     * @details - 生态系统集成：确保项目错误码能够与使用 `Boost` 的第三方库无缝协作。
     * 
     * @note 该特化使 `ngx::gist::code` 能够与 `Boost` 生态系统的错误处理组件互操作。
     * @warning 修改此特化可能破坏与 `Boost.System` 的兼容性。
     * @throws 无异常（类型特化不涉及运行时代码）
     */
    template <>
    struct is_error_code_enum<ngx::gist::code> : std::true_type
    {
    };

    /**
     * @brief Boost 错误码分类
     * @details 实现 `boost::system::error_category` 接口，为 `ngx::gist::code` 提供 `Boost` 错误分类支持。该类是错误码系统与 `Boost.System` 错误处理体系之间的桥梁。
     * 
     * 核心职责：
     * @details - 分类标识：通过 `name()` 返回 "ngx::gist" 标识错误来源；
     * @details - 消息转换：通过 `message()` 将整数错误码转换为人类可读字符串；
     * @details - 相等比较：继承的 `==` 运算符提供分类对象相等性比较。
     * 
     * 设计特性：
     * @details - 单例模式：通过 `category()` 函数返回全局单例实例，确保全局一致性；
     * @details - 线程安全：`boost::system::error_category` 成员函数要求线程安全，符合多线程环境使用；
     * @details - 性能优化：`message()` 委托给 `ngx::gist::cached_message()` 避免重复分配
     * 
     * `Boost` 兼容性：
     * @details - 接口一致：实现与 `std::error_category` 相同的接口，保持开发一致性；
     * @details - 无状态设计：不添加额外状态成员，遵循 `Boost` 分类设计模式；
     * @details - 异常规范：成员函数遵循 `Boost` 异常规范，与 `Boost.System` 组件无缝协作。
     * 
     * @note 该类遵循 `boost::system::error_category` 约定，与标准库版本保持功能对等。
     * @warning 不要直接实例化此类，应通过 `category()` 函数获取单例。
     * @throws 无异常（所有成员函数标记为 `noexcept` 或仅可能抛出 `std::bad_alloc`）
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
     * @details 返回 `gist_category` 的全局单例引用。该函数是 `Boost.System` 错误分类系统的入口点，提供统一错误分类访问接口。
     * 
     * 单例特性：
     * @details - 延迟初始化：首次调用时构造单例，后续调用直接返回引用；
     * @details - 线程安全：`C++11` 保证静态局部变量初始化是线程安全的；
     * @details - 零开销：返回引用，无拷贝开销
     * 
     * 设计考虑：
     * @details - 全局一致性：确保整个项目使用相同的 `Boost` 错误分类实例；
     * @details - 生命周期管理：单例生命周期与程序相同，避免重复构造和销毁；
     * @details - 异常安全：首次调用可能抛出 `std::bad_alloc`，后续调用保证不抛异常。
     * 
     * 使用场景：
     * @details - 错误码构造：创建 `boost::system::error_code` 对象时需要关联分类单例；
     * @details - 分类比较：比较错误码是否属于 `gist` 分类；
     * @details - `Boost` 集成：与 `Boost` 生态系统的错误处理组件协作。
     * 
     * @return `gist_category` 单例引用，生命周期与程序相同
     * @note 该单例用于所有需要 `gist` 错误分类的 `Boost` 相关场景，确保全局一致性。
     * @warning 不要在静态析构阶段使用返回的引用，可能导致静态初始化顺序问题。
     * @throws 无异常（函数标记为 `noexcept`，但单例构造可能抛出 `std::bad_alloc`）
     */
    inline const error_category &category() noexcept
    {
        static gist_category instance;
        return instance;
    }

    /**
     * @brief 创建 Boost 错误码
     * @details 将 `ngx::gist::code` 枚举值转换为 `boost::system::error_code` 对象。该函数启用自定义错误码与 `Boost.System` 错误处理系统的集成，是 `Boost` 兼容性的核心组件。
     * 
     * 转换机制：
     * @details - 错误值映射：枚举值安全转换为 `int` 类型，保持值语义不变；
     * @details - 分类关联：与 `gist_category` 单例关联，标识错误来源；
     * @details - 隐式转换：配合 `boost::system::is_error_code_enum` 特化支持隐式转换，提供零摩擦集成。
     * 
     * 使用场景：
     * @details - 显式创建：直接调用 `make_error_code()` 创建 `boost::system::error_code` 对象；
     * @details - 隐式转换：依赖 `boost::system::is_error_code_enum` 特化自动转换枚举值为错误码；
     * @details - `Boost` 集成：与 `Boost` 生态系统的错误处理组件协作。
     * 
     * 设计优势：
     * @details - 类型安全：编译时检查确保只有 `ngx::gist::code` 枚举可以转换；
     * @details - 零开销：转换过程无动态分配，仅涉及值复制和分类关联；
     * @details - 双向兼容：生成的 `boost::system::error_code` 可反向获取原始枚举值（通过 `value()`）。
     * 
     * @param c 自定义错误码枚举值
     * @return `boost::system::error_code` 对应的 `Boost` 错误码对象
     * @note 由于 `boost::system::is_error_code_enum` 特化，通常不需要显式调用此函数。
     * @warning 转换后的错误码仅包含原始枚举值，不包含额外上下文信息。
     * @throws 无异常（函数标记为 `noexcept`）
     */
    inline error_code make_error_code(const ngx::gist::code c) noexcept
    {
        return {static_cast<int>(c), category()};
    }
}
