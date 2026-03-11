/**
 * @file handling.hpp
 * @brief 极简错误码检查适配层（热路径安全）
 * @details 提供对 `ngx::gist::code`、`std::error_code` 和 `boost::system::error_code` 的统一错误检查接口。该模块是错误处理系统的前端，设计为热路径（`hot path`）零开销，适用于网络 `I/O`、协议解析、数据转发等性能敏感场景。
 *
 * 核心特性：
 * @details - 统一接口：三种错误码类型（`ngx::gist::code`、`std::error_code`、`boost::system::error_code`）的通用检查；
 * @details - 零开销：所有函数均为 `constexpr` 和 `noexcept`，无动态分配，无异常抛出；
 * @details - 编译时优化：使用 `if constexpr` 实现类型特化，消除运行时分支；
 * @details - 类型安全：静态断言确保仅支持已知错误码类型。
 *
 * 架构定位：
 * @details - 前端适配层：作为错误处理系统的前端，为上层业务代码提供统一的错误检查接口；
 * @details - 性能关键路径：专门优化用于热路径，确保网络 `I/O` 和协议解析等场景的零开销；
 * @details - 多生态系统桥接：桥接项目自定义错误码、标准库错误码和 `Boost` 错误码，实现无缝互操作。
 *
 * @note 该模块是性能关键代码，修改时需确保不引入运行时开销。
 * @warning 不要在热路径中使用异常，所有错误必须通过错误码传播。
 * @see code.hpp
 * @see compatible.hpp
 *
 * ```
 * // 使用示例：统一错误检查
 * ngx::gist::code my_code = ngx::gist::code::success;
 * std::error_code std_ec = std::make_error_code(std::errc::connection_refused);
 * boost::system::error_code boost_ec = boost::asio::error::eof;
 *
 * // 统一检查（编译时特化）
 * bool ok1 = ngx::gist::succeeded(my_code);     // true
 * bool ok2 = ngx::gist::succeeded(std_ec);      // false
 * bool ok3 = ngx::gist::succeeded(boost_ec);    // false
 *
 * bool failed1 = ngx::gist::failed(my_code);    // false
 * bool failed2 = ngx::gist::failed(std_ec);     // true
 * bool failed3 = ngx::gist::failed(boost_ec);   // true
 * ```
 */
#pragma once

#include <charconv>
#include <system_error>
#include <string_view>
#include <type_traits>

#include <boost/asio/error.hpp>
#include <forward-engine/gist/code.hpp>
#include <forward-engine/gist/compatible.hpp>

namespace ngx::gist
{
    /**
     * @brief 检查错误码是否表示成功（热路径安全）
     * @details 统一检查多种错误码类型是否表示操作成功。该函数是热路径错误处理的核心工具，设计为零开销，符合性能军规。
     *
     * 类型特化：
     * @details - `ngx::gist::code`：直接与 `code::success` 比较，零额外开销；
     * @details - `std::error_code`：使用 `!ec` 运算符（标准库约定），符合标准库语义；
     * @details - `boost::system::error_code`：使用 `!ec` 运算符（`Boost` 约定），保持与 `Boost` 生态系统一致。
     *
     * 编译时优化：
     * @details - 类型分发：使用 `if constexpr` 实现编译时类型分发，消除运行时类型检查开销；
     * @details - 静态断言：对于不支持的类型，触发 `static_assert` 编译错误，提供清晰的错误信息；
     * @details - 编译时求值：对于 `constexpr` 参数，函数可在编译时完成求值，进一步减少运行时开销。
     *
     *
     * 使用场景：
     * @details - 热路径错误检查：网络 `I/O`、协议解析、数据转发等性能敏感场景；
     * @details - 多错误码类型统一处理：需要同时处理项目错误码、标准库错误码和 `Boost` 错误码的代码；
     * @details - 编译时错误验证：在静态断言中验证错误码的成功状态。
     *
     * @tparam ErrorCode 错误码类型（支持 `ngx::gist::code`、`std::error_code`、`boost::system::error_code`）
     * @param ec 错误码对象（常量引用）
     * @return `true` 表示操作成功，`false` 表示操作失败
     * @note 该函数标记为 `constexpr` 和 `noexcept`，确保热路径零开销。
     * @warning 不支持其他错误码类型，尝试使用会触发编译错误。
     * @throws 无异常（函数标记为 `noexcept`）
     *
     * ```
     * // 使用示例：编译时类型特化
     * constexpr ngx::gist::code ec1 = ngx::gist::code::success;
     * constexpr bool success1 = ngx::gist::succeeded(ec1);  // true，编译时求值
     *
     * std::error_code ec2 = std::make_error_code(std::errc::connection_refused);
     * bool success2 = ngx::gist::succeeded(ec2);  // false，运行时检查
     *
     * boost::system::error_code ec3 = boost::asio::error::eof;
     * bool success3 = ngx::gist::succeeded(ec3);  // false，运行时检查
     *
     * // 编译时错误（不支持的类型）
     * // int invalid_ec = 42;
     * // bool invalid = ngx::gist::succeeded(invalid_ec);  // 编译错误：static_assert
     * ```
     */
    template <typename ErrorCode>
    [[nodiscard]] constexpr bool succeeded(const ErrorCode &ec) noexcept
    {
        if constexpr (std::is_same_v<ErrorCode, code>)
        {
            return ec == code::success;
        }
        else if constexpr (std::is_same_v<ErrorCode, std::error_code>)
        {
            return !ec;
        }
        else if constexpr (std::is_same_v<ErrorCode, boost::system::error_code>)
        {
            return !ec;
        }
        else
        {
            static_assert(sizeof(ErrorCode) == 0, "不支持的错误码类型");
        }
        return false;
    }

    /**
     * @brief 检查错误码是否表示失败（热路径安全）
     * @details 统一检查多种错误码类型是否表示操作失败。该函数是 `succeeded()` 的互补函数，通过简单取反实现，提供清晰的失败语义。
     *
     * 实现原理：
     * @details - 委托调用：直接调用 `!succeeded(ec)`，确保语义一致性并减少代码重复；
     * @details - 类型特化：所有类型特化逻辑委托给 `succeeded()` 函数，保持逻辑集中；
     * @details - 内联优化：函数标记为 `constexpr` 和 `noexcept`，编译器可内联展开，消除函数调用开销。
     *
     *
     * 使用场景：
     * @details - 错误处理流程：检查异步操作是否失败，触发错误处理逻辑；
     * @details - 条件分支：替代 `!succeeded(ec)`，提供更清晰的失败语义；
     * @details - 编译时验证：验证错误码的互补关系，确保逻辑一致性。
     *
     * @tparam ErrorCode 错误码类型（支持 `ngx::gist::code`、`std::error_code`、`boost::system::error_code`）
     * @param ec 错误码对象（常量引用）
     * @return `true` 表示操作失败，`false` 表示操作成功
     * @note 该函数标记为 `constexpr` 和 `noexcept`，确保热路径零开销。
     * @warning 语义上 `failed(ec) == !succeeded(ec)` 应始终成立。
     * @throws 无异常（函数标记为 `noexcept`）
     *
     * ```
     * // 使用示例：检查操作失败
     * ngx::gist::code ec1 = ngx::gist::code::io_error;
     * if (ngx::gist::failed(ec1))
     * {
     *     trace::error("Operation failed");  // 会执行
     * }
     *
     * std::error_code ec2 = std::make_error_code(std::errc::timed_out);
     * if (ngx::gist::failed(ec2))
     * {
     *     co_return ec2;  // 协程提前返回
     * }
     *
     * boost::system::error_code ec3{};
     * if (!ngx::gist::failed(ec3))
     * {
     *     // 成功路径，继续处理
     *     co_await next_step();
     * }
     *
     * // 语义验证
     * static_assert(ngx::gist::failed(ec) == !ngx::gist::succeeded(ec));
     * ```
     */
    template <typename ErrorCode>
    [[nodiscard]] constexpr bool failed(const ErrorCode &ec) noexcept
    {
        return !succeeded(ec);
    }

    /**
     * @brief 将 `boost::system::error_code` 转换为 `ngx::gist::code`
     * @details 将 `Boost` 生态系统中的错误码转换为项目内部错误码表示。该函数是错误码系统互操作性的关键部分。
     *
     * 转换逻辑：
     * @details 1. 成功检查：如果 `Boost` 错误码表示成功（`!ec`），返回 `code::success`；
     * @details 2. `gist` 错误码：如果错误码属于 `ngx::gist` 分类，直接转换值并验证范围；
     * @details 3. 常见 `Boost.Asio` 错误：映射常见网络错误到对应的 `gist` 错误码；
     * @details 4. 默认映射：其他错误映射为 `code::io_error`。
     *
     * 支持的 `Boost.Asio` 错误映射：
     * @details - `boost::asio::error::eof` → `code::eof`
     * @details - `boost::asio::error::operation_aborted` → `code::canceled`
     * @details - `boost::asio::error::timed_out` → `code::timeout`
     * @details - `boost::asio::error::connection_refused` → `code::connection_refused`
     * @details - `boost::asio::error::connection_reset` → `code::connection_reset`
     * @details - `boost::asio::error::connection_aborted` → `code::connection_aborted`
     * @details - `boost::asio::error::host_unreachable` → `code::host_unreachable`
     * @details - `boost::asio::error::network_unreachable` → `code::network_unreachable`
     * @details - `boost::asio::error::no_buffer_space` → `code::resource_unavailable`
     *
     * @param ec `Boost` 系统错误码（常量引用）
     * @return `ngx::gist::code` 对应的内部错误码
     * @note 该函数是 `noexcept` 的，但 `Boost` 错误码的比较可能抛出（极罕见）。
     * @warning 未映射的 `Boost` 错误将返回 `code::io_error`，可能丢失原始错误信息。
     * @throws 无异常（函数标记为 `noexcept`，但依赖的 `Boost` 操作理论上可能抛出）
     *
     * ```
     * // 使用示例：Boost 错误码转换
     * boost::system::error_code boost_ec = boost::asio::error::connection_refused;
     * ngx::gist::code gist_ec = ngx::gist::to_code(boost_ec);
     * // gist_ec == ngx::gist::code::connection_refused
     *
     * // 使用示例：处理 Boost 异步操作
     * boost::asio::async_read(socket, buffer, [](const boost::system::error_code& ec, size_t)
     * {
     *     if (ngx::gist::failed(ngx::gist::to_code(ec)))
     *     {
     *         trace::error("Async read failed: {}", ec.message());
     *     }
     * });
     *
     * // 使用示例：gist 错误码回环
     * ngx::gist::code original = ngx::gist::code::timeout;
     * std::error_code std_ec = original;  // 隐式转换
     * boost::system::error_code boost_ec = std_ec;  // Boost 兼容
     * ngx::gist::code converted = ngx::gist::to_code(boost_ec);
     * // converted == original (应该成立)
     * ```
     */
    [[nodiscard]] inline code to_code(const boost::system::error_code &ec) noexcept
    {
        if (!ec)
        {
            return code::success;
        }

        if (std::string_view(ec.category().name()) == "ngx::gist")
        {
            const auto value = ec.value();
            if (value >= 0 && value < static_cast<int>(code::_count))
            {
                return static_cast<code>(value);
            }
            return code::generic_error;
        }

        if (ec == boost::asio::error::eof)
        {
            return code::eof;
        }
        if (ec == boost::asio::error::operation_aborted)
        {
            return code::canceled;
        }
        if (ec == boost::asio::error::timed_out)
        {
            return code::timeout;
        }
        if (ec == boost::asio::error::connection_refused)
        {
            return code::connection_refused;
        }
        if (ec == boost::asio::error::connection_reset)
        {
            return code::connection_reset;
        }
        if (ec == boost::asio::error::connection_aborted)
        {
            return code::connection_aborted;
        }
        if (ec == boost::asio::error::host_unreachable)
        {
            return code::host_unreachable;
        }
        if (ec == boost::asio::error::network_unreachable)
        {
            return code::network_unreachable;
        }
        if (ec == boost::asio::error::no_buffer_space)
        {
            return code::resource_unavailable;
        }

        return code::io_error;
    }

    /**
     * @brief 将 `std::error_code` 转换为 `ngx::gist::code`
     * @details 将 `C++` 标准库错误码转换为项目内部错误码表示。该函数是错误码系统与标准库互操作性的关键部分。
     *
     * 转换逻辑：
     * @details - 1. 成功检查：如果标准错误码表示成功（`!ec`），返回 `code::success`；
     * @details - 2. gist 错误码：如果错误码属于 `ngx::gist` 分类（通过指针比较），直接转换值并验证范围；
     * @details - 3. 常见标准错误：映射 `std::errc` 错误到对应的 `gist` 错误码；
     * @details - 4. 默认映射：其他错误映射为 `code::io_error`。
     *
     * 支持的 std::errc 错误映射：
     * @details - `std::errc::connection_refused` → `code::connection_refused`
     * @details - `std::errc::connection_reset` → `code::connection_reset`
     * @details - `std::errc::connection_aborted` → `code::connection_aborted`
     * @details - `std::errc::timed_out` → `code::timeout`
     * @details - `std::errc::host_unreachable` → `code::host_unreachable`
     * @details - `std::errc::network_unreachable` → `code::network_unreachable`
     * @details - `std::errc::operation_canceled` → `code::canceled`
     *
     * @param ec `C++` 标准库错误码（常量引用）
     * @return `ngx::gist::code` 对应的内部错误码
     * @note 该函数是 `noexcept` 的，错误码比较操作不会抛出异常。
     * @warning 未映射的标准错误将返回 `code::io_error`，可能丢失原始错误信息。
     * @throws 无异常（函数标记为 `noexcept`）
     *
     * ```
     * // 使用示例：标准库错误码转换
     * std::error_code std_ec = std::make_error_code(std::errc::connection_refused);
     * ngx::gist::code gist_ec = ngx::gist::to_code(std_ec);
     * // gist_ec == ngx::gist::code::connection_refused
     *
     * // 使用示例：处理标准库异常
     * try
     * {
     *     some_std_function();
     * } catch (const std::system_error& e)
     * {
     *     ngx::gist::code ec = ngx::gist::to_code(e.code());
     *     trace::error("System error: {}, gist code: {}", e.what(), ngx::gist::describe(ec));
     * }
     *
     * // 使用示例：gist 错误码回环
     * ngx::gist::code original = ngx::gist::code::timeout;
     * std::error_code std_ec = original;  // 隐式转换（依赖 compatible.hpp）
     * ngx::gist::code converted = ngx::gist::to_code(std_ec);
     * // converted == original (应该成立)
     *
     * // 使用示例：检查是否为 gist 错误
     * if (&std_ec.category() == &ngx::gist::category())
     * {
     *     // 这是 gist 错误码，可以直接转换
     *     ngx::gist::code ec = static_cast<ngx::gist::code>(std_ec.value());
     * }
     * ```
     */
    [[nodiscard]] inline code to_code(const std::error_code &ec) noexcept
    {
        if (!ec)
        {
            return code::success;
        }

        if (&ec.category() == &ngx::gist::category())
        {
            const auto value = ec.value();
            if (value >= 0 && value < static_cast<int>(code::_count))
            {
                return static_cast<code>(value);
            }
            return code::generic_error;
        }

        if (ec == std::make_error_code(std::errc::connection_refused))
        {
            return code::connection_refused;
        }
        if (ec == std::make_error_code(std::errc::connection_reset))
        {
            return code::connection_reset;
        }
        if (ec == std::make_error_code(std::errc::connection_aborted))
        {
            return code::connection_aborted;
        }
        if (ec == std::make_error_code(std::errc::timed_out))
        {
            return code::timeout;
        }
        if (ec == std::make_error_code(std::errc::host_unreachable))
        {
            return code::host_unreachable;
        }
        if (ec == std::make_error_code(std::errc::network_unreachable))
        {
            return code::network_unreachable;
        }
        if (ec == std::make_error_code(std::errc::operation_canceled))
        {
            return code::canceled;
        }

        return code::io_error;
    }

} // namespace ngx::gist
