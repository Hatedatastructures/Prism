/**
 * @file handling.hpp
 * @brief 极简错误码检查适配层
 * @details 提供对 ngx::gist::code、std::error_code 和 boost::system::error_code
 * 的统一错误检查接口。该模块是错误处理系统的前端，设计为热路径零开销，适用于
 * 网络 I/O、协议解析、数据转发等性能敏感场景。
 * 核心特性包括统一接口，三种错误码类型的通用检查；零开销，所有函数均为
 * constexpr 和 noexcept，无动态分配，无异常抛出；编译时优化，使用 if constexpr
 * 实现类型特化，消除运行时分支；类型安全，静态断言确保仅支持已知错误码类型。
 * 架构定位是前端适配层，作为错误处理系统的前端，为上层业务代码提供统一的
 * 错误检查接口；性能关键路径，专门优化用于热路径，确保网络 I/O 和协议解析
 * 等场景的零开销；多生态系统桥接，桥接项目自定义错误码、标准库错误码和 Boost
 * 错误码，实现无缝互操作。
 * @note 该模块是性能关键代码，修改时需确保不引入运行时开销。
 * @warning 不要在热路径中使用异常，所有错误必须通过错误码传播。
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
     * @brief 检查错误码是否表示成功
     * @tparam ErrorCode 错误码类型，支持 ngx::gist::code、std::error_code、
     * boost::system::error_code
     * @param ec 错误码对象的常量引用
     * @return true 表示操作成功，false 表示操作失败
     * @details 统一检查多种错误码类型是否表示操作成功。该函数是热路径错误处理
     * 的核心工具，设计为零开销，符合性能军规。类型特化包括 ngx::gist::code，
     * 直接与 code::success 比较，零额外开销；std::error_code，使用 !ec 运算符，
     * 符合标准库语义；boost::system::error_code，使用 !ec 运算符，保持与 Boost
     * 生态系统一致。
     * 编译时优化包括类型分发，使用 if constexpr 实现编译时类型分发，消除运行时
     * 类型检查开销；静态断言，对于不支持的类型，触发 static_assert 编译错误，
     * 提供清晰的错误信息；编译时求值，对于 constexpr 参数，函数可在编译时完成
     * 求值，进一步减少运行时开销。
     * 使用场景包括热路径错误检查，网络 I/O、协议解析、数据转发等性能敏感场景；
     * 多错误码类型统一处理，需要同时处理项目错误码、标准库错误码和 Boost 错误码
     * 的代码；编译时错误验证，在静态断言中验证错误码的成功状态。
     * @note 该函数标记为 constexpr 和 noexcept，确保热路径零开销。
     * @warning 不支持其他错误码类型，尝试使用会触发编译错误。
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
     * @brief 检查错误码是否表示失败
     * @tparam ErrorCode 错误码类型，支持 ngx::gist::code、std::error_code、
     * boost::system::error_code
     * @param ec 错误码对象的常量引用
     * @return true 表示操作失败，false 表示操作成功
     * @details 统一检查多种错误码类型是否表示操作失败。该函数是 succeeded()
     * 的互补函数，通过简单取反实现，提供清晰的失败语义。实现原理包括委托调用，
     * 直接调用 !succeeded(ec)，确保语义一致性并减少代码重复；类型特化，所有
     * 类型特化逻辑委托给 succeeded() 函数，保持逻辑集中；内联优化，函数标记为
     * constexpr 和 noexcept，编译器可内联展开，消除函数调用开销。
     * 使用场景包括错误处理流程，检查异步操作是否失败，触发错误处理逻辑；
     * 条件分支，替代 !succeeded(ec)，提供更清晰的失败语义；编译时验证，验证
     * 错误码的互补关系，确保逻辑一致性。
     * @note 该函数标记为 constexpr 和 noexcept，确保热路径零开销。
     * @warning 语义上 failed(ec) == !succeeded(ec) 应始终成立。
     */
    template <typename ErrorCode>
    [[nodiscard]] constexpr bool failed(const ErrorCode &ec) noexcept
    {
        return !succeeded(ec);
    }

    /**
     * @brief 将 boost::system::error_code 转换为 ngx::gist::code
     * @param ec Boost 系统错误码的常量引用
     * @return 对应的内部错误码
     * @details 将 Boost 生态系统中的错误码转换为项目内部错误码表示。该函数是
     * 错误码系统互操作性的关键部分。转换逻辑包括成功检查，如果 Boost 错误码
     * 表示成功（!ec），返回 code::success；gist 错误码，如果错误码属于 ngx::gist
     * 分类，直接转换值并验证范围；常见 Boost.Asio 错误，映射常见网络错误到对应
     * 的 gist 错误码；默认映射，其他错误映射为 code::io_error。
     * 支持的 Boost.Asio 错误映射包括 boost::asio::error::eof 映射到 code::eof；
     * boost::asio::error::operation_aborted 映射到 code::canceled；
     * boost::asio::error::timed_out 映射到 code::timeout；
     * boost::asio::error::connection_refused 映射到 code::connection_refused；
     * boost::asio::error::connection_reset 映射到 code::connection_reset；
     * boost::asio::error::connection_aborted 映射到 code::connection_aborted；
     * boost::asio::error::host_unreachable 映射到 code::host_unreachable；
     * boost::asio::error::network_unreachable 映射到 code::network_unreachable；
     * boost::asio::error::no_buffer_space 映射到 code::resource_unavailable。
     * @note 该函数是 noexcept 的，但 Boost 错误码的比较可能抛出（极罕见）。
     * @warning 未映射的 Boost 错误将返回 code::io_error，可能丢失原始错误信息。
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
     * @brief 将 std::error_code 转换为 ngx::gist::code
     * @param ec C++ 标准库错误码的常量引用
     * @return 对应的内部错误码
     * @details 将 C++ 标准库错误码转换为项目内部错误码表示。该函数是错误码系统
     * 与标准库互操作性的关键部分。转换逻辑包括成功检查，如果标准错误码表示成功
     * （!ec），返回 code::success；gist 错误码，如果错误码属于 ngx::gist 分类
     * （通过指针比较），直接转换值并验证范围；常见标准错误，映射 std::errc 错误
     * 到对应的 gist 错误码；默认映射，其他错误映射为 code::io_error。
     * 支持的 std::errc 错误映射包括 std::errc::connection_refused 映射到
     * code::connection_refused；std::errc::connection_reset 映射到 code::connection_reset；
     * std::errc::connection_aborted 映射到 code::connection_aborted；
     * std::errc::timed_out 映射到 code::timeout；std::errc::host_unreachable 映射到
     * code::host_unreachable；std::errc::network_unreachable 映射到
     * code::network_unreachable；std::errc::operation_canceled 映射到 code::canceled。
     * @note 该函数是 noexcept 的，错误码比较操作不会抛出异常。
     * @warning 未映射的标准错误将返回 code::io_error，可能丢失原始错误信息。
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

}
