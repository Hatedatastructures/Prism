/**
 * @file handling.hpp
 * @brief 极简错误码检查适配层
 * @details 提供对 fault::code、std::error_code 和
 * boost::system::error_code 的统一错误检查接口。
 * 所有函数均为 constexpr 和 noexcept，无动态分配，
 * 专为热路径设计。
 * @note 该模块是性能关键代码，修改时需确保不引入
 * 运行时开销。
 * @warning 热路径中所有错误必须通过错误码传播，
 * 禁止使用异常。
 */
#pragma once

#include <system_error>
#include <string_view>
#include <type_traits>

#include <boost/asio/error.hpp>
#include <prism/fault/code.hpp>
#include <prism/fault/compatible.hpp>

namespace psm::fault
{
    /**
     * @brief 检查错误码是否表示成功
     * @tparam ErrorCode 错误码类型，支持 fault::code、
     * std::error_code、boost::system::error_code
     * @param ec 错误码对象的常量引用
     * @return true 表示操作成功，false 表示操作失败
     * @details 使用 if constexpr 实现编译时类型分发，
     * 消除运行时类型检查开销。对于不支持的类型触发
     * static_assert 编译错误。
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
     * @tparam ErrorCode 错误码类型，同 succeeded()
     * @param ec 错误码对象的常量引用
     * @return true 表示操作失败，false 表示操作成功
     * @details succeeded() 的互补函数，语义等价于
     * !succeeded(ec)。
     */
    template <typename ErrorCode>
    [[nodiscard]] constexpr bool failed(const ErrorCode &ec) noexcept
    {
        return !succeeded(ec);
    }

    /**
     * @brief 将 boost 错误码转换为 fault::code
     * @param ec Boost 系统错误码
     * @return 对应的内部错误码
     * @details 映射常见 Boost.Asio 网络错误到对应
     * 的 fault 错误码，未映射的错误返回 io_error。
     * @warning 未映射的 Boost 错误将返回 io_error，
     * 可能丢失原始错误信息。
     */
    [[nodiscard]] inline code to_code(const boost::system::error_code &ec) noexcept
    {
        if (!ec)
        {
            return code::success;
        }

        if (std::string_view(ec.category().name()) == "psm::fault")
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
     * @brief 将 std 错误码转换为 fault::code
     * @param ec C++ 标准库错误码
     * @return 对应的内部错误码
     * @details 映射常见 std::errc 错误到对应的
     * fault 错误码，未映射的错误返回 io_error。
     * @warning 未映射的标准错误将返回 io_error。
     */
    [[nodiscard]] inline code to_code(const std::error_code &ec) noexcept
    {
        if (!ec)
        {
            return code::success;
        }

        if (&ec.category() == &psm::fault::category())
        {
            const auto value = ec.value();
            if (value >= 0 && value < static_cast<int>(code::_count))
            {
                return static_cast<code>(value);
            }
            return code::generic_error;
        }

        // 预构造错误码对象，避免每次比较都调用 std::make_error_code
        static const auto ec_conn_refused = std::make_error_code(std::errc::connection_refused);
        static const auto ec_conn_reset = std::make_error_code(std::errc::connection_reset);
        static const auto ec_conn_aborted = std::make_error_code(std::errc::connection_aborted);
        static const auto ec_timed_out = std::make_error_code(std::errc::timed_out);
        static const auto ec_host_unreach = std::make_error_code(std::errc::host_unreachable);
        static const auto ec_net_unreach = std::make_error_code(std::errc::network_unreachable);
        static const auto ec_canceled = std::make_error_code(std::errc::operation_canceled);

        if (ec == ec_conn_refused)
        {
            return code::connection_refused;
        }
        if (ec == ec_conn_reset)
        {
            return code::connection_reset;
        }
        if (ec == ec_conn_aborted)
        {
            return code::connection_aborted;
        }
        if (ec == ec_timed_out)
        {
            return code::timeout;
        }
        if (ec == ec_host_unreach)
        {
            return code::host_unreachable;
        }
        if (ec == ec_net_unreach)
        {
            return code::network_unreachable;
        }
        if (ec == ec_canceled)
        {
            return code::canceled;
        }

        return code::io_error;
    }

} // namespace psm::fault
