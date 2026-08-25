/**
 * @file handling.hpp
 * @brief 极简错误码检查适配层
 * @details 提供对 Fault::Code、std::error_code 和
 * boost::system::error_code 的统一错误检查接口。
 * 所有函数均为 constexpr 和 noexcept，无动态分配，
 * 专为热路径设计。
 * @note 该模块是性能关键代码，修改时需确保不引入
 * 运行时开销。
 * @warning 热路径中所有错误必须通过错误码传播，
 * 禁止使用异常。
 * @note 镜像自 include/prism/foundation/fault/，同步策略：锁定
 */
#pragma once

#include <common/Core/Error.hpp>
#include <common/Core/Fault/Code.hpp>
#include <common/Core/Fault/Compatible.hpp>

#include <boost/asio/error.hpp>

#include <string_view>
#include <system_error>
#include <type_traits>

namespace Preview::Fault
{

    /**
     * @brief 检查错误码是否表示成功
     * @tparam ErrorCode 错误码类型，支持 Fault::Code、
     * std::error_code、boost::system::error_code
     * @param ec 错误码对象的常量引用
     * @return true 表示操作成功，false 表示操作失败
     * @details 使用 if constexpr 实现编译时类型分发，
     * 消除运行时类型检查开销。对于不支持的类型触发
     * static_assert 编译错误。
     */
    template <typename ErrorCode>
    [[nodiscard]] constexpr auto Succeeded(const ErrorCode &ec) noexcept -> bool
    {
        if constexpr (std::is_same_v<ErrorCode, Code>)
        {
            return ec == Code::success;
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
     * @tparam ErrorCode 错误码类型，同 Succeeded()
     * @param ec 错误码对象的常量引用
     * @return true 表示操作失败，false 表示操作成功
     * @details Succeeded() 的互补函数，语义等价于
     * !Succeeded(ec)。
     */
    template <typename ErrorCode>
    [[nodiscard]] constexpr auto Failed(const ErrorCode &ec) noexcept -> bool
    {
        return !Succeeded(ec);
    }

    /**
     * @brief 将 boost 错误码转换为 Fault::Code
     * @param ec Boost 系统错误码
     * @return 对应的内部错误码
     * @details 映射常见 Boost.Asio 网络错误到对应
     * 的 fault 错误码，未映射的错误返回 io_error。
     * @warning 未映射的 Boost 错误将返回 io_error，
     * 可能丢失原始错误信息。
     */
    [[nodiscard]] inline auto ToCode(const boost::system::error_code &ec) noexcept -> Code
    {
        if (!ec)
        {
            return Code::success;
        }

        if (std::string_view(ec.category().name()) == "Preview::fault")
        {
            const auto value = ec.value();
            if (value >= 0 && value < static_cast<std::int32_t>(Code::_count))
            {
                return static_cast<Code>(value);
            }
            return Code::generic_error;
        }

        // 协议层错误（Preview::Error，类别名 Preview.Protocol）→ fault 映射
        if (std::string_view(ec.category().name()) == "preview.protocol")
        {
            switch (static_cast<Preview::Error>(ec.value()))
            {
            case Preview::Error::none: return Code::success;
            case Preview::Error::need_more: return Code::would_block;
            case Preview::Error::unexpected_eof: return Code::eof;
            case Preview::Error::bad_length:
            case Preview::Error::bad_magic:
            case Preview::Error::bad_message:
            case Preview::Error::version_mismatch: return Code::bad_message;
            case Preview::Error::bad_auth:
            case Preview::Error::auth_failed: return Code::auth_failed;
            case Preview::Error::not_supported:
            case Preview::Error::unsupported: return Code::not_supported;
            case Preview::Error::bad_address: return Code::unsupported_address;
            case Preview::Error::not_open:
            case Preview::Error::broken_pipe:
            case Preview::Error::io_error: return Code::io_error;
            case Preview::Error::canceled: return Code::canceled;
            case Preview::Error::timeout: return Code::timeout;
            case Preview::Error::protocol_error: return Code::protocol_error;
            case Preview::Error::kdf_error: return Code::generic_error;
            default: return Code::generic_error;
            }
        }

        if (ec == boost::asio::error::eof)
        {
            return Code::eof;
        }
        if (ec == boost::asio::error::operation_aborted)
        {
            return Code::canceled;
        }
        if (ec == boost::asio::error::timed_out)
        {
            return Code::timeout;
        }
        if (ec == boost::asio::error::connection_refused)
        {
            return Code::connection_refused;
        }
        if (ec == boost::asio::error::connection_reset)
        {
            return Code::connection_reset;
        }
        if (ec == boost::asio::error::connection_aborted)
        {
            return Code::connection_aborted;
        }
        if (ec == boost::asio::error::host_unreachable)
        {
            return Code::host_noreply;
        }
        if (ec == boost::asio::error::network_unreachable)
        {
            return Code::net_noreply;
        }
        if (ec == boost::asio::error::no_buffer_space)
        {
            return Code::resource_unavailable;
        }

        return Code::io_error;
    }

    /**
     * @brief 将 std 错误码转换为 Fault::Code
     * @param ec C++ 标准库错误码
     * @return 对应的内部错误码
     * @details 映射常见 std::errc 错误到对应的
     * fault 错误码，未映射的错误返回 io_error。
     * @warning 未映射的标准错误将返回 io_error。
     */
    [[nodiscard]] inline auto ToCode(const std::error_code &ec) noexcept -> Code
    {
        if (!ec)
        {
            return Code::success;
        }

        if (&ec.category() == &Preview::Fault::category())
        {
            const auto value = ec.value();
            if (value >= 0 && value < static_cast<std::int32_t>(Code::_count))
            {
                return static_cast<Code>(value);
            }
            return Code::generic_error;
        }

        // 预构造错误码对象，避免每次比较都调用 std::make_error_code
        static const auto ec_refused = std::make_error_code(std::errc::connection_refused);
        static const auto ec_reset = std::make_error_code(std::errc::connection_reset);
        static const auto ec_aborted = std::make_error_code(std::errc::connection_aborted);
        static const auto ec_timeout = std::make_error_code(std::errc::timed_out);
        static const auto ec_host = std::make_error_code(std::errc::host_unreachable);
        static const auto ec_net = std::make_error_code(std::errc::network_unreachable);
        static const auto ec_cancel = std::make_error_code(std::errc::operation_canceled);

        if (ec == ec_refused)
        {
            return Code::connection_refused;
        }
        if (ec == ec_reset)
        {
            return Code::connection_reset;
        }
        if (ec == ec_aborted)
        {
            return Code::connection_aborted;
        }
        if (ec == ec_timeout)
        {
            return Code::timeout;
        }
        if (ec == ec_host)
        {
            return Code::host_noreply;
        }
        if (ec == ec_net)
        {
            return Code::net_noreply;
        }
        if (ec == ec_cancel)
        {
            return Code::canceled;
        }

        return Code::io_error;
    }

} // namespace Preview::Fault
