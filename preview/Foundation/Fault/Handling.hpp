/**
 * @file Handling.hpp
 * @brief 极简错误码检查适配层
 * @details 提供对 Fault::Code、std::error_code 和
 * boost::system::error_code 的统一错误检查接口。
 * 所有函数均为 constexpr 和 noexcept，无动态分配，
 * 专为热路径设计。
 * @note 该模块是性能关键代码，修改时需确保不引入
 * 运行时开销。
 * @warning 热路径中所有错误必须通过错误码传播，
 * 禁止使用异常。
 * @note 与生产 fault/handling.hpp 保持公共 fault/系统错误语义；Preview
 *       协议错误的分类转换仅在本边界实现，避免生产 Foundation 依赖 Preview。
 */
#pragma once

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Fault/Compatible.hpp>

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
            return ec == Code::Success;
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
            return Code::Success;
        }

        if (std::string_view(ec.category().name()) == "Preview::fault")
        {
            const auto value = ec.value();
            if (value >= 0 && value < static_cast<std::int32_t>(Code::_count))
            {
                return static_cast<Code>(value);
            }
            return Code::GenericError;
        }

        // 协议层错误（prism.protocol，固定枚举序号）→ fault 映射。
        // 仅依赖中立分类契约，避免 Fault 反向 include 协议实现。
        if (std::string_view(ec.category().name()) == "prism.protocol")
        {
            switch (ec.value())
            {
            case 0: return Code::Success;
            case 1: return Code::WouldBlock;
            case 2: return Code::Eof;
            case 3:
            case 4:
            case 9:
            case 7: return Code::BadMessage;
            case 5:
            case 6: return Code::AuthFailed;
            case 8:
            case 17: return Code::NotSupported;
            case 10: return Code::UnsupportedAddress;
            case 11:
            case 14:
            case 18: return Code::IoError;
            case 12: return Code::Canceled;
            case 13: return Code::Timeout;
            case 15: return Code::ProtocolError;
            case 16: return Code::GenericError;
            default: return Code::GenericError;
            }
        }

        if (ec == boost::asio::error::eof)
        {
            return Code::Eof;
        }
        if (ec == boost::asio::error::operation_aborted)
        {
            return Code::Canceled;
        }
        if (ec == boost::asio::error::timed_out)
        {
            return Code::Timeout;
        }
        if (ec == boost::asio::error::connection_refused)
        {
            return Code::ConnectionRefused;
        }
        if (ec == boost::asio::error::connection_reset)
        {
            return Code::ConnectionReset;
        }
        if (ec == boost::asio::error::connection_aborted)
        {
            return Code::ConnectionAborted;
        }
        if (ec == boost::asio::error::host_unreachable)
        {
            return Code::HostNoreply;
        }
        if (ec == boost::asio::error::network_unreachable)
        {
            return Code::NetNoreply;
        }
        if (ec == boost::asio::error::no_buffer_space)
        {
            return Code::ResourceUnavailable;
        }

        return Code::IoError;
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
            return Code::Success;
        }

        if (&ec.category() == &Preview::Fault::Category())
        {
            const auto value = ec.value();
            if (value >= 0 && value < static_cast<std::int32_t>(Code::_count))
            {
                return static_cast<Code>(value);
            }
            return Code::GenericError;
        }

        // 预构造错误码对象，避免每次比较都调用 std::make_error_code
        static const auto EcRefused = std::make_error_code(std::errc::connection_refused);
        static const auto EcReset = std::make_error_code(std::errc::connection_reset);
        static const auto EcAborted = std::make_error_code(std::errc::connection_aborted);
        static const auto EcTimeout = std::make_error_code(std::errc::timed_out);
        static const auto EcHost = std::make_error_code(std::errc::host_unreachable);
        static const auto EcNet = std::make_error_code(std::errc::network_unreachable);
        static const auto EcCancel = std::make_error_code(std::errc::operation_canceled);

        if (ec == EcRefused)
        {
            return Code::ConnectionRefused;
        }
        if (ec == EcReset)
        {
            return Code::ConnectionReset;
        }
        if (ec == EcAborted)
        {
            return Code::ConnectionAborted;
        }
        if (ec == EcTimeout)
        {
            return Code::Timeout;
        }
        if (ec == EcHost)
        {
            return Code::HostNoreply;
        }
        if (ec == EcNet)
        {
            return Code::NetNoreply;
        }
        if (ec == EcCancel)
        {
            return Code::Canceled;
        }

        return Code::IoError;
    }

} // namespace Preview::Fault
