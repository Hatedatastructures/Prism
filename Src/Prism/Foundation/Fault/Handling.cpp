/**
 * @file Handling.cpp
 * @brief 操作系统与 Boost 错误码映射实现。
 */
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

namespace Prism::Fault
{
    auto ToNative(const Failure &Value) noexcept -> std::error_code
    {
        if (Value.Native)
        {
            return Value.Native;
        }
        if (Value.Succeeded())
        {
            return {};
        }
        return make_error_code(Value.Code);
    }

    auto ToCode(const boost::system::error_code &ErrorValue) noexcept -> Code
    {
        if (!ErrorValue)
        {
            return Code::Success;
        }

        if (&ErrorValue.category() == &boost::system::Category())
        {
            return Detail::MapFaultCategoryValue(ErrorValue.value());
        }
        if (&ErrorValue.category() == &Prism::ErrorCategory())
        {
            return Detail::MapProtocolCategoryValue(ErrorValue.value());
        }
        if (ErrorValue == boost::asio::error::eof)
        {
            return Code::Eof;
        }
        if (ErrorValue == boost::asio::error::operation_aborted)
        {
            return Code::Canceled;
        }
        if (ErrorValue == boost::asio::error::timed_out)
        {
            return Code::Timeout;
        }
        if (ErrorValue == boost::asio::error::connection_refused)
        {
            return Code::ConnectionRefused;
        }
        if (ErrorValue == boost::asio::error::connection_reset)
        {
            return Code::ConnectionReset;
        }
        if (ErrorValue == boost::asio::error::connection_aborted)
        {
            return Code::ConnectionAborted;
        }
        if (ErrorValue == boost::asio::error::host_unreachable)
        {
            return Code::HostNoreply;
        }
        if (ErrorValue == boost::asio::error::network_unreachable)
        {
            return Code::NetNoreply;
        }
        if (ErrorValue == boost::asio::error::no_buffer_space)
        {
            return Code::ResourceUnavailable;
        }

        return Code::IoError;
    }

    auto ToCode(const std::error_code &ErrorValue) noexcept -> Code
    {
        if (!ErrorValue)
        {
            return Code::Success;
        }

        if (&ErrorValue.category() == &Prism::Fault::Category())
        {
            return Detail::MapFaultCategoryValue(ErrorValue.value());
        }
        // 使用 Boost.System 官方类别转换得到的 std 类别对象身份，不检查消息或数值猜测。
        static const auto &ProtocolCategory =
            static_cast<const std::error_category &>(Prism::ErrorCategory());
        if (&ErrorValue.category() == &ProtocolCategory)
        {
            return Detail::MapProtocolCategoryValue(ErrorValue.value());
        }
        // 预构造错误码对象，避免每次比较都调用 std::make_error_code
        static const auto EcRefused = std::make_error_code(std::errc::connection_refused);
        static const auto EcReset = std::make_error_code(std::errc::connection_reset);
        static const auto EcAborted = std::make_error_code(std::errc::connection_aborted);
        static const auto EcTimeout = std::make_error_code(std::errc::timed_out);
        static const auto EcHost = std::make_error_code(std::errc::host_unreachable);
        static const auto EcNet = std::make_error_code(std::errc::network_unreachable);
        static const auto EcCancel = std::make_error_code(std::errc::operation_canceled);
        // 通过 Asio 官方工厂保留目标平台对应的 category/value，不复制平台数值。
        static const auto AsioEof = static_cast<std::error_code>(
            boost::asio::error::make_error_code(boost::asio::error::eof));
        static const auto AsioOperationAborted = static_cast<std::error_code>(
            boost::asio::error::make_error_code(boost::asio::error::operation_aborted));
        static const auto AsioTimedOut = static_cast<std::error_code>(
            boost::asio::error::make_error_code(boost::asio::error::timed_out));
        static const auto AsioConnectionRefused = static_cast<std::error_code>(
            boost::asio::error::make_error_code(boost::asio::error::connection_refused));
        static const auto AsioConnectionReset = static_cast<std::error_code>(
            boost::asio::error::make_error_code(boost::asio::error::connection_reset));
        static const auto AsioConnectionAborted = static_cast<std::error_code>(
            boost::asio::error::make_error_code(boost::asio::error::connection_aborted));
        static const auto AsioHostUnreachable = static_cast<std::error_code>(
            boost::asio::error::make_error_code(boost::asio::error::host_unreachable));
        static const auto AsioNetworkUnreachable = static_cast<std::error_code>(
            boost::asio::error::make_error_code(boost::asio::error::network_unreachable));
        static const auto AsioNoBufferSpace = static_cast<std::error_code>(
            boost::asio::error::make_error_code(boost::asio::error::no_buffer_space));

        if (ErrorValue == EcRefused) { return Code::ConnectionRefused; }
        if (ErrorValue == EcReset) { return Code::ConnectionReset; }
        if (ErrorValue == EcAborted) { return Code::ConnectionAborted; }
        if (ErrorValue == EcTimeout) { return Code::Timeout; }
        if (ErrorValue == EcHost) { return Code::HostNoreply; }
        if (ErrorValue == EcNet) { return Code::NetNoreply; }
        if (ErrorValue == EcCancel) { return Code::Canceled; }
        if (ErrorValue == AsioEof) { return Code::Eof; }
        if (ErrorValue == AsioOperationAborted) { return Code::Canceled; }
        if (ErrorValue == AsioTimedOut) { return Code::Timeout; }
        if (ErrorValue == AsioConnectionRefused) { return Code::ConnectionRefused; }
        if (ErrorValue == AsioConnectionReset) { return Code::ConnectionReset; }
        if (ErrorValue == AsioConnectionAborted) { return Code::ConnectionAborted; }
        if (ErrorValue == AsioHostUnreachable) { return Code::HostNoreply; }
        if (ErrorValue == AsioNetworkUnreachable) { return Code::NetNoreply; }
        if (ErrorValue == AsioNoBufferSpace) { return Code::ResourceUnavailable; }

        return Code::IoError;
    }
} // namespace Prism::Fault
