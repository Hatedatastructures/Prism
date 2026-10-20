/**
 * @file Handling.hpp
 * @brief 极简错误码检查适配层
 * @details 提供对 Fault::Code、std::error_code 和
 * boost::system::error_code 的统一错误检查接口。
 * 分类值映射保持 constexpr；标准库与 Boost 错误码转换由 Foundation
 * 实现库提供，并保持无异常热路径。
 * @note 该模块是性能关键代码，修改时需确保不引入
 * 运行时开销。
 * @warning 热路径中所有错误必须通过错误码传播，
 * 禁止使用异常。
 * @note 与生产 fault/handling.hpp 保持公共 fault/系统错误语义；Prism
 *       协议错误的分类转换仅在本边界实现，避免生产 Foundation 依赖 Prism。
 */
#pragma once

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>
#include <Prism/Foundation/Error.hpp>

#include <boost/asio/error.hpp>
#include <boost/system/error_code.hpp>

#include <system_error>
#include <type_traits>

namespace Prism::Fault
{
    namespace Detail
    {
        /**
         * @brief 按 Fault 分类对象的身份解释其错误值。
         * @param Value 分类承载的整数值。
         * @return 有效 Code 原样映射；越界值映射为 GenericError。
         */
        [[nodiscard]] constexpr auto MapFaultCategoryValue(const int Value) noexcept -> Code
        {
            if (Value >= 0 && Value < static_cast<int>(Code::Count))
            {
                return static_cast<Code>(Value);
            }
            return Code::GenericError;
        }

        /**
         * @brief 按中立协议 Error 枚举显式映射到 Fault::Code。
         * @param Value ProtocolCategory 携带的整数值。
         * @return 对应 Code；无效枚举值映射为 GenericError。
         */
        [[nodiscard]] constexpr auto MapProtocolCategoryValue(const int Value) noexcept -> Code
        {
            switch (static_cast<Prism::Error>(Value))
            {
            case Prism::Error::None: return Code::Success;
            case Prism::Error::NeedMore: return Code::WouldBlock;
            case Prism::Error::UnexpectedEof: return Code::Eof;
            case Prism::Error::BadLength: return Code::BadMessage;
            case Prism::Error::BadMagic: return Code::BadMessage;
            case Prism::Error::BadAuth: return Code::AuthFailed;
            case Prism::Error::BadMessage: return Code::BadMessage;
            case Prism::Error::BadAddress: return Code::UnsupportedAddress;
            case Prism::Error::NotOpen: return Code::IoError;
            case Prism::Error::Canceled: return Code::Canceled;
            case Prism::Error::Timeout: return Code::Timeout;
            case Prism::Error::BrokenPipe: return Code::IoError;
            case Prism::Error::ProtocolError: return Code::ProtocolError;
            case Prism::Error::KdfError: return Code::GenericError;
            case Prism::Error::Unsupported: return Code::NotSupported;
            case Prism::Error::IoError: return Code::IoError;
            case Prism::Error::CryptoError: return Code::GenericError;
            default: return Code::GenericError;
            }
        }
    } // namespace Detail

    /**
     * @brief 检查错误码是否表示成功
     * @tparam ErrorCode 错误码类型，支持 Fault::Code、
     * std::error_code、boost::system::error_code
     * @param ErrorValue 错误码对象的常量引用
     * @return true 表示操作成功，false 表示操作失败
     * @details 使用 if constexpr 实现编译时类型分发，
     * 消除运行时类型检查开销。对于不支持的类型触发
     * static_assert 编译错误。
     */
    template <typename ErrorCode>
    [[nodiscard]] constexpr auto Succeeded(const ErrorCode &ErrorValue) noexcept -> bool
    {
        if constexpr (std::is_same_v<ErrorCode, Code>)
        {
            return ErrorValue == Code::Success;
        }
        else if constexpr (std::is_same_v<ErrorCode, std::error_code>)
        {
            return !ErrorValue;
        }
        else if constexpr (std::is_same_v<ErrorCode, boost::system::error_code>)
        {
            return !ErrorValue;
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
     * @param ErrorValue 错误码对象的常量引用
     * @return true 表示操作失败，false 表示操作成功
     * @details Succeeded() 的互补函数，语义等价于
     * !Succeeded(ErrorValue)。
     */
    template <typename ErrorCode>
    [[nodiscard]] constexpr auto Failed(const ErrorCode &ErrorValue) noexcept -> bool
    {
        return !Succeeded(ErrorValue);
    }

    /**
     * @brief 将 boost 错误码转换为 Fault::Code
     * @param ErrorValue Boost 系统错误码
     * @return 对应的内部错误码
     * @details 映射常见 Boost.Asio 网络错误到对应
     * 的 fault 错误码，未映射的错误返回 io_error。
     * @warning 未映射的 Boost 错误将返回 io_error，
     * 可能丢失原始错误信息。
     */
    [[nodiscard]] auto ToCode(const boost::system::error_code &ErrorValue) noexcept -> Code;

    /**
     * @brief 将 std 错误码转换为 Fault::Code
     * @param ErrorValue C++ 标准库错误码
     * @return 对应的内部错误码
     * @details 映射标准 errc 错误及由 Boost.Asio 官方工厂转换出的标准错误码。
     *          Boost 错误按标准类别对象和值精确匹配，不依赖消息或类别名称。
     * @warning 未映射的标准错误将返回 io_error。
     */
    [[nodiscard]] auto ToCode(const std::error_code &ErrorValue) noexcept -> Code;

} // namespace Prism::Fault
