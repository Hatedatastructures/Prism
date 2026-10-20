/**
 * @file ShadowtlsTypes.cpp
 * @brief ShadowTLS typed 错误投影实现。
 */
#include <Prism/Protocols/Shadowtls/Types.hpp>

#include <Prism/Foundation/Fault/Handling.hpp>

namespace Prism::Shadowtls
{
    auto FailureFromError(const Prism::Error ErrorCode, const std::size_t Bytes) noexcept
        -> Failure
    {
        const auto Native = static_cast<std::error_code>(Prism::make_error_code(ErrorCode));
        return {Prism::Fault::ToCode(Native), Native, Bytes};
    }

    auto FailureFromFault(const Prism::Fault::Failure &Value, const std::size_t Bytes) noexcept
        -> Failure
    {
        return {Value.Code, Value.Native, Bytes};
    }

    auto ToFaultFailure(const Failure &Value) noexcept -> Prism::Fault::Failure
    {
        return {Value.Code, Value.Native};
    }

    auto ToProtocolError(const Prism::Fault::Code Code) noexcept -> Prism::Error
    {
        switch (Code)
        {
        case Prism::Fault::Code::Success: return Prism::Error::None;
        case Prism::Fault::Code::Eof: return Prism::Error::UnexpectedEof;
        case Prism::Fault::Code::AuthFailed: return Prism::Error::BadAuth;
        case Prism::Fault::Code::Canceled: return Prism::Error::Canceled;
        case Prism::Fault::Code::Timeout: return Prism::Error::Timeout;
        case Prism::Fault::Code::NotSupported: return Prism::Error::Unsupported;
        case Prism::Fault::Code::BadMessage: return Prism::Error::BadMessage;
        default: return Prism::Error::IoError;
        }
    }
}
