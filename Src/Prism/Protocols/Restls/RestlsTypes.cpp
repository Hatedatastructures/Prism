/**
 * @file RestlsTypes.cpp
 * @brief Restls 失败投影实现。
 */
#include <Prism/Protocols/Restls/Types.hpp>

#include <Prism/Foundation/Fault/Handling.hpp>

namespace Prism::Restls
{
    auto Failure::Succeeded() const noexcept -> bool
    {
        return Code == Prism::Error::None && !Native;
    }

    auto Failure::Failed() const noexcept -> bool
    {
        return !Succeeded();
    }

    auto ToFaultFailure(const Failure &Value) noexcept -> Prism::Fault::Failure
    {
        const auto ErrorCode = Prism::make_error_code(Value.Code);
        return {Prism::Fault::ToCode(ErrorCode), Value.Native};
    }

    auto ProtocolFailure(const Prism::Error Code) noexcept -> Failure
    {
        return {Code, {}};
    }

    auto PreserveFirstFailure(Failure Primary, Failure Cleanup) noexcept -> Failure
    {
        return Primary.Failed() ? Primary : Cleanup;
    }
}
