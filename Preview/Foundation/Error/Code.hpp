#pragma once

#include <cstdint>

namespace Preview::Foundation
{

    /** @brief Task 2 的轻量值错误。零值表示成功。 */
    enum class Error : std::uint8_t
    {
        None = 0,
        Success = None,
        InvalidArgument,
        InvalidDescriptor,
        Duplicate,
        DuplicateKindName = Duplicate,
        MissingCapability,
        MissingCapabilities = MissingCapability,
        Frozen,
        RegistrationFrozen = Frozen,
        AlreadyFrozen,
        NotFound,
        CallbackException,
    };

    using ErrorCode = Error;

    [[nodiscard]] constexpr auto IsSuccess(const Error Value) noexcept -> bool
    {
        return Value == Error::None;
    }

} // namespace Preview::Foundation
