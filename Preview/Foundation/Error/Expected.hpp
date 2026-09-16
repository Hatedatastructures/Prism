#pragma once

#include <expected>

#include <Preview/Foundation/Error/Code.hpp>

namespace Preview::Foundation
{

    template <typename Value>
    using Expected = std::expected<Value, Error>;

    using Status = Expected<void>;

    [[nodiscard]] inline auto Unexpected(const Error ValueError) -> std::unexpected<Error>
    {
        return std::unexpected<Error>(ValueError);
    }

} // namespace Preview::Foundation

namespace Preview
{

    template <typename Value>
    using Expected = Foundation::Expected<Value>;

    using BuiltinError = Foundation::Error;

} // namespace Preview
