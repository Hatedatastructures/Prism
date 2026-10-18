/** @file Code.hpp @brief 冷路径描述符注册与冻结的唯一错误类别。 */
#pragma once

#include <cstdint>

namespace Prism::Foundation
{

    /** @brief 描述符操作的纯值错误；不拥有资源或执行取消、关闭，任意 executor 可读取。 */
    enum class Error : std::uint8_t
    {
        None = 0,
        InvalidArgument,
        InvalidDescriptor,
        Duplicate,
        MissingCapability,
        Frozen,
        AlreadyFrozen,
        NotFound,
        CallbackException,
    };

    [[nodiscard]] constexpr auto IsSuccess(const Error Value) noexcept -> bool
    {
        return Value == Error::None;
    }

} // namespace Prism::Foundation
