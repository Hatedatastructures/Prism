/**
 * @file Expected.hpp
 * @brief Foundation 的值结果形状：以 Error 为失败值的 std::expected 别名、Status 与 Unexpected 工厂。
 * @details 在 Prism::Foundation 定义值错误 Error、Expected<Value>（即 std::expected<Value, Error>）、
 *          Status（Expected<void>，只区分成功与失败）以及把 Error 包成 std::unexpected<Error> 的
 *          Unexpected，然后在 Prism 命名空间导出同名的 Expected 模板别名和 BuiltinError。
 *          失败值是可复制的 Error 枚举而不是异常；构造、赋值与析构沿用 std::expected 的值语义，
 *          不持有堆资源、不绑定 executor，也不引入取消或协程行为。
 * @note 本头拥有 Error 类型与 Expected 结果形状，供各层契约以返回值表达失败。
 */

#pragma once

#include <cstdint>
#include <expected>

namespace Prism::Foundation
{

    /** @brief 描述符操作的纯值错误；不拥有资源或执行取消、关闭。 */
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

    template <typename Value>
    using Expected = std::expected<Value, Error>;

    using Status = Expected<void>;

    [[nodiscard]] inline auto Unexpected(const Error ValueError) -> std::unexpected<Error>
    {
        return std::unexpected<Error>(ValueError);
    }

} // namespace Prism::Foundation

namespace Prism
{

    template <typename Value>
    using Expected = Foundation::Expected<Value>;

    using BuiltinError = Foundation::Error;

} // namespace Prism
