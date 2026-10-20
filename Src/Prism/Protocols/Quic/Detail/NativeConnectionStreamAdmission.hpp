/**
 * @file NativeConnectionStreamAdmission.hpp
 * @brief QUIC Native 原生错误类别与流准入映射的私有声明。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <system_error>

namespace Prism::Quic::Detail
{
    [[nodiscard]] auto NgTcp2ErrorCategory() noexcept
        -> const std::error_category &;
    [[nodiscard]] auto NgTcp2IoFailure(const int NativeValue) noexcept
        -> Prism::Fault::Failure;
    [[nodiscard]] auto StreamCanceled(std::error_code Native = {}) noexcept
        -> Prism::Fault::Failure;
    [[nodiscard]] auto StreamBlocked() noexcept -> Prism::Fault::Failure;
    [[nodiscard]] auto NgTcp2Failure(const int NativeValue) noexcept
        -> Prism::Fault::Failure;

} // namespace Prism::Quic::Detail
