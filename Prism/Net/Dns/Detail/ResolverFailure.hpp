/**
 * @file ResolverFailure.hpp
 * @brief DNS Resolver 的原生失败归类与取消识别。
 * @details 错误码只在 Resolver 边界映射一次；Failure 同时保留领域类别和原生 category/value。
 */
#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/error.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/error_code.hpp>

#include <system_error>

namespace Prism::Network::Dns::Detail
{
    /**
     * @brief 判断 Boost.Asio 查询错误是否为取消。
     * @param ErrorCode 已观察到的 Boost.System 错误。
     * @return Asio 或 Boost 标准取消值返回 true。
     */
    [[nodiscard]] inline auto IsResolverCancellation(
        const boost::system::error_code &ErrorCode) noexcept -> bool
    {
        return ErrorCode == boost::asio::error::operation_aborted ||
               ErrorCode == boost::system::errc::make_error_code(
                                boost::system::errc::operation_canceled);
    }

    /**
     * @brief 将 Boost.System 失败保留为唯一领域值。
     * @param ErrorCode 已观察到的 Boost.System 错误；成功值返回默认 Failure。
     * @return Failure 保留转换后的原生 category/value；名称查询失败归为 DnsFailed。
     */
    [[nodiscard]] inline auto ResolverFailureFromBoost(
        const boost::system::error_code &ErrorCode) noexcept -> Prism::Fault::Failure
    {
        if (!ErrorCode)
        {
            return {};
        }
        const auto Native = static_cast<std::error_code>(ErrorCode);
        auto Failure = Prism::Fault::FromNative(Native);
        if (IsResolverCancellation(ErrorCode))
        {
            Failure.Code = Prism::Fault::Code::Canceled;
        }
        else if (ErrorCode == boost::asio::error::host_not_found ||
                 ErrorCode == boost::asio::error::host_not_found_try_again ||
                 ErrorCode == boost::asio::error::no_data)
        {
            Failure.Code = Prism::Fault::Code::DnsFailed;
        }
        return Failure;
    }

    /**
     * @brief 将标准库失败保留为唯一领域值。
     * @param ErrorCode 已观察到的标准错误；成功值返回默认 Failure。
     * @return Failure 保留原生 category/value，取消保持独立领域类别。
     */
    [[nodiscard]] inline auto ResolverFailureFromNative(
        const std::error_code &ErrorCode) noexcept -> Prism::Fault::Failure
    {
        if (!ErrorCode)
        {
            return {};
        }
        auto Failure = Prism::Fault::FromNative(ErrorCode);
        if (ErrorCode == std::make_error_code(std::errc::operation_canceled))
        {
            Failure.Code = Prism::Fault::Code::Canceled;
        }
        return Failure;
    }

    /**
     * @brief 判断类型化失败是否为取消。
     * @param Failure Resolver 当前阶段的失败值。
     * @return 领域取消或原生取消返回 true。
     */
    [[nodiscard]] inline auto IsResolverCancellation(
        const Prism::Fault::Failure &Failure) noexcept -> bool
    {
        return Failure.Code == Prism::Fault::Code::Canceled ||
               Failure.Native == std::make_error_code(std::errc::operation_canceled) ||
               Failure.Native == static_cast<std::error_code>(
                                     boost::asio::error::make_error_code(
                                         boost::asio::error::operation_aborted));
    }
} // namespace Prism::Network::Dns::Detail
