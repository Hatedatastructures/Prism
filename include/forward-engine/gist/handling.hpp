/**
 * @file handling.hpp
 * @brief 极简错误码检查适配层（热路径安全）
 * @details 
 * 提供对 `ngx::gist::code`、`std::error_code` 和 `boost::system::error_code` 的统一错误检查。
 * 所有函数均为 `constexpr` 和 `noexcept`，确保热路径零开销。
 * 
 * 设计原则：
 * - 无异常抛出：热路径严禁使用异常
 * - 零动态分配：所有函数不进行堆分配  
 * - 类型安全：编译期类型检查
 * - 极简设计：只提供错误状态检查，不提供错误描述
 * 
 */
#pragma once

#include <system_error>
#include <type_traits>

#include <boost/system/error_code.hpp>
#include <forward-engine/gist/code.hpp>

namespace ngx::gist
{
    /**
     * @brief 检查错误码是否表示成功（热路径安全）
     * @tparam ErrorCode 错误码类型（支持 code/std::error_code/boost::system::error_code）
     * @param ec 错误码
     * @return true 表示成功，false 表示失败
     * @note 此函数不抛出异常，适用于网络I/O、协议解析等性能敏感路径
     */
    template <typename ErrorCode>
    [[nodiscard]] constexpr bool succeeded(const ErrorCode &ec) noexcept
    {
        if constexpr (std::is_same_v<ErrorCode, code>)
        {
            return ec == code::success;
        }
        else if constexpr (std::is_same_v<ErrorCode, std::error_code>)
        {
            return !ec;
        }
        else if constexpr (std::is_same_v<ErrorCode, boost::system::error_code>)
        {
            return !ec;
        }
        else
        {
            static_assert(sizeof(ErrorCode) == 0, "不支持的错误码类型");
        }
        return false;
    }

    /**
     * @brief 检查错误码是否表示失败（热路径安全）
     * @tparam ErrorCode 错误码类型
     * @param ec 错误码
     * @return true 表示失败，false 表示成功
     * @note 此函数不抛出异常，适用于网络I/O、协议解析等性能敏感路径
     */
    template <typename ErrorCode>
    [[nodiscard]] constexpr bool failed(const ErrorCode &ec) noexcept
    {
        return !succeeded(ec);
    }

} // namespace ngx::gist
