/**
 * @file BasicAuthentication.hpp
 * @brief HTTP/1.1 Basic 凭据转换的私有接口。
 */
#pragma once

#include <Prism/Account/Authenticator.hpp>

#include <string_view>

namespace Prism::Http11::detail
{
    /**
     * @brief 将代理认证头转换为同步 Authenticate 请求。
     * @details Base64 解码产生的用户名和密码视图只在同步 Authenticate 调用期间有效；
     *          Authenticator 不得保存这些视图。
     */
    [[nodiscard]] auto AuthenticateBasic(
        std::string_view Authorization,
        const Prism::Authenticator &Authenticator) -> Prism::AuthenticationResult;
} // namespace Prism::Http11::detail
