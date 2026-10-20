/**
 * @file ForwardRequest.hpp
 * @brief HTTP/1.1 普通正向代理请求序列化接口
 */

#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace Prism::Http11
{
    struct HttpRequest;

    [[nodiscard]] auto BuildForwardRequest(std::string_view Raw,
                                           const HttpRequest &Request) -> std::string;
} // namespace Prism::Http11
