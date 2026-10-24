/** @file HttpRequestSecurity.hpp @brief Operations HTTP 请求授权判定契约。 */
#pragma once

#include <Prism/Operations/HttpRequest.hpp>
#include <Prism/Operations/Models.hpp>

#include <boost/asio/ip/tcp.hpp>

namespace Prism::Operations::HttpDetail::RequestSecurity
{
    /** @brief 校验 loopback Host、可选同源 Origin 与 POST 命令 token。 */
    [[nodiscard]] auto IsAuthorized(
        const HttpRequest &Request,
        const boost::asio::ip::tcp::endpoint &LocalEndpoint,
        const BootstrapIdentity &Identity) -> bool;
}
