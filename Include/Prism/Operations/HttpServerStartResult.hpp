/**
 * @file HttpServerStartResult.hpp
 * @brief Operations HTTP listener 启动结果契约。
 * @details 成功返回绑定的 TCP endpoint，失败返回底层 Boost.System 错误码。
 */

#pragma once

#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>

#include <expected>

namespace Prism::Operations
{
    using HttpServerStartResult = std::expected<
        boost::asio::ip::tcp::endpoint, boost::system::error_code>;
}
