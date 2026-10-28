/**
 * @file Client.hpp
 * @brief TrustTunnel HTTP/2 客户端连接工厂接口。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Trusttunnel/Http2/Client/Types.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>

namespace Prism::Trusttunnel
{
    /**
     * @brief 建立经 HTTP/2 CONNECT 的客户端传输。
     * @param Parameters 按值接管上游、目标与 byte pool；TLS context 借用至握手完成。
     * @return 成功返回唯一 Transmission owner；失败保留首个 typed/native 原因并完成清理。
     */
    [[nodiscard]] auto ConnectHttp2(Http2ConnectParameters Parameters)
        -> boost::asio::awaitable<
            std::expected<SharedTransmission, Prism::Fault::Failure>>;
}
