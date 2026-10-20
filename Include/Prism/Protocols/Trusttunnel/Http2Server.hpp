/**
 * @file Http2Server.hpp
 * @brief TrustTunnel HTTP/2 CONNECT 服务端公开工厂与 typed 结果。
 */
#pragma once

#include <Prism/Protocols/Trusttunnel/Http2ServerTypes.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>

namespace Prism::Trusttunnel
{

    namespace Net = boost::asio;

    /**
     * @brief 接管 raw carrier 并完成 TLS、HTTP/2 CONNECT 与 wire authentication。
     * @param Request 按值移交 raw、immutable binding、byte pool；TLS context 借用到返回。
     * @return 已认证目标及唯一 Transmission owner，或保留 Code/Native 的 typed failure。
     * @details 首个 I/O 前准备 admission；失败由同一 ticket 负责 Close 与 Activity drain，
     *          成功 carrier 保留双向 half-close，并将最终关闭责任移交返回值。
     */
    [[nodiscard]] auto AcceptHttp2(Http2AcceptRequest Request)
        -> Net::awaitable<std::expected<Http2Accepted, Prism::Fault::Failure>>;

} // namespace Prism::Trusttunnel
