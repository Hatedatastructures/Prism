/**
 * @file bootstrap.hpp
 * @brief 多路复用会话引导（sing-mux 协商 + 协议分流）
 */

#pragma once

#include <prism/foundation/memory/pool.hpp>
#include <prism/protocol/multiplex/config.hpp>
#include <prism/protocol/multiplex/core.hpp>
#include <prism/resource/session.hpp>
#include <prism/trace/context.hpp>
#include <prism/net/connect/types.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <memory>


namespace psm::multiplex
{

    namespace net = boost::asio;

    /**
     * @struct bootstrap_context
     * @brief 多路复用会话引导上下文
     */
    struct bootstrap_context
    {
        transport::shared_transmission transport;
        psm::resource::session *res{nullptr};
    };

    [[nodiscard]] auto bootstrap(bootstrap_context ctx)
        -> net::awaitable<std::shared_ptr<core>>;

} // namespace psm::multiplex
