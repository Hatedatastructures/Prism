/**
 * @file bootstrap.hpp
 * @brief 多路复用会话引导（sing-mux 协商 + 协议分流）
 */

#pragma once

#include <prism/diagnose/context.hpp>
#include <prism/foundation/memory/pool.hpp>
#include <prism/net/connection/types.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/protocol/multiplex/config.hpp>
#include <prism/protocol/multiplex/multiplexer.hpp>
#include <prism/resource/session.hpp>

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
        transport::shared_transmission transport; ///< 已协商完成的多路复用传输层
        psm::resource::session *res{nullptr};     ///< 会话资源指针
    };

    /**
     * @brief 引导多路复用会话（sing-mux 协商 + 协议分流）
     * @param ctx 引导上下文（transport + res）
     * @return 多路复用器共享指针
     */
    [[nodiscard]] auto bootstrap(bootstrap_context ctx) -> net::awaitable<std::shared_ptr<multiplexer>>;

} // namespace psm::multiplex
