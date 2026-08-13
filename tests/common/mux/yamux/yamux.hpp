/**
 * @file yamux.hpp
 * @brief yamux 协议聚合头（re-export 子头）
 * @details 供测试引用过渡使用。
 */

#pragma once

// clang-format off
#include <common/mux/yamux/codec.hpp>
#include <common/mux/yamux/client.hpp>
#include <common/mux/yamux/server.hpp>
#include <common/mux/yamux/session.hpp>
#include <common/mux/stream.hpp>
#include <common/mux/yamux/types.hpp>
// clang-format on

namespace psmtest::mux::yamux
{

    /// 服务端会话容器（共享模板实例化）
    using server = mux::server<codec>;

    /// 客户端会话容器（共享模板实例化）
    using client = mux::client<codec>;

    /**
     * @brief 创建客户端会话（工厂）
     * @param upstream 上游传输（所有权移交）
     * @param opt 会话选项
     * @return 客户端会话容器
     */
    [[nodiscard]] inline auto connect(shared_transmission upstream,
                                      const session_options &opt = {}) -> mux::client<codec>
    {
        return mux::connect<codec>(std::move(upstream), opt);
    }

    /**
     * @brief 创建服务端会话（工厂）
     * @param upstream 上游传输（所有权移交）
     * @param opt 会话选项
     * @return 服务端会话容器
     */
    [[nodiscard]] inline auto accept(shared_transmission upstream,
                                     const session_options &opt = {}) -> mux::server<codec>
    {
        return mux::accept<codec>(std::move(upstream), opt);
    }

} // namespace psmtest::mux::yamux
