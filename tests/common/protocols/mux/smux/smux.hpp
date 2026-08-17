/**
 * @file smux.hpp
 * @brief smux 协议聚合头（re-export 子头）
 * @details 统一引入 smux 族全部子头并导出工厂函数：
 * - types.hpp：常量与帧头结构
 * - codec.hpp：帧编解码（frame_codec 策略）
 * - session.hpp / client.hpp / server.hpp：共享会话框架实例化
 * - stream.hpp：流传输适配器
 * @note client / server 别名定义于 client.hpp / server.hpp，本文件不重复定义。
 */

#pragma once

// clang-format off
#include <common/protocols/mux/smux/codec.hpp>
#include <common/protocols/mux/smux/client.hpp>
#include <common/protocols/mux/smux/server.hpp>
#include <common/protocols/mux/smux/session.hpp>
#include <common/protocols/mux/stream.hpp>
#include <common/protocols/mux/smux/types.hpp>
// clang-format on

namespace preview::mux::smux
{

    // =========================================================================
    // 工厂（自由函数；client / server 别名见 client.hpp / server.hpp）
    // =========================================================================

    /**
     * @brief 创建客户端会话（工厂）
     * @tparam Memory 会话内存策略（默认 8KB arena）
     * @param upstream 上游传输（所有权移交）
     * @param opt 会话选项
     * @return 客户端会话容器
     */
    template <preview::memory::restrict Memory = preview::memory::session_resource<>>
    [[nodiscard]] inline auto connect(shared_transmission upstream,
                                      const session_options &opt = {}) -> mux::client<codec, Memory>
    {
        return mux::connect<codec, Memory>(std::move(upstream), opt);
    }

    /**
     * @brief 创建服务端会话（工厂）
     * @tparam Memory 会话内存策略（默认 8KB arena）
     * @param upstream 上游传输（所有权移交）
     * @param opt 会话选项
     * @return 服务端会话容器
     */
    template <preview::memory::restrict Memory = preview::memory::session_resource<>>
    [[nodiscard]] inline auto accept(shared_transmission upstream,
                                     const session_options &opt = {}) -> mux::server<codec, Memory>
    {
        return mux::accept<codec, Memory>(std::move(upstream), opt);
    }

} // namespace preview::mux::smux
