/**
 * @file h2mux.hpp
 * @brief h2mux 协议聚合头（re-export 子头）
 * @details 供测试引用过渡使用。
 */

#pragma once

// clang-format off
#include <common/mux/h2mux/codec.hpp>
#include <common/mux/h2mux/client.hpp>
#include <common/mux/h2mux/server.hpp>
#include <common/mux/h2mux/session.hpp>
#include <common/mux/stream.hpp>
#include <common/mux/h2mux/types.hpp>
// clang-format on

namespace psmtest::mux::h2mux
{

    /**
     * @brief 服务端会话容器（共享模板实例化，可注入内存策略）
     * @tparam Memory 会话内存策略（默认 8KB arena）
     */
    template <psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
    using server = mux::server<codec, Memory>;

    /**
     * @brief 客户端会话容器（共享模板实例化，可注入内存策略）
     * @tparam Memory 会话内存策略（默认 8KB arena）
     */
    template <psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
    using client = mux::client<codec, Memory>;

    /**
     * @brief 创建客户端会话（工厂）
     * @tparam Memory 会话内存策略（默认 8KB arena）
     * @param upstream 上游传输（所有权移交）
     * @param opt 会话选项
     * @return 客户端会话容器
     */
    template <psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
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
    template <psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
    [[nodiscard]] inline auto accept(shared_transmission upstream,
                                     const session_options &opt = {}) -> mux::server<codec, Memory>
    {
        return mux::accept<codec, Memory>(std::move(upstream), opt);
    }

} // namespace psmtest::mux::h2mux
