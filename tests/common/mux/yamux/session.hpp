/**
 * @file session.hpp
 * @brief yamux 多路复用会话（共享框架 + yamux 帧策略）
 * @details 复用 mux::session<yamux::codec> 共享框架，
 *          提供 yamux 专属别名与工厂。
 */

#pragma once

#include <common/mux/codec.hpp>
#include <common/mux/session.hpp>
#include <common/mux/yamux/codec.hpp>
#include <common/mux/yamux/types.hpp>

namespace psmtest::mux::yamux
{

    /**
     * @brief yamux 会话（共享框架实例化，可注入内存策略）
     * @tparam Memory 会话内存策略（默认 8KB arena）
     */
    template <psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
    using session = mux::session<codec, Memory>;

    /**
     * @brief 创建 yamux 会话
     * @tparam Memory 会话内存策略（默认 8KB arena）
     * @param raw 底层传输（所有权移交）
     * @param opt 会话选项
     * @return 会话实例
     */
    template <psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
    [[nodiscard]] inline auto make_session(std::shared_ptr<transport_base> raw,
                                           const session_options &opt = {}) -> std::shared_ptr<session<Memory>>
    {
        return session<Memory>::create(std::move(raw), opt);
    }

} // namespace psmtest::mux::yamux
