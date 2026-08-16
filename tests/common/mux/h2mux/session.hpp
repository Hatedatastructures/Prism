/**
 * @file session.hpp
 * @brief sing-mux（h2mux）多路复用会话（共享框架 + h2mux 帧策略）
 * @details 复用 mux::session<h2mux::codec> 共享框架，
 *          提供 h2mux 专属别名与工厂。
 */

#pragma once

#include <common/mux/codec.hpp>
#include <common/mux/h2mux/codec.hpp>
#include <common/mux/h2mux/types.hpp>
#include <common/mux/session.hpp>

namespace psmtest::mux::h2mux
{

    /**
     * @brief h2mux 会话（共享框架实例化，可注入内存策略）
     * @tparam Memory 会话内存策略（默认 8KB arena）
     */
    template <psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
    using session = mux::session<codec, Memory>;

    /**
     * @brief 创建 h2mux 会话
     * @tparam Memory 会话内存策略（默认 8KB arena）
     * @param raw 底层传输（所有权移交）
     * @param opt 会话选项
     * @return 会话实例
     */
    template <psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
    [[nodiscard]] inline auto make_session(shared_transmission raw,
                                           const session_options &opt = {}) -> std::shared_ptr<session<Memory>>
    {
        return session<Memory>::create(std::move(raw), opt);
    }

} // namespace psmtest::mux::h2mux
