/**
 * @file session.hpp
 * @brief smux 多路复用会话（共享框架 + smux 帧策略）
 * @details 复用 mux::session<smux::codec> 共享框架，
 *          提供 smux 专属别名与工厂。
 */

#pragma once

#include <common/protocols/mux/codec.hpp>
#include <common/protocols/mux/session.hpp>
#include <common/protocols/mux/smux/codec.hpp>
#include <common/protocols/mux/smux/types.hpp>

namespace preview::mux::smux
{

    /**
     * @brief smux 会话（共享框架实例化，可注入内存策略）
     * @tparam Memory 会话内存策略（默认 8KB arena）
     */
    template <preview::memory::restrict Memory = preview::memory::session_resource<>>
    using session = mux::session<codec, Memory>;

    /**
     * @brief 创建 smux 会话
     * @tparam Memory 会话内存策略（默认 8KB arena）
     * @param raw 底层传输（所有权移交）
     * @param opt 会话选项
     * @return 会话实例
     */
    template <preview::memory::restrict Memory = preview::memory::session_resource<>>
    [[nodiscard]] inline auto make_session(shared_transmission raw,
                                           const session_options &opt = {}) -> std::shared_ptr<session<Memory>>
    {
        return session<Memory>::create(std::move(raw), opt);
    }

} // namespace preview::mux::smux
