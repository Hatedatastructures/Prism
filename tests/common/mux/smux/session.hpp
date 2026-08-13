/**
 * @file session.hpp
 * @brief smux 多路复用会话（共享框架 + smux 帧策略）
 * @details 复用 mux::session<smux::codec> 共享框架，
 *          提供 smux 专属别名与工厂。
 */

#pragma once

#include <common/mux/codec.hpp>
#include <common/mux/session.hpp>
#include <common/mux/smux/codec.hpp>
#include <common/mux/smux/types.hpp>

namespace psmtest::mux::smux
{

    /// smux 会话（共享框架实例化）
    using session = mux::session<codec>;

    /**
     * @brief 创建 smux 会话
     * @param raw 底层传输（所有权移交）
     * @param opt 会话选项
     * @return 会话实例
     */
    [[nodiscard]] inline auto make_session(std::shared_ptr<transport_base> raw,
                                           const session_options &opt = {}) -> std::shared_ptr<session>
    {
        return session::create(std::move(raw), opt);
    }

} // namespace psmtest::mux::smux
