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

    /// h2mux 会话（共享框架实例化）
    using session = mux::session<codec>;

    /// 创建 h2mux 会话
    [[nodiscard]] inline auto make_session(std::shared_ptr<transport_base> raw,
                                           const session_options &opt = {})
        -> std::shared_ptr<session>
    {
        return session::create(std::move(raw), opt);
    }

} // namespace psmtest::mux::h2mux
