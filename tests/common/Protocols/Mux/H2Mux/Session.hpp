/**
 * @file Session.hpp
 * @brief sing-mux（h2mux）多路复用会话（共享框架 + h2mux 帧策略）
 * @details 复用 Mux::Session<H2Mux::Codec> 共享框架，
 *          提供 h2mux 专属别名与工厂。
 */

#pragma once

#include <common/Protocols/Mux/Codec.hpp>
#include <common/Protocols/Mux/H2Mux/Codec.hpp>
#include <common/Protocols/Mux/H2Mux/Types.hpp>
#include <common/Protocols/Mux/Session.hpp>

namespace Preview::Mux::H2Mux
{

    /**
     * @brief h2mux 会话（共享框架实例化，可注入内存策略）
     * @tparam Memory 会话内存策略（默认 8KB Arena）
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    using Session = Mux::Session<Codec, Memory>;

    /**
     * @brief 创建 h2mux 会话
     * @tparam Memory 会话内存策略（默认 8KB Arena）
     * @param raw 底层传输（所有权移交）
     * @param opt 会话选项
     * @return 会话实例
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    [[nodiscard]] inline auto MakeSession(SharedTransmission raw,
                                           const SessionOptions &opt = {}) -> std::shared_ptr<Session<Memory>>
    {
        return Session<Memory>::Create(std::move(raw), opt);
    }

} // namespace Preview::Mux::H2Mux
