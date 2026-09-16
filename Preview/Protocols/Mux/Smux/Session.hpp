/**
 * @file Session.hpp
 * @brief smux 多路复用会话（共享框架 + smux 帧策略）
 * @details 复用 Mux::Session<Smux::Codec> 共享框架，
 *          提供 smux 专属别名与工厂。
 */

#pragma once

#include <memory>
#include <utility>

#include <Preview/Protocols/Mux/Codec.hpp>
#include <Preview/Protocols/Mux/Session.hpp>
#include <Preview/Protocols/Mux/Smux/Codec.hpp>
#include <Preview/Protocols/Mux/Smux/Types.hpp>

namespace Preview::Mux::Smux
{

    /**
     * @brief smux 会话（共享框架实例化，可注入内存策略）
     * @tparam Memory 会话内存策略（默认 8KB Arena）
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    using Session = Mux::Session<Codec, Memory>;

    /**
     * @brief 创建 smux 会话
     * @tparam Memory 会话内存策略（默认 8KB Arena）
     * @param Raw 底层传输（所有权移交）
     * @param Options 会话选项
     * @return 会话实例
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    [[nodiscard]] inline auto MakeSession(
        SharedTransmission Raw,
        const SessionOptions &Options = {}) -> std::shared_ptr<Session<Memory>>
    {
        return Session<Memory>::Create(std::move(Raw), Options);
    }

} // namespace Preview::Mux::Smux
