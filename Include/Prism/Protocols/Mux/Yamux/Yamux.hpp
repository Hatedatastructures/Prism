/**
 * @file Yamux.hpp
 * @brief yamux 协议聚合头（re-export 子头）
 * @details 统一定义 yamux 会话别名并导出客户端、服务端与流传输工厂。
 */

#pragma once

#include <memory>
#include <utility>

// clang-format off
#include <Prism/Protocols/Mux/Yamux/Detail/Wire/Codec.hpp>
#include <Prism/Protocols/Mux/Client.hpp>
#include <Prism/Protocols/Mux/Server.hpp>
#include <Prism/Protocols/Mux/Session.hpp>
#include <Prism/Protocols/Mux/SessionOptions.hpp>
#include <Prism/Protocols/Mux/Stream.hpp>
#include <Prism/Protocols/Mux/Yamux/Types.hpp>
#include <Prism/Protocols/Mux/Types.hpp>
// clang-format on

namespace Prism::Mux::Yamux
{

    // =========================================================================
    // yamux 类型别名与工厂。
    // =========================================================================

    /** @brief yamux 客户端会话类型。 */
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    using Client = Mux::Client<Detail::Codec, Memory>;

    /** @brief yamux 服务端会话类型。 */
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    using Server = Mux::Server<Detail::Codec, Memory>;

    /** @brief yamux 共享会话类型。 */
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    using Session = Mux::Session<Detail::Codec, Memory>;

    /** @brief 创建 yamux 会话。 */
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    [[nodiscard]] inline auto MakeSession(
        SharedTransmission Raw,
        const SessionOptions &Options = {}) -> std::shared_ptr<Session<Memory>>
    {
        return Session<Memory>::Create(std::move(Raw), Options);
    }

    /**
     * @brief 创建客户端会话（工厂）
     * @tparam Memory 会话内存策略（默认 8KB Arena）
     * @param Upstream 上游传输（所有权移交）
     * @param Options 会话选项
     * @return 客户端会话容器
     */
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    [[nodiscard]] inline auto Connect(
        SharedTransmission Upstream,
        const SessionOptions &Options = {}) -> Client<Memory>
    {
        return Mux::Connect<Detail::Codec, Memory>(std::move(Upstream), Options);
    }

    /**
     * @brief 创建服务端会话（工厂）
     * @tparam Memory 会话内存策略（默认 8KB Arena）
     * @param Upstream 上游传输（所有权移交）
     * @param Options 会话选项
     * @return 服务端会话容器
     */
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        const SessionOptions &Options = {}) -> Server<Memory>
    {
        return Mux::Accept<Detail::Codec, Memory>(std::move(Upstream), Options);
    }

} // namespace Prism::Mux::Yamux
