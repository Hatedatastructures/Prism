/**
 * @file Smux.hpp
 * @brief smux 协议聚合头（re-export 子头）
 * @details 统一引入 smux 族全部子头并导出工厂函数：
 * - types.hpp：常量与帧头结构
 * - Codec.hpp：帧编解码（FrameCodec 策略）
 * - Session.hpp / Client.hpp / Server.hpp：共享会话框架实例化
 * - Stream.hpp：流传输适配器
 * @note Client / Server 别名定义于 Client.hpp / Server.hpp，本文件不重复定义。
 */

#pragma once

#include <utility>

// clang-format off
#include <Prism/Protocols/Mux/Smux/Detail/Wire/Codec.hpp>
#include <Prism/Protocols/Mux/Smux/Client.hpp>
#include <Prism/Protocols/Mux/Smux/Server.hpp>
#include <Prism/Protocols/Mux/Smux/Session.hpp>
#include <Prism/Protocols/Mux/Stream.hpp>
#include <Prism/Protocols/Mux/Smux/Detail/Wire/Types.hpp>
// clang-format on

namespace Prism::Mux::Smux
{

    // =========================================================================
    // 工厂（自由函数；Client / Server 别名见 Client.hpp / Server.hpp）
    // =========================================================================

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
        const SessionOptions &Options = {}) -> Mux::Client<Detail::Codec, Memory>
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
        const SessionOptions &Options = {}) -> Mux::Server<Detail::Codec, Memory>
    {
        return Mux::Accept<Detail::Codec, Memory>(std::move(Upstream), Options);
    }

} // namespace Prism::Mux::Smux
