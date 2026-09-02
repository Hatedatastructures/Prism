/**
 * @file H2Mux.hpp
 * @brief h2mux 协议聚合头（re-export 子头）
 * @details 统一引入 h2mux 族全部子头并导出工厂函数：
 * - types.hpp：常量与帧头结构
 * - Codec.hpp：帧编解码（FrameCodec 策略）
 * - Session.hpp / Client.hpp / Server.hpp：共享会话框架实例化
 * - Stream.hpp：流传输适配器
 * @note Client / Server 别名定义于 Client.hpp / Server.hpp，本文件不重复定义。
 */

#pragma once

// clang-format off
#include <preview/Protocols/Mux/H2Mux/Codec.hpp>
#include <preview/Protocols/Mux/H2Mux/Client.hpp>
#include <preview/Protocols/Mux/H2Mux/Server.hpp>
#include <preview/Protocols/Mux/H2Mux/Session.hpp>
#include <preview/Protocols/Mux/Stream.hpp>
#include <preview/Protocols/Mux/H2Mux/Types.hpp>
// clang-format on

namespace Preview::Mux::H2Mux
{

    // =========================================================================
    // 工厂（自由函数；Client / Server 别名见 Client.hpp / Server.hpp）
    // =========================================================================

    /**
     * @brief 创建客户端会话（工厂）
     * @tparam Memory 会话内存策略（默认 8KB Arena）
     * @param upstream 上游传输（所有权移交）
     * @param opt 会话选项
     * @return 客户端会话容器
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    [[nodiscard]] inline auto Connect(SharedTransmission upstream,
                                      const SessionOptions &opt = {}) -> Mux::Client<Codec, Memory>
    {
        return Mux::Connect<Codec, Memory>(std::move(upstream), opt);
    }

    /**
     * @brief 创建服务端会话（工厂）
     * @tparam Memory 会话内存策略（默认 8KB Arena）
     * @param upstream 上游传输（所有权移交）
     * @param opt 会话选项
     * @return 服务端会话容器
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    [[nodiscard]] inline auto Accept(SharedTransmission upstream,
                                     const SessionOptions &opt = {}) -> Mux::Server<Codec, Memory>
    {
        return Mux::Accept<Codec, Memory>(std::move(upstream), opt);
    }

} // namespace Preview::Mux::H2Mux
