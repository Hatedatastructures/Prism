/**
 * @file Tuic.hpp
 * @brief TUIC QUIC 数据报 adapter。
 */

#pragma once

#include <utility>

#include <Preview/Composition/Adapters/DataPlane.hpp>
#include <Preview/Protocols/Tuic/Tuic.hpp>

namespace Preview::Composition::Adapters
{

    /**
     * @brief 将已绑定的 QUIC 数据报 provider 组装为 TUIC 数据面。
     * @param Provider 已认证 QUIC 会话的数据报 provider。
     * @param Config TUIC 服务端配置。
     * @return 类型化数据面结果。
     */
    [[nodiscard]] inline auto MakeTuicDatagram(
        Preview::Quic::SharedDatagramProvider Provider,
        const Preview::Tuic::ServerConfig &Config) -> DataPlaneResult
    {
        if (!Provider)
        {
            return DataPlaneResult::Failure(Preview::Error::NotOpen);
        }
        auto Datagram = Preview::Tuic::AcceptPacket(std::move(Provider), Config);
        if (!Datagram)
        {
            return DataPlaneResult::Failure(Preview::Error::IoError);
        }
        return DataPlaneResult::Datagram(std::move(Datagram));
    }

} // namespace Preview::Composition::Adapters
