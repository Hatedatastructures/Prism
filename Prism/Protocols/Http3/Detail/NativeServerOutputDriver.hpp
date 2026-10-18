/**
 * @file NativeServerOutputDriver.hpp
 * @brief 驱动 HTTP/3 输出包写入 QUIC stream 并完成 FIN 半关闭。
 * @details 每次写入只确认 provider 接受的字节；协议 write offset 随确认量推进。
 */

#pragma once

#include <cstddef>
#include <span>
#include <system_error>
#include <vector>

#include <Prism/Protocols/Http3/Detail/NativeServer.hpp>

namespace Prism::Http3::Detail
{
    inline auto NativeServerOutputDriver::Drain(NativeServerSessionOwner &Owner)
    -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        while (!Owner.Closed_ && Owner.Server_ && Owner.Server_->IsOpen())
        {
            std::vector<OutPacket> Packets;
            if (!Owner.Server_->PumpOutput(Packets))
            {
                Owner.Observe(NativeServerSessionStage::DrainOutput, Fault::Code::ProtocolError);
                co_return std::unexpected(
                    Prism::Fault::Failure{Fault::Code::ProtocolError});
            }
            if (Packets.empty())
            {
                Owner.Observe(NativeServerSessionStage::DrainOutput);
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            for (auto &Packet : Packets)
            {
                const auto It = Owner.Streams_.find(Packet.StreamId);
                if (It == Owner.Streams_.end() || !It->second)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Fault::Code::ProtocolError});
                }
                std::size_t Offset = 0;
                while (Offset < Packet.Data.size())
                {
                    std::error_code Error;
                    const auto Written = co_await It->second->Write(
                        std::span<const std::byte>(Packet.Data).subspan(Offset), Error);
                    if (Owner.Closed_)
                    {
                        co_return std::unexpected(
                            Prism::Fault::Failure{Fault::Code::Canceled});
                    }
                    if (Error || Written == 0 || Written > Packet.Data.size() - Offset)
                    {
                        auto Failure = Prism::Fault::Failure{Fault::Code::WouldBlock};
                        if (Error) Failure = Prism::Fault::FromNative(Error);
                        Owner.RecordFailure(Failure);
                        Owner.Observe(
                            NativeServerSessionStage::DrainOutput, Failure.Code,
                            Packet.StreamId);
                        co_return std::unexpected(Failure);
                    }
                    Offset += Written;
                    Owner.Server_->AddWriteOffset(Packet.StreamId, Written);
                }
                if (Packet.Fin)
                {
                    Owner.Server_->AddWriteOffset(Packet.StreamId, 0);
                    const auto Shutdown = co_await It->second->ShutdownWrite();
                    if (Owner.Closed_)
                    {
                        co_return std::unexpected(
                            Prism::Fault::Failure{Fault::Code::Canceled});
                    }
                    if (!Shutdown)
                    {
                        Owner.RecordFailure(Shutdown.error());
                        Owner.Observe(
                            NativeServerSessionStage::DrainOutput, Shutdown.error().Code,
                            Packet.StreamId);
                        co_return std::unexpected(Shutdown.error());
                    }
                }
            }
        }
        co_return std::unexpected(
            Prism::Fault::Failure{Fault::Code::Canceled});
    }
}
