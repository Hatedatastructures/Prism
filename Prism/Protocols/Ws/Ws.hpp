/**
 * @file Ws.hpp
 * @brief WebSocket 的类型化建连与接收入口。
 * @details 工厂接管流传输和字节池；失败时通过 admission 在原 executor 取消、关闭并排空，
 *          成功时把唯一 StreamTransport owner 交给调用者。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <expected>
#include <memory>
#include <string>
#include <utility>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Ws/Detail/StreamOwner.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Ws
{
    namespace Net = boost::asio;

    struct ClientOptions final
    {
        std::string Host;
        std::string Key{"dGhlIHNhbXBsZSBub25jZQ=="};
    };

    struct ServerOptions final
    {
        std::string Path{"/"};
        std::string Host;
    };

    struct ConnectOptions final
    {
        SharedTransmission Transport;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
        ClientOptions Client;
    };

    struct AcceptOptions final
    {
        SharedTransmission Transport;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
        ServerOptions Server;
    };

    namespace Detail
    {
        struct Factory;
    }

    /**
     * @class StreamTransport
     * @brief 已完成 Upgrade 的 WebSocket 流传输 owner。
     * @details 仅暴露 Transmission 数据面和生命周期；握手、帧 wire、Codec 与连接状态由 Detail 所有。
     *          Activity 同时聚合本层操作与成功接管的底层传输 owner；IsRetired 是独立物理回执，
     *          不从 Drain 的历史错误推导。调用者负责停止发起、半关闭、Close、Drain 并核对 IsRetired。
     */
    class StreamTransport final : public Detail::StreamOwner<>
    {
    private:
        explicit StreamTransport(
            SharedTransmission Transport,
            std::shared_ptr<Prism::Memory::BytePool> Bytes,
            bool Client)
            : Detail::StreamOwner<>(std::move(Transport), std::move(Bytes), Client)
        {
        }

        using Detail::StreamOwner<>::Accept;
        using Detail::StreamOwner<>::ReadHandshake;
        using Detail::StreamOwner<>::WriteHandshake;
        using Detail::StreamOwner<>::MaxFramePayload;
        using Detail::StreamOwner<>::MemoryType;

        friend struct Detail::Factory;
    };

    struct ConnectResult final
    {
        std::string Accept;
        std::shared_ptr<StreamTransport> Connection;
    };

    struct AcceptResult final
    {
        std::string Key;
        std::shared_ptr<StreamTransport> Connection;
    };

    namespace Detail
    {
        struct Factory final
        {
            [[nodiscard]] static auto Connect(ConnectOptions Input)
                -> Net::awaitable<std::expected<ConnectResult, Prism::Fault::Failure>>
            {
                if (!Input.Transport)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::IoError});
                }

                auto TicketResult = co_await Prism::Contract::InboundAdmission::Prepare(
                    Input.Transport);
                if (!TicketResult)
                {
                    co_return std::unexpected(TicketResult.error());
                }
                auto Ticket = std::move(*TicketResult);

                if (!Input.Bytes)
                {
                    const auto Failure = co_await Ticket.Retire(
                        Prism::Fault::Failure{Prism::Fault::Code::IoError});
                    co_return std::unexpected(Failure);
                }

                auto Connection = std::shared_ptr<StreamTransport>(new StreamTransport(
                    Input.Transport, std::move(Input.Bytes), true));
                const auto Tracked = Ticket.Track(Connection);
                if (!Tracked)
                {
                    const auto Failure = co_await Ticket.Retire(Tracked.error());
                    co_return std::unexpected(Failure);
                }

                const auto Handshake = co_await Connection->WriteHandshake(
                    Input.Client.Key, Input.Client.Host);
                if (!Handshake)
                {
                    const auto Failure = co_await Ticket.Retire(Handshake.error());
                    co_return std::unexpected(Failure);
                }

                ConnectResult Result;
                Result.Accept = Connection->Accept();
                Result.Connection = std::move(Connection);
                Ticket.Release();
                co_return Result;
            }

            [[nodiscard]] static auto Accept(AcceptOptions Input)
                -> Net::awaitable<std::expected<AcceptResult, Prism::Fault::Failure>>
            {
                if (!Input.Transport)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::IoError});
                }

                auto TicketResult = co_await Prism::Contract::InboundAdmission::Prepare(
                    Input.Transport);
                if (!TicketResult)
                {
                    co_return std::unexpected(TicketResult.error());
                }
                auto Ticket = std::move(*TicketResult);

                if (!Input.Bytes)
                {
                    const auto Failure = co_await Ticket.Retire(
                        Prism::Fault::Failure{Prism::Fault::Code::IoError});
                    co_return std::unexpected(Failure);
                }

                auto Connection = std::shared_ptr<StreamTransport>(new StreamTransport(
                    Input.Transport, std::move(Input.Bytes), false));
                const auto Tracked = Ticket.Track(Connection);
                if (!Tracked)
                {
                    const auto Failure = co_await Ticket.Retire(Tracked.error());
                    co_return std::unexpected(Failure);
                }

                AcceptResult Result;
                const auto Handshake = co_await Connection->ReadHandshake(
                    Result.Key, Input.Server.Path, Input.Server.Host);
                if (!Handshake)
                {
                    const auto Failure = co_await Ticket.Retire(Handshake.error());
                    co_return std::unexpected(Failure);
                }

                Result.Connection = std::move(Connection);
                Ticket.Release();
                co_return Result;
            }
        };
    }

    [[nodiscard]] inline auto Connect(ConnectOptions Options)
        -> Net::awaitable<std::expected<ConnectResult, Prism::Fault::Failure>>
    {
        return Detail::Factory::Connect(std::move(Options));
    }

    [[nodiscard]] inline auto Accept(AcceptOptions Options)
        -> Net::awaitable<std::expected<AcceptResult, Prism::Fault::Failure>>
    {
        return Detail::Factory::Accept(std::move(Options));
    }
} // namespace Prism::Ws
