/**
 * @file NativeFacades.hpp
 * @brief 原生 QUIC Client、Server、Gateway 门面 owner。
 * @details 门面只转发到共享 NativeConnection，生命周期关闭仍由连接 owner 负责；
 *          多连接监听和 CID 路由由上层 Boundary/Registry 持有。
 */

#pragma once

#include <Preview/Protocols/Quic/Detail/NativeConnection.hpp>
#include <Preview/Protocols/Quic/Detail/NativeConnectionStreamAdmission.hpp>

namespace Preview::Quic
{

    inline Client::Client(const ClientOptions &Options)
        : Connection_(std::make_shared<Detail::NativeConnection>(Options))
    {
    }

    inline Client::~Client() noexcept
    {
        if (Connection_)
        {
            Connection_->Close();
        }
    }

    inline auto Client::Start() -> void
    {
        if (Connection_)
        {
            Connection_->Start();
        }
    }

    inline auto Client::WaitHandshake() -> Net::awaitable<bool>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return false;
        }
        co_return co_await Connection->WaitHandshake();
    }

    inline auto Client::MarkProtocolReady() -> Net::awaitable<bool>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return false;
        }
        co_return co_await Connection->MarkProtocolReady();
    }

    inline auto Client::OpenBidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Preview::Fault::Failure>>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Connection->OpenBidirectionalStream();
    }

    inline auto Client::OpenUnidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Preview::Fault::Failure>>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Connection->OpenUnidirectionalStream();
    }

    inline auto Client::AcceptUnidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Preview::Fault::Failure>>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Connection->AcceptUnidirectionalStream();
    }

    inline auto Client::ExportKeyingMaterial(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) const -> bool
    {
        return Connection_ && Connection_->ExportKeyingMaterial(Output, Label, Context);
    }

    inline auto Client::Datagram() const -> SharedDatagramProvider
    {
        if (Connection_)
        {
            return Connection_->DatagramProvider();
        }
        return nullptr;
    }

    inline auto Client::Close() -> void
    {
        if (Connection_)
        {
            Connection_->Close();
        }
    }

    inline auto Client::Drain() -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
        co_return co_await Connection->Drain();
    }

    inline auto Client::IsRetired() const noexcept -> bool
    {
        return !Connection_ || Connection_->IsRetired();
    }

    inline auto Client::Health() const noexcept -> NativeConnectionHealth
    {
        if (!Connection_)
        {
            return NativeConnectionHealth{.Closed = true};
        }
        return Connection_->Health();
    }

    inline Server::Server(const ServerOptions &Options)
        : Context_(Preview::Executor::ContextOwner::Find(Options.Executor)),
          Generation_(Options.Generation),TlsContext_(Options.TlsContext),
          Connection_(std::make_shared<Detail::NativeConnection>(Options)),
          OnStarted_(Options.OnStarted)
    {
    }

    inline Server::~Server() noexcept
    {
        if (Connection_)
        {
            Connection_->Close();
        }
    }

    inline auto Server::Start() -> void
    {
        if (Connection_)
        {
            Connection_->Start();
        }
        if (OnStarted_)
        {
            try
            {
                OnStarted_(shared_from_this());
            }
            catch (...)
            {
            }
        }
    }

    inline auto Server::Drain()
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        return DrainOwned(shared_from_this());
    }

    /** @brief 创建等待任务时保活 server、context 与 generation，直到 native drain 退出。 */
    inline auto Server::DrainOwned(std::shared_ptr<Server> Owner)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        const auto Connection=Owner->Connection_;
        if (!Connection)
        {
            Owner->Generation_ = {};
            Owner->TlsContext_.reset();
            Owner->OnStarted_ = {};
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
        const auto Drained = co_await Connection->Drain();
        const auto NativeRetired = Connection->IsRetired();
        if (NativeRetired)
        {
            Owner->Connection_.reset();
            Owner->Generation_ = {};
            Owner->TlsContext_.reset();
            Owner->OnStarted_ = {};
        }
        if (!Drained)
        {
            co_return std::unexpected(Drained.error());
        }
        if (!NativeRetired)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        co_return std::expected<void, Preview::Fault::Failure>{};
    }

    inline auto Server::ReceivePacket(
        const std::span<const std::byte> Data,
        const Net::ip::udp::endpoint &Peer) -> bool
    {
        return Connection_ && Connection_->ReceivePacket(Peer, Data);
    }

    inline auto Server::WaitHandshake() -> Net::awaitable<bool>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return false;
        }
        co_return co_await Connection->WaitHandshake();
    }

    inline auto Server::MarkProtocolReady() -> Net::awaitable<bool>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return false;
        }
        co_return co_await Connection->MarkProtocolReady();
    }

    inline auto Server::AcceptBidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Preview::Fault::Failure>>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Connection->AcceptBidirectionalStream();
    }

    inline auto Server::OpenUnidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Preview::Fault::Failure>>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Connection->OpenUnidirectionalStream();
    }

    inline auto Server::AcceptUnidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Preview::Fault::Failure>>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Connection->AcceptUnidirectionalStream();
    }

    inline auto Server::ExportKeyingMaterial(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) const -> bool
    {
        return Connection_ && Connection_->ExportKeyingMaterial(Output, Label, Context);
    }

    inline auto Server::Datagram() const -> SharedDatagramProvider
    {
        if (Connection_)
        {
            return Connection_->DatagramProvider();
        }
        return nullptr;
    }

    inline auto Server::Close() -> void
    {
        if (Connection_)
        {
            Connection_->Close();
        }
    }

    inline auto Server::IsRetired() const noexcept -> bool
    {
        return !Connection_ && !TlsContext_ && !OnStarted_;
    }

    inline auto Server::Health() const noexcept -> NativeConnectionHealth
    {
        if (!Connection_)
        {
            return NativeConnectionHealth{.Closed = true};
        }
        return Connection_->Health();
    }

    inline Gateway::Gateway(ServerOptions Options) : Server_(std::make_shared<Server>(std::move(Options)))
    {
    }

    inline auto Gateway::Start() -> void
    {
        if (Server_)
        {
            Server_->Start();
        }
    }

    inline auto Gateway::WaitHandshake() -> Net::awaitable<bool>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return false;
        }
        co_return co_await Server->WaitHandshake();
    }

    inline auto Gateway::MarkProtocolReady() -> Net::awaitable<bool>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return false;
        }
        co_return co_await Server->MarkProtocolReady();
    }

    inline auto Gateway::AcceptBidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Preview::Fault::Failure>>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Server->AcceptBidirectionalStream();
    }

    inline auto Gateway::OpenUnidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Preview::Fault::Failure>>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Server->OpenUnidirectionalStream();
    }

    inline auto Gateway::AcceptUnidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Preview::Fault::Failure>>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Server->AcceptUnidirectionalStream();
    }

    inline auto Gateway::ExportKeyingMaterial(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) const -> bool
    {
        return Server_ && Server_->ExportKeyingMaterial(Output, Label, Context);
    }

    inline auto Gateway::Datagram() const -> SharedDatagramProvider
    {
        if (Server_)
        {
            return Server_->Datagram();
        }
        return nullptr;
    }

    inline auto Gateway::Close() -> void
    {
        if (Server_)
        {
            Server_->Close();
        }
    }

    inline auto Gateway::Drain() -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
        co_return co_await Server->Drain();
    }

    inline auto Gateway::IsRetired() const noexcept -> bool
    {
        return !Server_ || Server_->IsRetired();
    }

    inline auto Gateway::Health() const noexcept -> NativeConnectionHealth
    {
        if (!Server_)
        {
            return NativeConnectionHealth{.Closed = true};
        }
        return Server_->Health();
    }


} // namespace Preview::Quic
