/**
 * @file Facades.cpp
 * @brief 原生 QUIC Client、Server、Gateway 门面的生命周期与调用 owner。
 */

#include <Prism/Protocols/Quic/Native.hpp>
#include <Prism/Protocols/Quic/Native/Stream/Detail/Admission.hpp>

#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string_view>
#include <utility>

namespace Prism::Quic
{
    Client::Client(const ClientOptions &Options)
        : Connection_(std::make_shared<Detail::NativeConnection>(Options))
    {
    }

    Client::~Client() noexcept
    {
        if (Connection_)
        {
            Connection_->Close();
        }
    }

    auto Client::Start() -> void
    {
        if (Connection_)
        {
            Connection_->Start();
        }
    }

    auto Client::WaitHandshake() -> Net::awaitable<bool>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return false;
        }
        co_return co_await Connection->WaitHandshake();
    }

    auto Client::MarkProtocolReady() -> Net::awaitable<bool>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return false;
        }
        co_return co_await Connection->MarkProtocolReady();
    }

    auto Client::OpenBidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Connection->OpenBidirectionalStream();
    }

    auto Client::OpenUnidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Connection->OpenUnidirectionalStream();
    }

    auto Client::AcceptUnidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Connection->AcceptUnidirectionalStream();
    }

    auto Client::ExportKeyingMaterial(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) const -> bool
    {
        return Connection_ && Connection_->ExportKeyingMaterial(Output, Label, Context);
    }

    auto Client::Close() -> void
    {
        if (Connection_)
        {
            Connection_->Close();
        }
    }

    auto Client::Drain() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Connection = Connection_;
        return DrainConnection(Connection);
    }

    auto Client::DrainConnection(std::shared_ptr<Detail::NativeConnection> Connection)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Connection)
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        co_return co_await Connection->Drain();
    }

    Server::Server(const ServerOptions &Options)
        : Context_(Prism::Executor::ContextOwner::Find(Options.Executor)),
          Generation_(Options.Generation),TlsContext_(Options.TlsContext),
          Connection_(std::make_shared<Detail::NativeConnection>(Options)),
          OnStarted_(Options.OnStarted)
    {
    }

    Server::~Server() noexcept
    {
        if (Connection_)
        {
            Connection_->Close();
        }
    }

    auto Server::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return DrainOwned(shared_from_this());
    }

    auto Server::ReceivePacket(
        const std::span<const std::byte> Data,
        const Net::ip::udp::endpoint &Peer) -> bool
    {
        return Connection_ && Connection_->ReceivePacket(Peer, Data);
    }

    auto Server::WaitHandshake() -> Net::awaitable<bool>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return false;
        }
        co_return co_await Connection->WaitHandshake();
    }

    auto Server::MarkProtocolReady() -> Net::awaitable<bool>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return false;
        }
        co_return co_await Connection->MarkProtocolReady();
    }

    auto Server::AcceptBidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Connection->AcceptBidirectionalStream();
    }

    auto Server::OpenUnidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Connection->OpenUnidirectionalStream();
    }

    auto Server::AcceptUnidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Connection->AcceptUnidirectionalStream();
    }

    auto Server::ExportKeyingMaterial(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) const -> bool
    {
        return Connection_ && Connection_->ExportKeyingMaterial(Output, Label, Context);
    }

    auto Server::Close() -> void
    {
        if (Connection_)
        {
            Connection_->Close();
        }
    }

    Gateway::Gateway(ServerOptions Options) : Server_(std::make_shared<Server>(std::move(Options)))
    {
    }

    auto Gateway::Start() -> void
    {
        if (Server_)
        {
            Server_->Start();
        }
    }

    auto Gateway::WaitHandshake() -> Net::awaitable<bool>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return false;
        }
        co_return co_await Server->WaitHandshake();
    }

    auto Gateway::MarkProtocolReady() -> Net::awaitable<bool>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return false;
        }
        co_return co_await Server->MarkProtocolReady();
    }

    auto Gateway::AcceptBidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Server->AcceptBidirectionalStream();
    }

    auto Gateway::OpenUnidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Server->OpenUnidirectionalStream();
    }

    auto Gateway::AcceptUnidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return std::unexpected(Detail::StreamCanceled());
        }
        co_return co_await Server->AcceptUnidirectionalStream();
    }

    auto Gateway::ExportKeyingMaterial(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) const -> bool
    {
        return Server_ && Server_->ExportKeyingMaterial(Output, Label, Context);
    }

    auto Gateway::Close() -> void
    {
        if (Server_)
        {
            Server_->Close();
        }
    }

    auto Gateway::Drain() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Server = Server_;
        return Server->Drain();
    }

    auto Server::Start() -> void
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

    /** @brief 创建等待任务时保活 server、context 与 generation，直到 native drain 退出。 */
    auto Server::DrainOwned(std::shared_ptr<Server> Owner)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Connection = Owner->Connection_;
        if (!Connection)
        {
            Owner->Generation_ = {};
            Owner->TlsContext_.reset();
            Owner->OnStarted_ = {};
            co_return std::expected<void, Prism::Fault::Failure>{};
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
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }
} // namespace Prism::Quic
