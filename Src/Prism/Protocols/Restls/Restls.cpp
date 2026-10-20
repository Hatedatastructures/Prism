/**
 * @file Restls.cpp
 * @brief Restls 公开工厂与服务端会话实现。
 */
#include <Prism/Protocols/Restls/Restls.hpp>

#include <Prism/Protocols/Restls/Detail/Codec.hpp>
#include <Prism/Protocols/Restls/Detail/Conn.hpp>
#include <Prism/Protocols/Restls/Detail/Retirement.hpp>
#include <Prism/Protocols/Restls/Detail/ServerSession.hpp>

#include <chrono>
#include <memory>
#include <utility>

namespace Prism::Restls::Detail
{
    TransportRetirement::TransportRetirement(SharedTransmission Transport)
        : Transport_(std::move(Transport)),
          Storage_(Prism::Executor::ContextOwner::Storage(Transport_->Executor())),
          Reclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(Transport_->Executor()))
    {
        for (auto *Layer = Transport_.get(); Layer; Layer = Layer->NextLayer())
            Activities_.push_back(Layer->Activity());
    }

    ServerSession::State::State(Net::any_io_executor Executor)
        : Signal(std::move(Executor))
    {
        Signal.expires_at(std::chrono::steady_clock::time_point::max());
    }

    ServerSession::ServerSession(ServerOptions Options)
        : Options_(std::move(Options))
    {
    }
}

namespace Prism::Restls
{
    ServerSession::ServerSession(ServerOptions Options)
        : Owner_(std::make_unique<Detail::ServerSession>(std::move(Options)))
    {
    }

    ServerSession::~ServerSession() noexcept = default;

    auto ServerSession::Run(SharedTransmission Inbound, const ServerConfig &Config)
        -> Net::awaitable<Result<SharedConn>>
    {
        auto Outcome = co_await Owner_->Run(std::move(Inbound), Config);
        if (!Outcome)
        {
            co_return std::unexpected(Outcome.error());
        }
        co_return SharedConn(std::move(*Outcome));
    }

    auto Connect(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        const std::span<const std::uint8_t> ServerRandom)
        -> Net::awaitable<Result<SharedConn>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(ProtocolFailure(Error::NotOpen));
        }
        auto Connection = std::make_shared<Detail::Conn<>>(std::move(Upstream), Config.password);
        const auto Handshake = co_await Connection->WriteHandshake(ServerRandom);
        if (!Handshake)
        {
            const auto Retired = co_await Detail::TransportRetirement::RetireAndDrain(
                std::move(Connection));
            const auto CleanupFailure = Retired ? Failure{} : Detail::WireFailure(Retired.error());
            co_return std::unexpected(PreserveFirstFailure(Handshake.error(), CleanupFailure));
        }
        co_return SharedConn(std::move(Connection));
    }

    auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config,
        const std::span<const std::uint8_t> ServerRandom)
        -> Net::awaitable<Result<SharedConn>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(ProtocolFailure(Error::NotOpen));
        }
        auto Connection = std::make_shared<Detail::Conn<>>(std::move(Upstream), Config.password);
        const auto Handshake = co_await Connection->ReadHandshake(ServerRandom);
        if (!Handshake)
        {
            const auto Retired = co_await Detail::TransportRetirement::RetireAndDrain(
                std::move(Connection));
            const auto CleanupFailure = Retired ? Failure{} : Detail::WireFailure(Retired.error());
            co_return std::unexpected(PreserveFirstFailure(Handshake.error(), CleanupFailure));
        }
        co_return SharedConn(std::move(Connection));
    }
}
