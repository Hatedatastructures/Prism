/**
 * @file Shadowtls.cpp
 * @brief ShadowTLS 公开工厂与服务端会话实现。
 */
#include <Prism/Protocols/Shadowtls/Shadowtls.hpp>

#include <Prism/Protocols/Shadowtls/Detail/Conn.hpp>
#include <Prism/Protocols/Shadowtls/Detail/Retirement.hpp>
#include <Prism/Protocols/Shadowtls/Detail/ServerSession.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <limits>
#include <memory>
#include <utility>

namespace Prism::Shadowtls::Detail
{
    TransportRetirement::TransportRetirement(SharedTransmission Transport)
        : Transport_(std::move(Transport)),
          Storage_(Prism::Executor::ContextOwner::Storage(Transport_->Executor())),
          Reclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(Transport_->Executor()))
    {
        for (auto *Layer = Transport_.get(); Layer; Layer = Layer->NextLayer())
            Activities_.push_back(Layer->Activity());
    }

    RecordProtector::RecordProtector(RecordProtectionOptions Options)
        : Context_(HMAC_CTX_new()), Direction_(Options.Tag), Mode_(Options.Mode)
    {
        constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
        const auto ValidMode = Mode_ == ProtectionMode::Application ||
                               Mode_ == ProtectionMode::ServerFlight;
        const auto ValidSeed =
            (Mode_ == ProtectionMode::Application &&
             Options.ChainSeed == RecordSeed::Directional) ||
            (Mode_ == ProtectionMode::ServerFlight &&
             Options.ChainSeed == RecordSeed::ServerRandomOnly);
        if (!Context_ || Options.ServerRandom.size() != TlsRndSize ||
            (Options.Tag != TagClient && Options.Tag != TagServer) ||
            Options.Password.size() > MaxInt || !ValidMode || !ValidSeed)
        {
            return;
        }
        if (HMAC_Init_ex(Context_, Options.Password.data(),
                         static_cast<int>(Options.Password.size()), EVP_sha1(), nullptr) != 1 ||
            HMAC_Update(Context_, Options.ServerRandom.data(), Options.ServerRandom.size()) != 1 ||
            (Options.ChainSeed == RecordSeed::Directional &&
             HMAC_Update(Context_, reinterpret_cast<const std::uint8_t *>(&Direction_), 1) != 1))
        {
            return;
        }
        if (Mode_ == ProtectionMode::ServerFlight)
        {
            Key_ = Kdf(Options.Password, Options.ServerRandom);
        }
        Valid_ = true;
    }

    ServerSession::ServerSession(ServerOptions Options)
        : Options_(std::move(Options))
    {
    }
}

namespace Prism::Shadowtls
{
    ServerSession::ServerSession(ServerOptions Options)
        : Owner_(std::make_unique<Detail::ServerSession>(std::move(Options)))
    {
    }

    ServerSession::~ServerSession() noexcept = default;

    auto ServerSession::Run(SharedTransmission Inbound, ServerConfig Config)
        -> Net::awaitable<Result<SharedConn>>
    {
        co_return co_await Owner_->Run(std::move(Inbound), std::move(Config));
    }

    auto Connect(ConnectParameters Params) -> Net::awaitable<Result<SharedConn>>
    {
        if (!Params.Upstream)
        {
            co_return std::unexpected(FailureFromError(Error::NotOpen));
        }
        auto Connection = std::make_shared<Detail::Conn<>>(
            std::move(Params.Upstream), Params.Config.Password);
        auto Handshake = co_await Connection->WriteHandshake(
            Params.ServerRandom, Params.ClientRandom);
        if (!Handshake)
        {
            auto Failure = Handshake.error();
            const auto Retired = co_await Detail::TransportRetirement::RetireAndDrain(
                std::static_pointer_cast<Prism::Transmission>(std::move(Connection)));
            if (!Retired && !Failure.Native)
            {
                Failure.Native = Retired.error().Native;
            }
            co_return std::unexpected(std::move(Failure));
        }
        co_return SharedConn(std::move(Connection));
    }

    auto ConnectStandard(StandardConnectParameters Params)
        -> Net::awaitable<Result<StandardConnectResult>>
    {
        if (!Params.Upstream)
        {
            co_return std::unexpected(FailureFromError(Error::NotOpen));
        }
        auto Connection = std::make_shared<Detail::Conn<>>(
            std::move(Params.Upstream), Params.Config.Password);
        auto Handshake = co_await Connection->WriteStandardHandshake(Params.ClientHelloWire);
        if (!Handshake)
        {
            auto Failure = Handshake.error();
            const auto Retired = co_await Detail::TransportRetirement::RetireAndDrain(
                std::static_pointer_cast<Prism::Transmission>(std::move(Connection)));
            if (!Retired && !Failure.Native)
            {
                Failure.Native = Retired.error().Native;
            }
            co_return std::unexpected(std::move(Failure));
        }
        co_return StandardConnectResult{
            Connection->TakeClientHelloWire(), SharedConn(std::move(Connection))};
    }

    auto Accept(SharedTransmission Upstream, const ServerConfig &Config)
        -> Net::awaitable<Result<SharedConn>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(FailureFromError(Error::NotOpen));
        }
        auto Connection = std::make_shared<Detail::Conn<>>(
            std::move(Upstream), Config.Password);
        auto Handshake = co_await Connection->ReadHandshake();
        if (!Handshake)
        {
            auto Failure = Handshake.error();
            const auto Retired = co_await Detail::TransportRetirement::RetireAndDrain(
                std::static_pointer_cast<Prism::Transmission>(std::move(Connection)));
            if (!Retired && !Failure.Native)
            {
                Failure.Native = Retired.error().Native;
            }
            co_return std::unexpected(std::move(Failure));
        }
        co_return SharedConn(std::move(Connection));
    }

    auto AcceptStandard(SharedTransmission Upstream, const ServerConfig &Config)
        -> Net::awaitable<Result<ServerHandover>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(FailureFromError(Error::NotOpen));
        }
        auto Connection = std::make_shared<Detail::Conn<>>(
            std::move(Upstream), Config.Password);
        auto Handshake = co_await Connection->ReadStandardHandshake();
        if (!Handshake)
        {
            auto Failure = Handshake.error();
            const auto Retired = co_await Detail::TransportRetirement::RetireAndDrain(
                std::static_pointer_cast<Prism::Transmission>(std::move(Connection)));
            if (!Retired && !Failure.Native)
            {
                Failure.Native = Retired.error().Native;
            }
            co_return std::unexpected(std::move(Failure));
        }
        co_return ServerHandover{
            Connection->TakeClientHelloWire(), SharedConn(std::move(Connection))};
    }
}
