/**
 * @file Ss2022.hpp
 * @brief Shadowsocks2022 协议处理器
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <Preview/Runtime/Contract/Handler.hpp>
#include <Preview/Composition/Adapters/TypedResult.hpp>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>

namespace Preview::Runtime::Handler
{

    namespace Net = boost::asio;

    class Ss2022 final : public ProtocolHandler
    {
    public:
        explicit Ss2022(Preview::Shadowsocks2022::ServerConfig cfg) : Cfg_(std::move(cfg)) {}

        Ss2022(Preview::Shadowsocks2022::ServerConfig cfg,
               std::shared_ptr<const Preview::Account::AccountDirectory> Directory)
            : Cfg_(std::move(cfg)), Directory_(std::move(Directory))
        {
            if (Directory_)
            {
                Cfg_.AuthenticatorOwner =
                    std::make_shared<Preview::Account::ProtocolAuthenticator>(Directory_);
                Cfg_.Authenticator = nullptr;
            }
        }

        auto Accept(Preview::SharedTransmission Inbound)
            -> Net::awaitable<AcceptResult> override
        {
            if (!Directory_)
            {
                auto [Err, Message, Connection] =
                    co_await Preview::Shadowsocks2022::Accept(std::move(Inbound), Cfg_);
                co_return Complete(
                    ProtocolResult{Err, std::move(Message), std::move(Connection)});
            }

            auto Replay = std::make_shared<Preview::Runtime::Detail::ReplayTransmission>(
                std::move(Inbound));
            Replay->EnableWrites();
            const auto Records = Preview::Runtime::Detail::RecordsForCredential(
                Directory_, Preview::Account::CredentialKind::Psk);
            for (const auto &Record : Records)
            {
                const auto Psk = Preview::Runtime::Detail::CopyPsk(Record->Credential());
                if (!Psk)
                {
                    continue;
                }
                auto Candidate = Cfg_;
                Candidate.UsePsk = true;
                Candidate.Psk = *Psk;
                auto [Err, Message, Connection] =
                    co_await Preview::Shadowsocks2022::Accept(Replay, Candidate);
                if (Err != Preview::Error::None || !Connection)
                {
                    Replay->ResetForRetry();
                    continue;
                }
                Replay->Commit();
                co_return Complete(
                    ProtocolResult{Err, std::move(Message), std::move(Connection)});
            }
            Replay->CloseUnderlying();
            AcceptResult Result;
            Result.err = Preview::Error::BadAuth;
            co_return Result;
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "ss2022"; }

    private:
        struct ProtocolResult
        {
            Preview::Error Err{Preview::Error::IoError};
            Preview::Shadowsocks2022::Message Message;
            Preview::Shadowsocks2022::SharedConn Connection;
        };

        [[nodiscard]] auto Complete(ProtocolResult Value) const -> AcceptResult
        {
            AcceptResult Result;
            Result.err = Value.Err;
            if (Value.Err != Preview::Error::None || !Value.Connection)
            {
                return Result;
            }
            Result.Target.Host = Value.Message.dst.Host;
            Result.Target.Port = std::to_string(Value.Message.dst.Port);
            Result.ProtocolAuthenticated = true;
            Result.AccountId = Value.Connection->AccountId();
            Result.identity = std::string(Value.Connection->Identity());
            Result.AccountLease = Value.Connection->TakeAuthLease();
            Result.AccountLeaseRequired = static_cast<bool>(Result.AccountLease);
            Result.Transmission = std::move(Value.Connection);
            Preview::Composition::Adapters::MaterializeTypedDataPlane(Result, false);
            if (!Preview::Composition::Adapters::EnforceProtocolAuthentication(Result))
            {
                return Result;
            }
            return Result;
        }

        Preview::Shadowsocks2022::ServerConfig Cfg_;
        std::shared_ptr<const Preview::Account::AccountDirectory> Directory_;
    };

} // namespace Preview::Runtime::Handler
