/**
 * @file Vmess.hpp
 * @brief VMess 协议处理器
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <Preview/Runtime/Contract/Handler.hpp>
#include <Preview/Composition/Adapters/TypedResult.hpp>
#include <Preview/Protocols/Vmess/Vmess.hpp>
#include <Preview/Protocols/Vmess/Dgram.hpp>
#include <Preview/Composition/Adapters/Common.hpp>

namespace Preview::Runtime::Handler
{

    namespace Net = boost::asio;

    class Vmess final : public ProtocolHandler
    {
    public:
        explicit Vmess(Preview::Vmess::ServerConfig cfg) : Cfg_(std::move(cfg)) {}

        Vmess(Preview::Vmess::ServerConfig cfg,
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
                    co_await Preview::Vmess::Accept(std::move(Inbound), Cfg_);
                co_return Complete(ProtocolResult{Err, std::move(Message), std::move(Connection)});
            }

            auto Replay = std::make_shared<Preview::Runtime::Detail::ReplayTransmission>(
                std::move(Inbound));
            Replay->EnableWrites();
            const auto Records = Preview::Runtime::Detail::RecordsForCredential(
                Directory_, Preview::Account::CredentialKind::Uuid);
            for (const auto &Record : Records)
            {
                const auto Uuid = Preview::Runtime::Detail::CopyUuid(Record->Credential());
                if (!Uuid)
                {
                    continue;
                }
                auto Candidate = Cfg_;
                Candidate.uuid = *Uuid;
                auto [Err, Message, Connection] =
                    co_await Preview::Vmess::Accept(Replay, Candidate);
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

        [[nodiscard]] auto Name() const -> std::string_view override { return "vmess"; }

    private:
        struct ProtocolResult
        {
            Preview::Error Err{Preview::Error::IoError};
            Preview::Vmess::Message Message;
            Preview::Vmess::SharedConn Connection;
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
            Result.AccountId = Value.Connection->AccountId();
            Result.identity = std::string(Value.Connection->Identity());
            if (Result.identity.empty())
            {
                Result.identity = Preview::Runtime::Detail::HexIdentity(Value.Message.uuid);
            }
            Result.ProtocolAuthenticated = true;
            Result.AccountLease = Value.Connection->TakeAuthLease();
            Result.AccountLeaseRequired = static_cast<bool>(Result.AccountLease);
            if (Value.Message.Cmd == Preview::Vmess::CmdMux)
            {
                Result.Transmission = std::move(Value.Connection);
                Preview::Composition::Adapters::MaterializeMuxDataPlane(Result);
            }
            else if (Value.Message.Cmd == Preview::Vmess::CmdUdp)
            {
                Result.IsDgram = true;
                Result.Transmission = std::make_shared<Preview::Vmess::Dgram<>>(
                    std::move(Value.Connection));
            }
            else
            {
                Result.Transmission = std::move(Value.Connection);
            }
            if (Value.Message.Cmd != Preview::Vmess::CmdMux)
            {
                Preview::Composition::Adapters::MaterializeTypedDataPlane(Result, Result.IsDgram);
            }
            if (!Preview::Composition::Adapters::EnforceProtocolAuthentication(Result))
            {
                return Result;
            }
            return Result;
        }

        Preview::Vmess::ServerConfig Cfg_;
        std::shared_ptr<const Preview::Account::AccountDirectory> Directory_;
    };

} // namespace Preview::Runtime::Handler
