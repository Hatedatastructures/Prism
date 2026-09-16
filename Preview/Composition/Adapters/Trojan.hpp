/**
 * @file Trojan.hpp
 * @brief Trojan 协议处理器
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <Preview/Runtime/Contract/Handler.hpp>
#include <Preview/Composition/Adapters/TypedResult.hpp>
#include <Preview/Protocols/Trojan/Trojan.hpp>
#include <Preview/Protocols/Trojan/Dgram.hpp>

namespace Preview::Runtime::Handler
{

    namespace Net = boost::asio;

    class Trojan final : public ProtocolHandler
    {
    public:
        explicit Trojan(Preview::Trojan::ServerConfig cfg) : Cfg_(std::move(cfg)) {}

        auto Accept(Preview::SharedTransmission Inbound)
            -> Net::awaitable<AcceptResult> override
        {
            auto [err, req, Conn] = co_await Preview::Trojan::Accept(std::move(Inbound), Cfg_);
            AcceptResult r;
            r.err = err;
            if (err != Preview::Error::None || !Conn) co_return r;
            r.Target.Host = req.Target.Host;
            r.Target.Port = std::to_string(req.Target.Port);
            r.ProtocolAuthenticated = true;
            r.AccountId = Conn->AccountId();
            r.identity = std::string(Conn->Identity());
            r.AccountLease = Conn->TakeAuthLease();
            r.AccountLeaseRequired = static_cast<bool>(r.AccountLease);
            if (req.Cmd == Preview::Trojan::Command::Mux)
            {
                r.Transmission = std::move(Conn);
                Preview::Composition::Adapters::MaterializeMuxDataPlane(r);
            }
            else if (req.Cmd == Preview::Trojan::Command::UdpAssociate)
            {
                r.IsDgram = true;
                r.Transmission = std::make_shared<Preview::Trojan::Dgram<>>(std::move(Conn));
            }
            else
            {
                r.Transmission = std::move(Conn);
            }
            if (req.Cmd != Preview::Trojan::Command::Mux)
            {
                Preview::Composition::Adapters::MaterializeTypedDataPlane(r, r.IsDgram);
            }
            if (!Preview::Composition::Adapters::EnforceProtocolAuthentication(r))
            {
                co_return r;
            }
            co_return r;
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "trojan"; }

    private:
        Preview::Trojan::ServerConfig Cfg_;
    };

} // namespace Preview::Runtime::Handler
