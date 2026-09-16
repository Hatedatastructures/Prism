/**
 * @file Vless.hpp
 * @brief VLESS 协议处理器
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <Preview/Runtime/Contract/Handler.hpp>
#include <Preview/Composition/Adapters/TypedResult.hpp>
#include <Preview/Composition/Adapters/Common.hpp>
#include <Preview/Protocols/Vless/Vless.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Composition/Adapters/Common.hpp>

namespace Preview::Runtime::Handler
{

    namespace Net = boost::asio;

    class Vless final : public ProtocolHandler
    {
    public:
        explicit Vless(Preview::Vless::ServerConfig cfg) : Cfg_(std::move(cfg)) {}

        auto Accept(Preview::SharedTransmission Inbound)
            -> Net::awaitable<AcceptResult> override
        {
            auto [err, req, Conn] = co_await Preview::Vless::Accept(std::move(Inbound), Cfg_);
            AcceptResult r;
            r.err = err;
            if (err != Preview::Error::None || !Conn) co_return r;
            r.Target.Host = req.Target.Host;
            r.Target.Port = std::to_string(req.Target.Port);
            r.AccountId = Conn->AccountId();
            r.identity = std::string(Conn->Identity());
            if (r.identity.empty())
            {
                r.identity = Preview::Runtime::Detail::HexIdentity(req.Uuid);
            }
            r.ProtocolAuthenticated = true;
            r.AccountLease = Conn->TakeAuthLease();
            r.AccountLeaseRequired = static_cast<bool>(r.AccountLease);
            r.Transmission = std::move(Conn);
            if (req.Cmd == Preview::Vless::Command::Mux)
            {
                Preview::Composition::Adapters::MaterializeMuxDataPlane(r);
            }
            else
            {
                r.IsDgram = (req.Cmd == Preview::Vless::Command::Udp);
                Preview::Composition::Adapters::MaterializeTypedDataPlane(r, r.IsDgram);
            }
            if (!Preview::Composition::Adapters::EnforceProtocolAuthentication(r))
            {
                co_return r;
            }
            co_return r;
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "vless"; }

    private:
        Preview::Vless::ServerConfig Cfg_;
    };

} // namespace Preview::Runtime::Handler
