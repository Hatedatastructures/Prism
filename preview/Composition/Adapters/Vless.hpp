/**
 * @file Vless.hpp
 * @brief VLESS 协议处理器
 */

#pragma once

#include <preview/Runtime/Contract/Handler.hpp>
#include <preview/Protocols/Vless/Vless.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Composition/Adapters/Common.hpp>

namespace Preview::Runtime::Handler
{

    class Vless final : public ProtocolHandler
    {
    public:
        explicit Vless(Preview::Vless::ServerConfig cfg) : Cfg_(std::move(cfg)) {}

        auto Accept(Preview::SharedTransmission Inbound)
            -> net::awaitable<AcceptResult> override
        {
            auto [err, req, Conn] = co_await Preview::Vless::Accept(std::move(Inbound), Cfg_);
            AcceptResult r;
            r.err = err;
            if (err != Preview::Error::None || !Conn) co_return r;
            r.Target.Host = req.Target.Host;
            r.Target.Port = std::to_string(req.Target.Port);
            r.identity = Preview::Runtime::Detail::UuidHex(req.Uuid);
            r.IsDgram = (req.Cmd == Preview::Vless::Command::Udp);
            r.Transmission = std::move(Conn);
            co_return r;
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "vless"; }

    private:
        Preview::Vless::ServerConfig Cfg_;
    };

} // namespace Preview::Runtime::Handler
