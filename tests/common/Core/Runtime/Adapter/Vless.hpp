/**
 * @file vless.hpp
 * @brief VLESS 协议处理器
 */

#pragma once

#include <common/Core/Runtime/Adapter/Handler.hpp>
#include <common/Protocols/Vless/Vless.hpp>
#include <common/Core/Error.hpp>
#include <common/Core/Runtime/Adapter/Common.hpp>

namespace Preview::Runtime::Handler
{

    class Vless final : public ProtocolHandler
    {
    public:
        explicit Vless(Preview::Vless::ServerConfig cfg) : cfg_(std::move(cfg)) {}

        auto Accept(Preview::SharedTransmission inbound)
            -> net::awaitable<AcceptResult> override
        {
            auto [err, req, Conn] = co_await Preview::Vless::Accept(std::move(inbound), cfg_);
            AcceptResult r;
            r.err = err;
            if (err != Preview::Error::none || !Conn) co_return r;
            r.Target.Host = req.Target.Host;
            r.Target.Port = std::to_string(req.Target.Port);
            r.identity = Preview::Runtime::Detail::UuidHex(req.Uuid);
            r.IsDgram = (req.Cmd == Preview::Vless::Command::Udp);
            r.Transmission = std::move(Conn);
            co_return r;
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "vless"; }

    private:
        Preview::Vless::ServerConfig cfg_;
    };

} // namespace Preview::Runtime::Handler
