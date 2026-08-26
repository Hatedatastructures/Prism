/**
 * @file Vmess.hpp
 * @brief VMess 协议处理器
 */

#pragma once

#include <common/Core/Runtime/Adapter/Handler.hpp>
#include <common/Protocols/Vmess/Vmess.hpp>
#include <common/Protocols/Vmess/Dgram.hpp>
#include <common/Core/Runtime/Adapter/Common.hpp>

namespace Preview::Runtime::Handler
{

    class Vmess final : public ProtocolHandler
    {
    public:
        explicit Vmess(Preview::Vmess::ServerConfig cfg) : Cfg_(std::move(cfg)) {}

        auto Accept(Preview::SharedTransmission Inbound)
            -> net::awaitable<AcceptResult> override
        {
            auto [err, msg, Conn] = co_await Preview::Vmess::Accept(std::move(Inbound), Cfg_);
            AcceptResult r;
            r.err = err;
            if (err != Preview::Error::None || !Conn) co_return r;
            r.Target.Host = msg.dst.Host;
            r.Target.Port = std::to_string(msg.dst.Port);
            r.identity = Preview::Runtime::Detail::UuidHex(Cfg_.uuid);
            if (msg.Cmd == Preview::Vmess::CmdUdp)
            {
                r.IsDgram = true;
                r.Transmission = std::make_shared<Preview::Vmess::Dgram<>>(std::move(Conn));
            }
            else
            {
                r.Transmission = std::move(Conn);
            }
            co_return r;
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "vmess"; }

    private:
        Preview::Vmess::ServerConfig Cfg_;
    };

} // namespace Preview::Runtime::Handler
