/**
 * @file vmess.hpp
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
        explicit Vmess(Preview::Vmess::ServerConfig cfg) : cfg_(std::move(cfg)) {}

        auto Accept(Preview::SharedTransmission inbound)
            -> net::awaitable<AcceptResult> override
        {
            auto [err, msg, Conn] = co_await Preview::Vmess::Accept(std::move(inbound), cfg_);
            AcceptResult r;
            r.err = err;
            if (err != Preview::Error::none || !Conn) co_return r;
            r.Target.Host = msg.dst.Host;
            r.Target.Port = std::to_string(msg.dst.Port);
            r.identity = Preview::Runtime::Detail::UuidHex(cfg_.uuid);
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
        Preview::Vmess::ServerConfig cfg_;
    };

} // namespace Preview::Runtime::Handler
