/**
 * @file trojan.hpp
 * @brief Trojan 协议处理器
 */

#pragma once

#include <common/Core/Runtime/Adapter/Handler.hpp>
#include <common/Protocols/Trojan/Trojan.hpp>
#include <common/Protocols/Trojan/Dgram.hpp>

namespace Preview::Runtime::Handler
{

    class Trojan final : public ProtocolHandler
    {
    public:
        explicit Trojan(Preview::Trojan::ServerConfig cfg) : cfg_(std::move(cfg)) {}

        auto Accept(Preview::SharedTransmission inbound)
            -> net::awaitable<AcceptResult> override
        {
            auto [err, req, Conn] = co_await Preview::Trojan::Accept(std::move(inbound), cfg_);
            AcceptResult r;
            r.err = err;
            if (err != Preview::Error::none || !Conn) co_return r;
            r.Target.Host = req.Target.Host;
            r.Target.Port = std::to_string(req.Target.Port);
            // identity 留空：Trojan 无客户端标识，禁止把密码写进统计
            if (req.Cmd == Preview::Trojan::Command::UdpAssociate)
            {
                r.IsDgram = true;
                r.Transmission = std::make_shared<Preview::Trojan::Dgram<>>(std::move(Conn));
            }
            else
            {
                r.Transmission = std::move(Conn);
            }
            co_return r;
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "trojan"; }

    private:
        Preview::Trojan::ServerConfig cfg_;
    };

} // namespace Preview::Runtime::Handler
