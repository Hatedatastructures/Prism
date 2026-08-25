/**
 * @file ss2022.hpp
 * @brief Shadowsocks2022 协议处理器
 */

#pragma once

#include <common/Core/Runtime/Adapter/Handler.hpp>
#include <common/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>

namespace Preview::Runtime::Handler
{

    class Ss2022 final : public ProtocolHandler
    {
    public:
        explicit Ss2022(Preview::Shadowsocks2022::ServerConfig cfg) : cfg_(std::move(cfg)) {}

        auto Accept(Preview::SharedTransmission inbound)
            -> net::awaitable<AcceptResult> override
        {
            auto [err, msg, Conn] = co_await Preview::Shadowsocks2022::Accept(std::move(inbound), cfg_);
            AcceptResult r;
            r.err = err;
            if (err != Preview::Error::none || !Conn) co_return r;
            r.Target.Host = msg.dst.Host;
            r.Target.Port = std::to_string(msg.dst.Port);
            // identity 留空：SS2022 无客户端标识，禁止把密码写进统计
            r.Transmission = std::move(Conn);
            co_return r;
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "ss2022"; }

    private:
        Preview::Shadowsocks2022::ServerConfig cfg_;
    };

} // namespace Preview::Runtime::Handler
