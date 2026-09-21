/**
 * @file Trusttunnel.hpp
 * @brief TrustTunnel 已完成 HTTP/2 carrier 后的协议接入处理器。
 */

#pragma once

#include <Preview/Composition/Adapters/TypedResult.hpp>
#include <Preview/Protocols/Trusttunnel/Http2.hpp>
#include <Preview/Runtime/Contract/Handler.hpp>

#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace Preview::Runtime::Handler
{

    namespace Net = boost::asio;

    class Trusttunnel final : public ProtocolHandler
    {
    public:
        auto Accept(Preview::SharedTransmission Inbound)
            -> Net::awaitable<AcceptResult> override
        {
            AcceptResult Result;
            const auto Transport = std::dynamic_pointer_cast<Preview::Trusttunnel::Http2Transport>(
                Inbound);
            if (!Transport)
            {
                Result.err = Preview::Error::ProtocolError;
                co_return Result;
            }
            const auto Target = ParseAuthority(Transport->Authority());
            if (!Target)
            {
                Result.err = Preview::Error::BadMessage;
                co_return Result;
            }
            Result.err = Preview::Error::None;
            Result.Target.Host = Target->Host;
            Result.Target.Port = std::to_string(Target->Port);
            Result.ProtocolAuthenticated = true;
            Result.Transmission = std::move(Inbound);
            Preview::Composition::Adapters::MaterializeTypedDataPlane(Result, false);
            co_return Result;
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "trusttunnel"; }

    private:
        struct Authority final
        {
            std::string Host;
            std::uint16_t Port{0};
        };

        [[nodiscard]] static auto ParseAuthority(const std::string_view Value)
            -> std::optional<Authority>
        {
            if (Value.empty())
            {
                return std::nullopt;
            }
            std::string_view Host;
            std::string_view PortText;
            if (Value.front() == '[')
            {
                const auto Close = Value.find(']');
                if (Close == std::string_view::npos || Close + 2U > Value.size() ||
                    Value[Close + 1U] != ':')
                {
                    return std::nullopt;
                }
                Host = Value.substr(1U, Close - 1U);
                PortText = Value.substr(Close + 2U);
            }
            else
            {
                const auto Colon = Value.rfind(':');
                if (Colon == std::string_view::npos || Value.find(':') != Colon)
                {
                    return std::nullopt;
                }
                Host = Value.substr(0, Colon);
                PortText = Value.substr(Colon + 1U);
            }
            std::uint32_t Port = 0;
            const auto [End, Error] = std::from_chars(
                PortText.data(), PortText.data() + PortText.size(), Port);
            if (Host.empty() || Port == 0U || Port > 65535U || Error != std::errc{} ||
                End != PortText.data() + PortText.size())
            {
                return std::nullopt;
            }
            return Authority{std::string(Host), static_cast<std::uint16_t>(Port)};
        }
    };

} // namespace Preview::Runtime::Handler
