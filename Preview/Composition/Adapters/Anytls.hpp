/**
 * @file Anytls.hpp
 * @brief AnyTLS 协议接入处理器。
 */

#pragma once

#include <string_view>
#include <utility>

#include <Preview/Composition/Adapters/TypedResult.hpp>
#include <Preview/Protocols/Anytls/Anytls.hpp>
#include <Preview/Runtime/Contract/Handler.hpp>

namespace Preview::Runtime::Handler
{

    namespace Net = boost::asio;

    /**
     * @class Anytls
     * @brief AnyTLS 服务端认证与多路复用数据面处理器。
     */
    class Anytls final : public ProtocolHandler
    {
    public:
        explicit Anytls(Preview::Anytls::ServerConfig Config) : Config_(std::move(Config)) {}

        auto Accept(Preview::SharedTransmission Inbound)
            -> Net::awaitable<AcceptResult> override
        {
            AcceptResult Result;
            const auto Raw = Inbound;
            auto [ErrorCode, Connection] =
                co_await Preview::Anytls::Accept(std::move(Inbound), Config_);
            Result.err = ErrorCode;
            if (ErrorCode != Preview::Error::None || !Connection)
            {
                if (Raw)
                {
                    Raw->Close();
                }
                if (Connection)
                {
                    Connection->Close();
                }
                co_return Result;
            }
            Result.ProtocolAuthenticated = true;
            Result.Transmission = std::move(Connection);
            Preview::Composition::Adapters::MaterializeMuxDataPlane(Result);
            co_return Result;
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "anytls"; }

    private:
        Preview::Anytls::ServerConfig Config_;
    };

} // namespace Preview::Runtime::Handler
