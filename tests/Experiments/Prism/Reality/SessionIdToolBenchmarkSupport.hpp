/**
 * @file SessionIdToolBenchmarkSupport.hpp
 * @brief SessionId 实验基准共享的 client/server factory。
 * @details 完整 Reality TLS carrier 不由此实验构造；三组基准使用相同密钥、随机数、短 ID 与 Hello 字节。
 */
#pragma once

#include "SessionIdTool.hpp"

#include "../../../Prism/Integration/Layering/CarrierBenchmarkTransportResult.hpp"

#include <Prism/Protocols/Reality/Detail/KeyMaterial.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string_view>
#include <utility>

namespace Prism::Tests::Experiments::Reality
{
    namespace Net = boost::asio;
    namespace Protocol = Prism::Reality;
    namespace SessionId = Prism::Reality::Detail::Experiments;
    using TransportResult = Prism::Tests::Integration::Layering::TransportResult;
    using Prism::Tests::Integration::Layering::ToTransportResult;

    /** @brief 由调用目标保留各自原有的 keygen 失败处理语义。 */
    using KeyGenerationHandler = std::function<void(Prism::Error, std::string_view)>;

    class SessionIdToolBenchmarkFactory
    {
    public:
        explicit SessionIdToolBenchmarkFactory(KeyGenerationHandler Handler)
        {
            const auto ServerError = Protocol::GenerateKeypair(ServerPrivate_, ServerPublic_);
            if (Handler)
            {
                Handler(ServerError, "Reality server key generation failed");
            }
            const auto ClientError = Protocol::GenerateKeypair(ClientPrivate_, ClientPublic_);
            if (Handler)
            {
                Handler(ClientError, "Reality client key generation failed");
            }
            for (std::size_t Index = 0; Index < Random_.size(); ++Index)
            {
                Random_[Index] = static_cast<std::uint8_t>(Index * 5 + 2);
            }
            for (std::size_t Index = 0; Index < Hello_.size(); ++Index)
            {
                Hello_[Index] = static_cast<std::uint8_t>(Index);
            }
        }

        [[nodiscard]] auto ServerAccept(Prism::SharedTransmission Upstream)
            -> Net::awaitable<TransportResult>
        {
            SessionId::ServerConfig Config;
            Config.private_key = ServerPrivate_;
            Config.ShortIds.emplace_back();
            Config.ShortIds.back().fill(0x42);
            auto [ErrorCode, SessionIdValue, Connection] = co_await SessionId::Accept(
                {std::move(Upstream), Config, ClientPublic_,
                 SessionId::HandshakeParams{Random_, Hello_}});
            (void)SessionIdValue;
            co_return ToTransportResult(ErrorCode, std::move(Connection));
        }

        [[nodiscard]] auto ClientConnect(Prism::SharedTransmission Upstream)
            -> Net::awaitable<TransportResult>
        {
            SessionId::ClientConfig Config;
            Config.private_key = ClientPrivate_;
            Config.ShortId.fill(0x42);
            auto [ErrorCode, Connection] = co_await SessionId::Connect(
                {std::move(Upstream), Config, ServerPublic_,
                 SessionId::HandshakeParams{Random_, Hello_, Config.ShortId}});
            co_return ToTransportResult(ErrorCode, std::move(Connection));
        }

    private:
        std::array<std::uint8_t, Protocol::KeyLen> ServerPrivate_{};
        std::array<std::uint8_t, Protocol::KeyLen> ServerPublic_{};
        std::array<std::uint8_t, Protocol::KeyLen> ClientPrivate_{};
        std::array<std::uint8_t, Protocol::KeyLen> ClientPublic_{};
        std::array<std::uint8_t, 32> Random_{};
        std::array<std::uint8_t, 128> Hello_{};
    };
}
