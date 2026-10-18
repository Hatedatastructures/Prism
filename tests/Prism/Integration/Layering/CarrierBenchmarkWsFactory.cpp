/**
 * @file CarrierBenchmarkWsFactory.cpp
 * @brief Layering 基准 WebSocket 客户端与服务端工厂绑定实现。
 */
#include "CarrierBenchmarkWsFactory.hpp"
#include "../../Protocols/Ws/WsFactorySupport.hpp"

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Ws/Ws.hpp>

#include <utility>

namespace Prism::Tests::Integration::Layering
{
    namespace WebSocket = Prism::Ws;

    auto CarrierBenchmarkWsFactory::ClientConnect(Prism::SharedTransmission Upstream) const
        -> Net::awaitable<TransportResult>
    {
        auto Connected = co_await WebSocket::Connect(
            Prism::Tests::WsFactorySupport::MakeConnectOptionsForTest(
                std::move(Upstream), WebSocket::ClientOptions{"example.com"}));
        if (!Connected)
        {
            co_return std::unexpected(Connected.error());
        }
        if (!Connected->Connection)
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        co_return Prism::SharedTransmission(std::move(Connected->Connection));
    }

    auto CarrierBenchmarkWsFactory::ServerAccept(Prism::SharedTransmission Upstream) const
        -> Net::awaitable<TransportResult>
    {
        auto Accepted = co_await WebSocket::Accept(
            Prism::Tests::WsFactorySupport::MakeAcceptOptionsForTest(
                std::move(Upstream), WebSocket::ServerOptions{}));
        if (!Accepted)
        {
            co_return std::unexpected(Accepted.error());
        }
        if (!Accepted->Connection)
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        co_return Prism::SharedTransmission(std::move(Accepted->Connection));
    }
} // namespace Prism::Tests::Integration::Layering
