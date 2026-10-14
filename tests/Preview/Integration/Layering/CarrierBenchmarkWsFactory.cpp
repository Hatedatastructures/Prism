/**
 * @file CarrierBenchmarkWsFactory.cpp
 * @brief Layering 基准 WebSocket 客户端与服务端工厂绑定实现。
 */
#include "CarrierBenchmarkWsFactory.hpp"
#include "../../protocols/Ws/WsFactorySupport.hpp"

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Protocols/Ws/Ws.hpp>

#include <utility>

namespace Preview::Tests::Integration::Layering
{
    namespace WebSocket = Preview::Ws;

    auto CarrierBenchmarkWsFactory::ClientConnect(Preview::SharedTransmission Upstream) const
        -> Net::awaitable<TransportResult>
    {
        auto Connected = co_await WebSocket::Connect(
            Preview::Tests::WsFactorySupport::MakeConnectOptionsForTest(
                std::move(Upstream), WebSocket::ClientOptions{"example.com"}));
        if (!Connected)
        {
            co_return std::unexpected(Connected.error());
        }
        if (!Connected->Connection)
        {
            co_return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::InvalidArgument});
        }
        co_return Preview::SharedTransmission(std::move(Connected->Connection));
    }

    auto CarrierBenchmarkWsFactory::ServerAccept(Preview::SharedTransmission Upstream) const
        -> Net::awaitable<TransportResult>
    {
        auto Accepted = co_await WebSocket::Accept(
            Preview::Tests::WsFactorySupport::MakeAcceptOptionsForTest(
                std::move(Upstream), WebSocket::ServerOptions{}));
        if (!Accepted)
        {
            co_return std::unexpected(Accepted.error());
        }
        if (!Accepted->Connection)
        {
            co_return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::InvalidArgument});
        }
        co_return Preview::SharedTransmission(std::move(Accepted->Connection));
    }
} // namespace Preview::Tests::Integration::Layering
