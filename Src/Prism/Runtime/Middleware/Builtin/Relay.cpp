/** @file Relay.cpp @brief 管线可靠 relay 的 Runtime 包装实现。 */
#include <Prism/Runtime/Middleware/Builtin/Relay.hpp>

#include <Prism/Foundation/Utility/TrafficSink.hpp>

#include <cstdint>

namespace Prism::Middleware::Builtin
{
    auto RelayMiddleware::Handle(Prism::SharedTransmission& Inbound, Context& ContextValue)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        auto Outbound = ContextValue.Outbound;
        if (!Outbound) Outbound = Outbound_;
        auto Timeout = IdleTimeout_;
        if (ContextValue.Timeout.count() > 0) Timeout = ContextValue.Timeout;
        Prism::Foundation::TrafficObservation Observation{
            ContextValue.Traffic,
            Prism::Foundation::TrafficEvent{
                .Generation = ContextValue.TaskIdentity.Generation,
                .Worker = ContextValue.TaskIdentity.WorkerId,
                .Session = ContextValue.TaskIdentity.SessionId,
                .Stream = ContextValue.TaskIdentity.StreamId,
                .Task = ContextValue.TaskIdentity.TaskId,
                .Account = ContextValue.DataPlane.AccountId,
                .Protocol = static_cast<std::uint64_t>(ContextValue.DataPlane.Protocol)}};
        Last_ = co_await Prism::Network::Relay::Run(
            {Inbound, Outbound, ContextValue.BufferSize, Timeout, Observation,
             ContextValue.Bytes, ContextValue.FirstTransfer});
        Observation.Complete(Last_.Failure);
        co_return Last_.Failure;
    }
}
