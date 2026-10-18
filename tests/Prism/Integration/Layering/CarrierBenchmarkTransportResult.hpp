/**
 * @file CarrierBenchmarkTransportResult.hpp
 * @brief 混合 carrier 基准统一的 owning 传输结果。
 */
#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Restls/Restls.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <expected>
#include <memory>
#include <concepts>
#include <utility>

namespace Prism::Tests::Integration::Layering
{
    using TransportResult =
        std::expected<Prism::SharedTransmission, Prism::Fault::Failure>;

    /** @brief 把既有协议错误码边界一次映射到基准的 typed 失败值。 */
    template <class ConnectionType>
    [[nodiscard]] inline auto ToTransportResult(
        Prism::Error ErrorCode,
        ConnectionType ConnectionValue) -> TransportResult
    {
        if (ErrorCode != Prism::Error::None)
            return std::unexpected(Prism::Fault::FromNative(
                Prism::make_error_code(ErrorCode)));
        if (!ConnectionValue)
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        return Prism::SharedTransmission(std::move(ConnectionValue));
    }

    /** @brief 协议 factory 只做 owning 转换并完整透传首个 typed Failure。 */
    template <class ConnectionType>
    [[nodiscard]] inline auto ToTransportResult(
        std::expected<ConnectionType, Prism::Fault::Failure> Result)
        -> TransportResult
    {
        if (!Result)
            return std::unexpected(Result.error());
        if (!*Result)
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        return Prism::SharedTransmission(std::move(*Result));
    }

    /** @brief 校验并提取 Accept 结果内的正式连接 owner。 */
    template <class Accepted>
        requires requires(Accepted Value) { Value.Connection; }
    [[nodiscard]] inline auto ToTransportResult(
        std::expected<Accepted, Prism::Fault::Failure> Result)
        -> TransportResult
    {
        if (!Result)
            return std::unexpected(Result.error());
        if (!Result->Connection)
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        return Prism::SharedTransmission{std::move(Result->Connection)};
    }

    /** @brief Restls 调用链直接保留其 typed Native cause。 */
    [[nodiscard]] inline auto ToTransportResult(
        Prism::Restls::Result<Prism::Restls::SharedConn> Result)
        -> TransportResult
    {
        if (!Result)
            return std::unexpected(Prism::Restls::ToFaultFailure(Result.error()));
        return Prism::SharedTransmission(std::move(*Result));
    }

    /** @brief 接收 carrier 的 expected 成功拥有值并保留完整 typed failure。 */
    template <class Value>
    [[nodiscard]] inline auto ToTransportResult(
        std::expected<Value, Prism::Fault::Failure> Result) -> TransportResult
    {
        if (!Result) return std::unexpected(Result.error());
        if constexpr (std::convertible_to<Value, Prism::SharedTransmission>)
        {
            return Prism::SharedTransmission(std::move(*Result));
        }
        else if constexpr (requires(Value Owner) { Owner.Connection; })
        {
            return Prism::SharedTransmission(std::move(Result->Connection));
        }
        else
        {
            static_assert(std::convertible_to<Value, Prism::SharedTransmission>,
                          "Carrier factory result must own a Transmission");
        }
    }
}
