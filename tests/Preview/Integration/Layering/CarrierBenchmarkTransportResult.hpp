/**
 * @file CarrierBenchmarkTransportResult.hpp
 * @brief 混合 carrier 基准统一的 owning 传输结果。
 */
#pragma once

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Protocols/Restls/Restls.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <expected>
#include <memory>
#include <concepts>
#include <utility>

namespace Preview::Tests::Integration::Layering
{
    using TransportResult =
        std::expected<Preview::SharedTransmission, Preview::Fault::Failure>;

    /** @brief 把既有协议错误码边界一次映射到基准的 typed 失败值。 */
    template <class ConnectionType>
    [[nodiscard]] inline auto ToTransportResult(
        Preview::Error ErrorCode,
        ConnectionType ConnectionValue) -> TransportResult
    {
        if (ErrorCode != Preview::Error::None)
            return std::unexpected(Preview::Fault::FromNative(
                Preview::make_error_code(ErrorCode)));
        if (!ConnectionValue)
            return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::InvalidArgument});
        return Preview::SharedTransmission(std::move(ConnectionValue));
    }

    /** @brief 协议 factory 只做 owning 转换并完整透传首个 typed Failure。 */
    template <class ConnectionType>
    [[nodiscard]] inline auto ToTransportResult(
        std::expected<ConnectionType, Preview::Fault::Failure> Result)
        -> TransportResult
    {
        if (!Result)
            return std::unexpected(Result.error());
        if (!*Result)
            return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::InvalidArgument});
        return Preview::SharedTransmission(std::move(*Result));
    }

    /** @brief 校验并提取 Accept 结果内的正式连接 owner。 */
    template <class Accepted>
        requires requires(Accepted Value) { Value.Connection; }
    [[nodiscard]] inline auto ToTransportResult(
        std::expected<Accepted, Preview::Fault::Failure> Result)
        -> TransportResult
    {
        if (!Result)
            return std::unexpected(Result.error());
        if (!Result->Connection)
            return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::InvalidArgument});
        return Preview::SharedTransmission{std::move(Result->Connection)};
    }

    /** @brief Restls 调用链直接保留其 typed Native cause。 */
    [[nodiscard]] inline auto ToTransportResult(
        Preview::Restls::Result<Preview::Restls::SharedConn> Result)
        -> TransportResult
    {
        if (!Result)
            return std::unexpected(Preview::Restls::ToFaultFailure(Result.error()));
        return Preview::SharedTransmission(std::move(*Result));
    }

    /** @brief 接收 carrier 的 expected 成功拥有值并保留完整 typed failure。 */
    template <class Value>
    [[nodiscard]] inline auto ToTransportResult(
        std::expected<Value, Preview::Fault::Failure> Result) -> TransportResult
    {
        if (!Result) return std::unexpected(Result.error());
        if constexpr (std::convertible_to<Value, Preview::SharedTransmission>)
        {
            return Preview::SharedTransmission(std::move(*Result));
        }
        else if constexpr (requires(Value Owner) { Owner.Connection; })
        {
            return Preview::SharedTransmission(std::move(Result->Connection));
        }
        else
        {
            static_assert(std::convertible_to<Value, Preview::SharedTransmission>,
                          "Carrier factory result must own a Transmission");
        }
    }
}
