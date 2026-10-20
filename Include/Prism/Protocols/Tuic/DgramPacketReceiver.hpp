/**
 * @file DgramPacketReceiver.hpp
 * @brief 读取并解析 TUIC UDP 关联的单个 packet 帧。
 * @details 同一接收 owner 支持底层 datagram 边界与 stream 帧边界；分片重组仍由 Dgram 持有。
 */
#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Common/Address.hpp>
#include <Prism/Protocols/Tuic/Codec.hpp>
#include <Prism/Protocols/Tuic/Types.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <span>

namespace Prism::Tuic::Detail
{
    namespace Net = boost::asio;

    /**
     * @class DgramPacketReceiver
     * @brief 将一个底层 datagram 或 stream frame 解析为 TUIC packet。
     * @details 只持有接收所需的底层传输引用；分片状态、输出和最终关闭由 Dgram owner 管理。
     */
    class DgramPacketReceiver final
    {
    public:
        using Packet = std::expected<Message, Error>;

        struct ReceiveResult final
        {
            Packet Value;
            std::optional<Prism::Fault::Failure> TerminalAfter{}; ///< 同读终态；截断时由关联 owner 锁存。
        };

        explicit DgramPacketReceiver(SharedTransmission Upstream);

        /** @brief 按底层传输边界读取并解析一个 packet。 */
        [[nodiscard]] auto Receive() -> Net::awaitable<ReceiveResult>;

    private:
        [[nodiscard]] auto ReceiveDatagram() -> Net::awaitable<ReceiveResult>;

        [[nodiscard]] auto ReceiveStreamFrame() -> Net::awaitable<ReceiveResult>;

        [[nodiscard]] auto ReadAddress(
            Message &Parsed,
            std::optional<Prism::Fault::Failure> &Terminal) -> Net::awaitable<Error>;

        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Dst)
            -> Net::awaitable<Prism::IoResult>;

        [[nodiscard]] auto ReadAddressBody(
            Address &AddressValue,
            std::optional<Prism::Fault::Failure> &ReadFailure) -> Net::awaitable<Error>;

        [[nodiscard]] static auto ReadFailureToError(
            const Prism::IoResult &ReadResult) noexcept -> Error;

        [[nodiscard]] static auto ReadFailureToError(
            const Prism::Fault::Failure &Failure) noexcept -> Error;

        SharedTransmission Upstream_;
        std::optional<Prism::Fault::Failure> PendingTerminal_{}; ///< 当前 stream frame 的 sticky 读取终态。
    };
} // namespace Prism::Tuic::Detail
