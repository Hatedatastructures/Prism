/**
 * @file FrameProcessor.hpp
 * @brief HTTP/2 输入帧分发和协议校验 owner。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Protocols/Http2/Detail/ConnectionState.hpp>
#include <Prism/Protocols/Http2/Detail/StreamController.hpp>

namespace Prism::Http2::Detail
{

    class CodecState;

    /** @brief 会话级 SETTINGS/GOAWAY 事件，协议内部 SETTINGS/GOAWAY 事件。 */
    struct ControlCallbacks
    {
        std::function<void(const std::vector<SettingsEntry> &)> OnSettings;
        std::function<void(const GoawayParams &)> OnGoaway;
    };

    struct ProcessorState final
    {
        ConnectionState &Connection;
        CodecState &Codec;
        StreamController &Streams;
        H2Session &Events;
        ControlCallbacks &Controls;
    };

    struct HeaderEvent final
    {
        std::uint32_t StreamId{0};
        bool EndStream{false};
        std::span<const std::byte> Block;
    };

    /** @class FrameProcessor
     *  @brief 把完整帧转换为流事件、控制事件和状态变化。
     */
    class FrameProcessor final
    {
    public:
        explicit FrameProcessor(ProcessorState State);

        /** @brief 在等待载荷前拒绝打断中的 HEADERS/CONTINUATION 序列。 */
        [[nodiscard]] auto ValidateHeaderSequence(
            const FrameHeader &Header,
            std::error_code &ErrorCode) const -> bool;

        [[nodiscard]] auto Dispatch(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool;

    private:
        struct HeaderContinuation
        {
            std::uint32_t StreamId{0};
            bool EndStream{false};
            std::vector<std::byte> Block;
        };

        [[nodiscard]] auto OnDataFrame(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool;

        [[nodiscard]] auto OnHeadersFrame(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool;

        [[nodiscard]] auto OnContinuationFrame(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool;

        [[nodiscard]] auto FinishHeaders(
            const HeaderEvent &Event,
            std::error_code &ErrorCode) -> bool;

        [[nodiscard]] auto OnWindowUpdate(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool;

        [[nodiscard]] auto OnSettingsFrame(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool;

        [[nodiscard]] auto OnPingFrame(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool;

        ConnectionState &Connection_;
        CodecState &Codec_;
        StreamController &Streams_;
        H2Session &Events_;
        ControlCallbacks &Controls_;
        std::optional<HeaderContinuation> PendingHeaders_;
    };

} // namespace Prism::Http2::Detail
