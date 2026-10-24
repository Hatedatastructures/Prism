/**
 * @file SessionState.hpp
 * @brief HTTP/2 私有会话状态 owner。
 * @details 本 owner 独占连接接收/发送缓冲、HPACK 状态、stream 表、frame dispatcher
 *          和 SETTINGS/GOAWAY 内部回调。Events 由外层 Session facade 持有。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Protocols/Http2/Detail/FrameProcessor.hpp>
#include <Prism/Protocols/Http2/Detail/CodecState.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http2/Types.hpp>

namespace Prism::Http2::Detail
{

    /**
     * @class SessionState
     * @brief 持有单条 HTTP/2 连接的全部协议状态。
     * @details Events 必须比本 owner 活得更久；外层 Session 将本对象作为成员持有，
     *          并在销毁本对象后才释放事件回调。Settings/Goaway 仅供协议内部处理与测试。
     */
    class SessionState final : public ControlCallbacks
    {
    public:
        SessionState(
            Net::any_io_executor Executor,
            bool IsServer,
            H2Session &Events)
            : Connection_(std::move(Executor), IsServer),
              Streams_(Connection_, Codec_, Events),
              Frames_(ProcessorState{
                  Connection_, Codec_, Streams_, Events, *this})
        {
        }

        [[nodiscard]] auto Feed(
            std::span<const std::byte> Data,
            std::error_code &ErrorCode) -> bool
        {
            return Connection_.Feed(Data, ErrorCode, Frames_);
        }

        [[nodiscard]] auto Collect(std::vector<std::byte> &Output) -> bool
        {
            return Connection_.Collect(Output);
        }

        [[nodiscard]] auto OpenStream(
            const HeaderList &Headers,
            bool EndStream) -> std::expected<std::int32_t, Prism::Fault::Failure>
        {
            return Streams_.OpenStream(Headers, EndStream);
        }

        [[nodiscard]] auto SubmitHeaders(
            std::int32_t StreamId,
            const HeaderList &Headers,
            bool EndStream) -> std::expected<void, Prism::Fault::Failure>
        {
            return Streams_.SubmitHeaders(StreamId, Headers, EndStream);
        }

        [[nodiscard]] auto SubmitData(
            std::int32_t StreamId,
            std::span<const std::byte> Data,
            bool EndStream) -> SubmitDataStatus
        {
            return Streams_.SubmitData(StreamId, Data, EndStream);
        }

        [[nodiscard]] auto AwaitWritable(
            std::int32_t StreamId,
            std::size_t RequiredBytes)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            return Streams_.AwaitWritable(StreamId, RequiredBytes);
        }

        auto ConsumeData(std::int32_t StreamId, std::size_t Bytes) -> void
        {
            Streams_.ConsumeData(StreamId, Bytes);
        }

        [[nodiscard]] auto ResetStream(
            std::int32_t StreamId,
            std::uint32_t ErrorCode) -> std::expected<void, Prism::Fault::Failure>
        {
            return Streams_.ResetStream(StreamId, ErrorCode);
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Connection_.Executor();
        }

        auto SendSettings(std::span<const SettingsEntry> Entries = {}) -> void
        {
            Streams_.SendSettings(Entries);
        }

        auto SendPing(std::span<const std::byte, 8> Opaque) -> void
        {
            Streams_.SendPing(Opaque);
        }

        auto SendGoaway(std::uint32_t LastStreamId, std::uint32_t ErrorCode) -> void
        {
            Streams_.SendGoaway(LastStreamId, ErrorCode);
        }

    private:
        ConnectionState Connection_;
        CodecState Codec_;
        StreamController Streams_;
        FrameProcessor Frames_;
    };

} // namespace Prism::Http2::Detail
