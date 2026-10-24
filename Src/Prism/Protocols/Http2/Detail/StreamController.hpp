/**
 * @file StreamController.hpp
 * @brief HTTP/2 流状态、流控和输出操作 owner。
 */

#pragma once

#include <algorithm>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/cancellation_type.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <set>
#include <span>
#include <system_error>
#include <vector>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <Prism/Protocols/Http2/Detail/ConnectionState.hpp>
#include <Prism/Protocols/Http2/Types.hpp>

namespace Prism::Http2::Detail
{

    class CodecState;

    /**
     * @class StreamController
     * @brief 管理流 ID、半关闭状态、窗口和所有出站帧。
     * @details 输入帧的类型分发仍由 FrameProcessor 完成；本 owner 只提供流
     *          状态变更和对应的出站操作。
     */
    class StreamController final
    {
    public:
        struct StreamState
        {
            bool LocalClosed{false};
            bool RemoteClosed{false};
            std::int64_t SendWindow{DefaultInitialWindow};
            std::uint32_t ReceiveWindow{DefaultInitialWindow};
            std::vector<std::byte> RxPending;
            std::vector<std::weak_ptr<Net::steady_timer>> WritableWaiters;
        };

        StreamController(ConnectionState &Connection, CodecState &Codec, H2Session &Events);

        [[nodiscard]] auto OpenStream(const HeaderList &Headers, bool EndStream)
            -> std::expected<std::int32_t, Prism::Fault::Failure>;

        [[nodiscard]] auto SubmitHeaders(
            const std::int32_t StreamId,
            const HeaderList &Headers,
            const bool EndStream) -> std::expected<void, Prism::Fault::Failure>;

        [[nodiscard]] auto SubmitData(
            const std::int32_t StreamId,
            std::span<const std::byte> Data,
            const bool EndStream) -> SubmitDataStatus;

        [[nodiscard]] auto AwaitWritable(
            const std::int32_t StreamId,
            const std::size_t RequiredBytes)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        auto ConsumeData(const std::int32_t StreamId, const std::size_t Bytes) -> void;

        /** @brief 丢弃已关闭流的迟到 DATA，只恢复连接级窗口，不再引用已退休流窗口。 */
        auto ConsumeClosedStreamData(const std::size_t Bytes) -> void;

        [[nodiscard]] auto ResetStream(
            const std::int32_t StreamId,
            const std::uint32_t ErrorCode) -> std::expected<void, Prism::Fault::Failure>;

        auto SendSettings(std::span<const SettingsEntry> Entries) -> void;

        auto SendPing(std::span<const std::byte, 8> Opaque) -> void;

        auto SendGoaway(const std::uint32_t LastStreamId, const std::uint32_t ErrorCode) -> void;

        [[nodiscard]] auto Find(const std::int32_t StreamId) noexcept -> StreamState *
        {
            const auto Iterator = Streams_.find(StreamId);
            return Iterator == Streams_.end() ? nullptr : &Iterator->second;
        }

        [[nodiscard]] auto Find(const std::int32_t StreamId) const noexcept
            -> const StreamState *
        {
            const auto Iterator = Streams_.find(StreamId);
            return Iterator == Streams_.end() ? nullptr : &Iterator->second;
        }

        /** @brief 查询已完成或已重置的流；压缩与连接流控仍须继续处理迟到帧。 */
        [[nodiscard]] auto IsClosedStream(const std::int32_t StreamId) const noexcept -> bool
        {
            return StreamId > 0 && ClosedStreams_.contains(static_cast<std::uint32_t>(StreamId));
        }

        [[nodiscard]] auto ValidateIncomingStream(
            const std::uint32_t StreamId,
            std::error_code &ErrorCode) const -> bool;

        auto RegisterIncomingStream(const std::uint32_t StreamId) -> void;

        [[nodiscard]] auto ApplyPeerSettings(
            const std::vector<SettingsEntry> &Entries,
            std::error_code &ErrorCode) -> bool;

        [[nodiscard]] auto ApplyStreamWindowUpdate(
            const std::int32_t StreamId,
            const std::uint32_t Increment,
            std::error_code &ErrorCode) -> bool;

        auto OnStreamCloseIf(const std::int32_t StreamId, const std::uint32_t ErrorCode) -> void;

        auto OnRemoteEnd(const std::int32_t StreamId, const std::uint32_t ErrorCode) -> void;

        [[nodiscard]] auto PeerMaxFrameSize() const noexcept -> std::uint32_t
        {
            return PeerMaxFrameSize_;
        }

    public:
        /** @brief connection WINDOW_UPDATE 后重查所有待写 stream。 */
        auto WakeConnectionWaiters() -> void;

    private:
        [[nodiscard]] auto HasSendWindow(
            const StreamState &State,
            const std::size_t RequiredBytes) const noexcept -> bool;

        static auto PruneWaiters(
            std::vector<std::weak_ptr<Net::steady_timer>> &Waiters) -> void;

        static auto WakeWaiters(
            std::vector<std::weak_ptr<Net::steady_timer>> &Waiters) -> void;

        auto RestoreReceiveWindow(
            const std::uint32_t StreamId,
            const std::size_t Bytes,
            std::uint32_t &Window) -> void;

        [[nodiscard]] auto SubmitHeadersFrame(
            const std::int32_t StreamId,
            const HeaderList &Headers,
            const bool EndStream) -> std::expected<void, Prism::Fault::Failure>;

        [[nodiscard]] auto NextClientStreamId()
            -> std::expected<std::int32_t, Prism::Fault::Failure>;

        [[nodiscard]] auto MissingStreamCode(const std::int32_t StreamId) const noexcept
            -> Prism::Fault::Code;

        ConnectionState &Connection_;
        CodecState &Codec_;
        H2Session &Events_;
        std::map<std::int32_t, StreamState> Streams_;
        std::set<std::uint32_t> ClosedStreams_;
        std::vector<std::weak_ptr<Net::steady_timer>> ConnectionWaiters_;
        std::int32_t NextClientId_{1};
        std::uint32_t LastRxStream_{0};
        std::uint32_t PeerInitialWindow_{DefaultInitialWindow};
        std::uint32_t PeerMaxFrameSize_{DefaultFramePayload};
    };

} // namespace Prism::Http2::Detail
