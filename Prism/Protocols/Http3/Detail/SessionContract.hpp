/**
 * @file SessionContract.hpp
 * @brief HTTP/3 frame会话的公开数据和生命周期契约。
 * @details 这里只声明 transport-neutral 的会话边界；具体状态转换由
 *          Session.hpp 聚合的职责头提供。
 */

#pragma once

#include <algorithm>
#include <atomic>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Protocols/Http3/Auth.hpp>
#include <Prism/Protocols/Http3/HeaderLimits.hpp>

namespace Prism::Http3::Detail
{

    /** @brief nghttp3 输出数据、目标流和流结束标记。 */
    struct OutPacket final
    {
        std::int64_t StreamId{0};
        Prism::Memory::Vector<std::byte> Data;
        bool Fin{false};

        explicit OutPacket(Prism::Memory::ResourcePointer Resource)
            : Data(Prism::Memory::EffectiveMr(Resource))
        {
        }
    };

    /**
     * @class Session
     * @brief 单条 HTTP/3 连接的 nghttp3 frame/QPACK 状态机。
     * @details nghttp3 的调用由上层串行安排；本类型只产生通用请求、数据和
     *          重置事件，不包含协议认证或应用层策略。
     */
    class Session final
    {
    public:
        explicit Session(Prism::Memory::ResourcePointer Resource = nullptr)
            : Resource_(Prism::Memory::EffectiveMr(Resource))
        {
        }

        ~Session() noexcept
        {
            Close();
        }

        Session(const Session &) = delete;
        auto operator=(const Session &) -> Session & = delete;

        [[nodiscard]] auto Init(std::function<std::int64_t()> OpenUniStream) -> bool;

        [[nodiscard]] auto Feed(
            std::int64_t StreamId,
            std::span<const std::byte> Data,
            bool Fin) -> Fault::Code;

        [[nodiscard]] auto Feed(
            std::int64_t StreamId,
            std::vector<std::byte> Data,
            bool Fin) -> Fault::Code;

        [[nodiscard]] auto TakeEvent() -> std::optional<ServerEvent>
        {
            if (Events_.empty())
            {
                return std::nullopt;
            }
            auto Event = std::move(Events_.front());
            Events_.pop_front();
            const auto EventBytes = OwnedEventBytes(Event);
            if (EventBytes <= PendingEventBytes_)
            {
                PendingEventBytes_ -= EventBytes;
            }
            return Event;
        }

        [[nodiscard]] auto PumpOutput(std::vector<OutPacket> &Output) -> bool;

        auto AddWriteOffset(std::int64_t StreamId, std::size_t Written) -> void;

        [[nodiscard]] auto SubmitResponse(ResponseHead Response) -> Fault::Code;

        auto Close() noexcept -> void;

        [[nodiscard]] auto IsOpen() const noexcept -> bool
        {
            return OpenAtomic_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Native() const noexcept -> nghttp3_conn *
        {
            return Conn_;
        }

    private:
        template <class EventValue>
        [[nodiscard]] static auto OwnedBytes(const EventValue &Value) noexcept -> std::size_t
        {
            if constexpr (requires { Value.Head.Headers.ReservedBytes(); })
            {
                return Value.Head.Headers.ByteSize();
            }
            else if constexpr (requires { Value.Data.size(); })
            {
                return Value.Data.size();
            }
            return 0;
        }

        [[nodiscard]] static auto OwnedEventBytes(const ServerEvent &Event) noexcept -> std::size_t
        {
            return std::visit([](const auto &Value) noexcept { return OwnedBytes(Value); }, Event);
        }

        [[nodiscard]] auto CanQueueEvent(const std::size_t Bytes) const noexcept -> bool
        {
            return Events_.size() < HeaderLimits::MaxPendingEvents &&
                   Bytes <= HeaderLimits::MaxPendingEventBytes - PendingEventBytes_;
        }

        [[nodiscard]] auto TryQueueEvent(ServerEvent Event) noexcept -> bool
        {
            const auto Bytes = OwnedEventBytes(Event);
            if (!CanQueueEvent(Bytes))
            {
                return false;
            }
            try
            {
                Events_.push_back(std::move(Event));
            }
            catch (...)
            {
                return false;
            }
            PendingEventBytes_ += Bytes;
            return true;
        }

        struct PendingResponse final
        {
            HeaderBlock Headers;
            bool Fin{false};

            PendingResponse(HeaderBlock HeadersValue, bool FinValue)
                : Headers(std::move(HeadersValue)), Fin(FinValue)
            {
            }

            PendingResponse(const PendingResponse &) = delete;
            auto operator=(const PendingResponse &) -> PendingResponse & = delete;
            PendingResponse(PendingResponse &&) noexcept = default;
            auto operator=(PendingResponse &&) noexcept -> PendingResponse & = delete;
        };

        static auto CbBeginHeaders(
            nghttp3_conn *,
            std::int64_t StreamId,
            void *UserData,
            void *) -> int;
        static auto CbRecvHeader(
            nghttp3_conn *,
            std::int64_t StreamId,
            std::int32_t,
            nghttp3_rcbuf *Name,
            nghttp3_rcbuf *Value,
            std::uint8_t,
            void *UserData,
            void *) -> int;
        static auto CbEndHeaders(
            nghttp3_conn *,
            std::int64_t StreamId,
            int Fin,
            void *UserData,
            void *) -> int;
        static auto CbRecvData(
            nghttp3_conn *,
            std::int64_t StreamId,
            const std::uint8_t *Data,
            std::size_t Length,
            void *UserData,
            void *) -> int;
        static auto CbStopSending(
            nghttp3_conn *,
            std::int64_t StreamId,
            std::uint64_t,
            void *UserData,
            void *) -> int;
        static auto CbEndStream(
            nghttp3_conn *,
            std::int64_t StreamId,
            void *UserData,
            void *) -> int;
        static auto CbRand(std::uint8_t *Destination, std::size_t Length) -> void;
        static auto ReadResponseBody(
            nghttp3_conn *,
            std::int64_t,
            nghttp3_vec *,
            std::size_t,
            std::uint32_t *Flags,
            void *,
            void *) -> nghttp3_ssize;

        [[nodiscard]] static auto NowTstamp() -> std::uint64_t
        {
            return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                                    std::chrono::steady_clock::now().time_since_epoch())
                                                    .count());
        }

        [[nodiscard]] static auto RcbufView(nghttp3_rcbuf *Buffer) -> std::string_view
        {
            if (!Buffer)
            {
                return {};
            }
            const auto Value = nghttp3_rcbuf_get_buf(Buffer);
            return {reinterpret_cast<const char *>(Value.base), Value.len};
        }

        [[nodiscard]] auto SubmitResponseHeaders(
            std::int64_t StreamId,
            std::uint16_t Status,
            const PendingResponse &Response) -> Fault::Code;

        nghttp3_conn *Conn_{nullptr};
        std::atomic<bool> OpenAtomic_{false};
        Prism::Memory::ResourcePointer Resource_{};
        std::int64_t ControlStream_{-1};
        std::int64_t EncoderStream_{-1};
        std::int64_t DecoderStream_{-1};
        std::unordered_map<std::int64_t, HeaderBlock> IncomingHeaders_;
        std::unordered_set<std::int64_t> HeaderFinStreams_;
        std::deque<ServerEvent> Events_;
        std::size_t PendingEventBytes_{0};
        std::unordered_map<std::int64_t, PendingResponse> Responses_;
        bool PendingOutput_{false};
        std::int64_t PendingStream_{-1};
        std::size_t PendingBytes_{0};
        bool PendingFin_{false};
        inline static thread_local Session *ActiveRandomOwner_{nullptr};
        std::vector<std::byte> ActiveData_;
        const std::byte *ActiveDataPointer_{nullptr};
    };

} // namespace Prism::Http3::Detail
