/**
 * @file SessionCallbacks.cpp
 * @brief HTTP/3 nghttp3 回调到通用事件的转换职责。
 */


#include <Prism/Protocols/Http3/Detail/SessionContract.hpp>
#include <Prism/Protocols/Http3/HeaderLimits.hpp>

#include <algorithm>
#include <utility>
#include <variant>

namespace Prism::Http3::Detail
{

    [[nodiscard]] auto Session::OwnedEventBytes(const ServerEvent &Event) noexcept -> std::size_t
    {
        return std::visit([](const auto &Value) noexcept { return OwnedBytes(Value); }, Event);
    }

    [[nodiscard]] auto Session::CanQueueEvent(const std::size_t Bytes) const noexcept -> bool
    {
        return Events_.size() < HeaderLimits::MaxPendingEvents &&
               Bytes <= HeaderLimits::MaxPendingEventBytes - PendingEventBytes_;
    }

    [[nodiscard]] auto Session::TryQueueEvent(ServerEvent Event) noexcept -> bool
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

    [[nodiscard]] auto Session::RcbufView(nghttp3_rcbuf *Buffer) -> std::string_view
    {
        if (!Buffer)
        {
            return {};
        }
        const auto Value = nghttp3_rcbuf_get_buf(Buffer);
        return {reinterpret_cast<const char *>(Value.base), Value.len};
    }

    auto Session::CbBeginHeaders(
        nghttp3_conn *,
        const std::int64_t StreamId,
        void *UserData,
        void *) -> int
    {
        auto *Self = static_cast<Session *>(UserData);
        if (!Self)
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        const auto Existing = Self->IncomingHeaders_.find(StreamId);
        if (Existing != Self->IncomingHeaders_.end())
        {
            Self->IncomingHeaders_.erase(Existing);
        }
        if (Self->IncomingHeaders_.size() >= HeaderLimits::MaxConcurrentSections)
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        try
        {
            Self->IncomingHeaders_.emplace(
                StreamId, HeaderBlock(std::make_shared<Prism::Memory::SessionResource<>>()));
            return 0;
        }
        catch (...)
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
    }

    auto Session::CbRecvHeader(
        nghttp3_conn *,
        const std::int64_t StreamId,
        std::int32_t,
        nghttp3_rcbuf *Name,
        nghttp3_rcbuf *Value,
        std::uint8_t,
        void *UserData,
        void *) -> int
    {
        auto *Self = static_cast<Session *>(UserData);
        if (!Self)
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        const auto It = Self->IncomingHeaders_.find(StreamId);
        if (It == Self->IncomingHeaders_.end())
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        const auto NameView = RcbufView(Name);
        const auto ValueView = RcbufView(Value);
        const auto Appended = It->second.TryAppend(NameView, ValueView);
        if (!Appended)
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    auto Session::CbEndHeaders(
        nghttp3_conn *,
        const std::int64_t StreamId,
        const int Fin,
        void *UserData,
        void *) -> int
    {
        auto *Self = static_cast<Session *>(UserData);
        if (!Self)
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        const auto It = Self->IncomingHeaders_.find(StreamId);
        if (It == Self->IncomingHeaders_.end())
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        const auto IsFin = Fin != 0;
        if (IsFin)
        {
            if (Self->HeaderFinStreams_.size() >= HeaderLimits::MaxPendingEvents)
            {
                return NGHTTP3_ERR_CALLBACK_FAILURE;
            }
            try
            {
                Self->HeaderFinStreams_.insert(StreamId);
            }
            catch (...)
            {
                return NGHTTP3_ERR_CALLBACK_FAILURE;
            }
        }
        const auto Queued = Self->TryQueueEvent(ServerEvent{
            RequestEvent{StreamId, RequestHead{std::move(It->second), IsFin}}});
        if (!Queued)
        {
            if (IsFin)
            {
                Self->HeaderFinStreams_.erase(StreamId);
            }
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        Self->IncomingHeaders_.erase(It);
        return 0;
    }

    auto Session::CbRecvData(
        nghttp3_conn *,
        const std::int64_t StreamId,
        const std::uint8_t *Data,
        const std::size_t Length,
        void *UserData,
        void *) -> int
    {
        auto *Self = static_cast<Session *>(UserData);
        if (!Self || (Length != 0 && !Data))
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        if (!Self->CanQueueEvent(Length))
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        try
        {
            std::vector<std::byte> Payload;
            const auto *Begin = reinterpret_cast<const std::byte *>(Data);
            if (Self->ActiveDataPointer_ == Begin && Length == Self->ActiveData_.size())
            {
                Payload = std::move(Self->ActiveData_);
            }
            else if (Length != 0)
            {
                Payload.assign(Begin, Begin + Length);
            }
            if (!Self->TryQueueEvent(ServerEvent{DataEvent{StreamId, std::move(Payload), false}}))
            {
                return NGHTTP3_ERR_CALLBACK_FAILURE;
            }
            return 0;
        }
        catch (...)
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
    }

    auto Session::CbStopSending(
        nghttp3_conn *,
        const std::int64_t StreamId,
        std::uint64_t,
        void *UserData,
        void *) -> int
    {
        auto *Self = static_cast<Session *>(UserData);
        if (!Self)
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        if (!Self->TryQueueEvent(
                ServerEvent{ResetEvent{StreamId, Fault::Code::ConnectionReset}}))
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    auto Session::CbEndStream(
        nghttp3_conn *,
        const std::int64_t StreamId,
        void *UserData,
        void *) -> int
    {
        auto *Self = static_cast<Session *>(UserData);
        if (!Self)
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        if (Self->HeaderFinStreams_.erase(StreamId) == 0)
        {
            if (!Self->TryQueueEvent(ServerEvent{DataEvent{StreamId, {}, true}}))
            {
                return NGHTTP3_ERR_CALLBACK_FAILURE;
            }
        }
        return 0;
    }

    auto Session::CbRand(
        std::uint8_t *Destination,
        const std::size_t Length) -> void
    {
        if (Length == 0)
        {
            return;
        }
        auto *Owner = ActiveRandomOwner_;
        if (Owner)
        {
            std::fill_n(Destination, Length, std::uint8_t{0});
        }
    }

} // namespace Prism::Http3::Detail
