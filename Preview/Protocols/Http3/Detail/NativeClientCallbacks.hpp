/**
 * @file NativeClientCallbacks.hpp
 * @brief 隔离 nghttp3 client 回调注册与同步复制。
 * @details 每个回调在返回前把 header 字段复制进会话自有存储，不保留 nghttp3 临时缓冲。
 */

#pragma once

#include <openssl/rand.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <expected>
#include <system_error>
#include <vector>

#include <nghttp3/nghttp3.h>

#include <Preview/Protocols/Http3/Detail/NativeClient.hpp>
#include <Preview/Protocols/Http3/HeaderLimits.hpp>

namespace Preview::Http3::Detail
{
    inline auto NativeClientCallbacks::Initialize(NativeClientSessionOwner &Owner) -> bool
    {
        nghttp3_callbacks Callbacks{};
        Callbacks.begin_headers = BeginHeaders;
        Callbacks.recv_header = ReceiveHeader;
        Callbacks.end_headers = EndHeaders;
        Callbacks.recv_data = ReceiveData;
        Callbacks.end_stream = EndStream;
        Callbacks.stop_sending = StopSending;
        Callbacks.reset_stream = ResetStream;
        Callbacks.rand = Random;
        nghttp3_settings Settings{};
        nghttp3_settings_default_versioned(NGHTTP3_SETTINGS_VERSION, &Settings);
        Settings.max_field_section_size = HeaderLimits::MaxHeaderSectionBytes;
        ActiveRandomOwner = &Owner;
        const auto Result = nghttp3_conn_client_new_versioned(
            &Owner.Conn_, NGHTTP3_CALLBACKS_VERSION, &Callbacks,
            NGHTTP3_SETTINGS_VERSION, &Settings, nghttp3_mem_default(), &Owner);
        ActiveRandomOwner = nullptr;
        if (Result != 0 || !Owner.Conn_ || Owner.RandomFailed_)
        {
            Owner.Conn_ = nullptr;
            return false;
        }
        return nghttp3_conn_bind_control_stream(
                   Owner.Conn_, Owner.Http3Streams_[0]->StreamId()) == 0 &&
               nghttp3_conn_bind_qpack_streams(
                   Owner.Conn_, Owner.Http3Streams_[1]->StreamId(),
                   Owner.Http3Streams_[2]->StreamId()) == 0;
    }

    inline auto NativeClientCallbacks::Submit(NativeClientSessionOwner &Owner) -> bool
    {
        if (!Owner.Conn_ || !Owner.RequestStream_ || !Owner.RequestHeaders_ ||
            Owner.RequestHeaders_->Fields.empty() || !Owner.RequestHeaders_->WithinLimits())
        {
            return false;
        }
        std::vector<nghttp3_nv> Fields;
        try
        {
            Fields.reserve(Owner.RequestHeaders_->Fields.size());
            for (const auto &Field : Owner.RequestHeaders_->Fields)
            {
                Fields.push_back({
                    reinterpret_cast<const std::uint8_t *>(Field.Name.data()),
                    reinterpret_cast<const std::uint8_t *>(Field.value.data()),
                    Field.Name.size(), Field.value.size(), NGHTTP3_NV_FLAG_NONE});
            }
        }
        catch (...)
        {
            return false;
        }
        nghttp3_data_reader Reader{};
        Reader.read_data = ReadRequestBody;
        nghttp3_data_reader *ReaderValue = nullptr;
        if (!Owner.RequestFin_)
        {
            ReaderValue = &Reader;
        }
        return nghttp3_conn_submit_request(
                   Owner.Conn_, Owner.RequestStreamId_, Fields.data(), Fields.size(),
                   ReaderValue, nullptr) == 0;
    }

    inline auto NativeClientCallbacks::BeginHeaders(
        nghttp3_conn *, const std::int64_t StreamId, void *UserData, void *) -> int
    {
        auto *Owner = static_cast<NativeClientSessionOwner *>(UserData);
        if (!Owner)
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        Owner->ResponseHeaders_.Clear();
        Owner->ResponseStatus_ = 0;
        Owner->ResponseStreamId_ = StreamId;
        return 0;
    }

    inline auto NativeClientCallbacks::ReceiveHeader(
        nghttp3_conn *, const std::int64_t StreamId, const std::int32_t Token,
        nghttp3_rcbuf *Name, nghttp3_rcbuf *Value, std::uint8_t,
        void *UserData, void *) -> int
    {
        auto *Owner = static_cast<NativeClientSessionOwner *>(UserData);
        if (!Owner)
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        if (StreamId != Owner->ResponseStreamId_)
        {
            return 0;
        }
        const auto Text = RcbufView(Value);
        if (Token == NGHTTP3_QPACK_TOKEN__STATUS)
        {
            std::uint16_t Status = 0;
            const auto Parsed = std::from_chars(Text.data(), Text.data() + Text.size(), Status);
            if (Parsed.ec != std::errc{} || Parsed.ptr != Text.data() + Text.size() ||
                Status > 999)
            {
                return NGHTTP3_ERR_CALLBACK_FAILURE;
            }
            Owner->ResponseStatus_ = Status;
        }
        const auto Appended = Owner->ResponseHeaders_.TryAppend(RcbufView(Name), Text);
        if (!Appended)
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    inline auto NativeClientCallbacks::EndHeaders(
        nghttp3_conn *, const std::int64_t StreamId, const int Fin, void *UserData, void *) -> int
    {
        auto *Owner = static_cast<NativeClientSessionOwner *>(UserData);
        if (Owner && StreamId == Owner->ResponseStreamId_)
        {
            Owner->ResponseHeadersDone_ = true;
            Owner->ResponseFin_ = Fin != 0;
            if (Fin != 0) Owner->ResponseDone_ = true;
        }
        if (!Owner)
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    inline auto NativeClientCallbacks::ReceiveData(
        nghttp3_conn *, std::int64_t, const std::uint8_t *, std::size_t, void *, void *) -> int
    {
        return 0;
    }

    inline auto NativeClientCallbacks::EndStream(
        nghttp3_conn *, const std::int64_t StreamId, void *UserData, void *) -> int
    {
        auto *Owner = static_cast<NativeClientSessionOwner *>(UserData);
        if (Owner && StreamId == Owner->ResponseStreamId_)
        {
            Owner->ResponseDone_ = true;
            Owner->ResponseFin_ = true;
        }
        if (!Owner)
        {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    inline auto NativeClientCallbacks::StopSending(
        nghttp3_conn *, std::int64_t, std::uint64_t, void *, void *) -> int
    {
        return 0;
    }

    inline auto NativeClientCallbacks::ResetStream(
        nghttp3_conn *, std::int64_t, std::uint64_t, void *, void *) -> int
    {
        return 0;
    }

    inline auto NativeClientCallbacks::Random(
        std::uint8_t *Destination, const std::size_t Length) -> void
    {
        auto *Owner = ActiveRandomOwner;
        int Result = 0;
        try
        {
            if (Owner && Owner->Options_.Random)
            {
                Result = Owner->Options_.Random(Destination, static_cast<int>(Length));
            }
            else
            {
                Result = RAND_bytes(Destination, static_cast<int>(Length));
            }
        }
        catch (...)
        {
            Result = 0;
        }
        if (Result != 1 && Owner)
        {
            std::fill_n(Destination, Length, std::uint8_t{0});
            Owner->RandomFailed_ = true;
        }
    }

    inline auto NativeClientCallbacks::ReadRequestBody(
        nghttp3_conn *, std::int64_t, nghttp3_vec *, std::size_t,
        std::uint32_t *Flags, void *, void *) -> nghttp3_ssize
    {
        if (Flags)
        {
            *Flags = 0;
        }
        return NGHTTP3_ERR_WOULDBLOCK;
    }

    inline auto NativeClientCallbacks::NowTstamp() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count());
    }

    inline auto NativeClientCallbacks::RcbufView(nghttp3_rcbuf *Buffer) -> std::string_view
    {
        if (!Buffer)
        {
            return {};
        }
        const auto Value = nghttp3_rcbuf_get_buf(Buffer);
        return {reinterpret_cast<const char *>(Value.base), Value.len};
    }
}
