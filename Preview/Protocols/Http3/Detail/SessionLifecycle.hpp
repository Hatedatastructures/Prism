/**
 * @file SessionLifecycle.hpp
 * @brief HTTP/3 nghttp3 会话的建立和关闭职责。
 */

#pragma once

#include <Preview/Protocols/Http3/Detail/SessionContract.hpp>
#include <Preview/Protocols/Http3/HeaderLimits.hpp>

namespace Preview::Http3::Detail
{

    inline auto Session::Init(std::function<std::int64_t()> OpenUniStream) -> bool
    {
        if (Conn_ || !OpenUniStream)
        {
            return Conn_ != nullptr;
        }

        nghttp3_callbacks Callbacks{};
        Callbacks.begin_headers = CbBeginHeaders;
        Callbacks.recv_header = CbRecvHeader;
        Callbacks.end_headers = CbEndHeaders;
        Callbacks.recv_data = CbRecvData;
        Callbacks.stop_sending = CbStopSending;
        Callbacks.end_stream = CbEndStream;
        Callbacks.rand = CbRand;

        nghttp3_settings Settings{};
        nghttp3_settings_default_versioned(NGHTTP3_SETTINGS_VERSION, &Settings);
        Settings.max_field_section_size = HeaderLimits::MaxHeaderSectionBytes;
        ActiveRandomOwner_ = this;
        const auto Result = nghttp3_conn_server_new_versioned(
            &Conn_, NGHTTP3_CALLBACKS_VERSION, &Callbacks,
            NGHTTP3_SETTINGS_VERSION, &Settings, nghttp3_mem_default(), this);
        ActiveRandomOwner_ = nullptr;
        if (Result != 0 || !Conn_)
        {
            Conn_ = nullptr;
            return false;
        }

        ControlStream_ = OpenUniStream();
        EncoderStream_ = OpenUniStream();
        DecoderStream_ = OpenUniStream();
        if (ControlStream_ < 0 || EncoderStream_ < 0 || DecoderStream_ < 0 ||
            nghttp3_conn_bind_control_stream(Conn_, ControlStream_) != 0 ||
            nghttp3_conn_bind_qpack_streams(Conn_, EncoderStream_, DecoderStream_) != 0)
        {
            Close();
            return false;
        }
        OpenAtomic_.store(true, std::memory_order_release);
        return true;
    }

    inline auto Session::Close() noexcept -> void
    {
        if (Conn_)
        {
            nghttp3_conn_del(Conn_);
            Conn_ = nullptr;
        }
        OpenAtomic_.store(false, std::memory_order_release);
        IncomingHeaders_.clear();
        HeaderFinStreams_.clear();
        Events_.clear();
        PendingEventBytes_ = 0;
        Responses_.clear();
        PendingOutput_ = false;
        PendingStream_ = -1;
        PendingBytes_ = 0;
        PendingFin_ = false;
    }

} // namespace Preview::Http3::Detail
