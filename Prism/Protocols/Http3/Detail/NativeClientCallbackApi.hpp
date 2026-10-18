/**
 * @file NativeClientCallbackApi.hpp
 * @brief 声明 H3 client 的私有 nghttp3 回调绑定点。
 * @details 此头只供 Detail owner 编译使用，不进入公开会话能力接口。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include <nghttp3/nghttp3.h>

namespace Prism::Http3::Detail
{
    class NativeClientSessionOwner;

    struct NativeClientCallbacks final
    {
        inline static thread_local NativeClientSessionOwner *ActiveRandomOwner{nullptr};

        static auto Initialize(NativeClientSessionOwner &Owner) -> bool;
        static auto Submit(NativeClientSessionOwner &Owner) -> bool;
        static auto BeginHeaders(
            nghttp3_conn *, std::int64_t StreamId, void *UserData, void *) -> int;
        static auto ReceiveHeader(
            nghttp3_conn *, std::int64_t StreamId, std::int32_t Token,
            nghttp3_rcbuf *Name, nghttp3_rcbuf *Value, std::uint8_t,
            void *UserData, void *) -> int;
        static auto EndHeaders(
            nghttp3_conn *, std::int64_t StreamId, int Fin, void *UserData, void *) -> int;
        static auto ReceiveData(
            nghttp3_conn *, std::int64_t, const std::uint8_t *, std::size_t, void *, void *) -> int;
        static auto EndStream(
            nghttp3_conn *, std::int64_t StreamId, void *UserData, void *) -> int;
        static auto StopSending(
            nghttp3_conn *, std::int64_t, std::uint64_t, void *, void *) -> int;
        static auto ResetStream(
            nghttp3_conn *, std::int64_t, std::uint64_t, void *, void *) -> int;
        static auto Random(std::uint8_t *Destination, std::size_t Length) -> void;
        static auto ReadRequestBody(
            nghttp3_conn *, std::int64_t, nghttp3_vec *, std::size_t,
            std::uint32_t *Flags, void *, void *) -> nghttp3_ssize;
        [[nodiscard]] static auto NowTstamp() -> std::uint64_t;
        [[nodiscard]] static auto RcbufView(nghttp3_rcbuf *Buffer) -> std::string_view;
    };
}
