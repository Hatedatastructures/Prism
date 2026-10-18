/**
 * @file CodecState.hpp
 * @brief HTTP/2 会话 HPACK 状态 owner。
 */

#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <vector>

#include <Prism/Protocols/Http2/Detail/Codec.hpp>

namespace Prism::Http2::Detail
{

    /**
     * @class CodecState
     * @brief 持有一条连接两端共享的 HPACK 编码器和解码器。
     * @details 动态表必须随会话存活，不能由每个 HEADERS 帧临时创建。
     */
    class CodecState final
    {
    public:
        [[nodiscard]] auto EncodeHeaders(const HeaderList &Headers) -> std::vector<std::byte>
        {
            return Encoder_.Encode(Headers);
        }

        [[nodiscard]] auto DecodeHeaders(std::span<const std::byte> Block)
            -> std::optional<HeaderList>
        {
            return Decoder_.Decode(Block);
        }

    private:
        HpackEncoder Encoder_;
        HpackDecoder Decoder_;
    };

} // namespace Prism::Http2::Detail
