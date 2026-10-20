/**
 * @file Http2Codec.cpp
 * @brief HTTP/2 连接压缩状态的实现。
 */
#include <Prism/Protocols/Http2/Detail/CodecState.hpp>

namespace Prism::Http2::Detail
{
    auto CodecState::EncodeHeaders(const HeaderList &Headers) -> std::vector<std::byte>
    {
        return Encoder_.Encode(Headers);
    }

    auto CodecState::DecodeHeaders(const std::span<const std::byte> Block)
        -> std::optional<HeaderList>
    {
        return Decoder_.Decode(Block);
    }
}
