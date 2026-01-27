#pragma once

#include <string>
#include <string_view>
#include <forward-engine/gist.hpp>

namespace ngx::protocol
{
    /**
     * @brief 协议帧
     */
    struct frame
    {
        enum class type : std::uint8_t
        {
            text = 0x1,
            binary = 0x2,
            close = 0x8,
            ping = 0x9,
            pong = 0xA,
        };

        type type;
        std::uint32_t id;
        std::string payload;

        frame() = default;
        frame(const enum type type, const std::uint32_t id, const std::string_view payload)
            : type(type), id(id), payload(payload) {}
    };

    [[nodiscard]] std::string serialize(const frame &frame_instance);

    [[nodiscard]] gist::code deserialize(std::string_view string_value, frame &frame_instance);
}
