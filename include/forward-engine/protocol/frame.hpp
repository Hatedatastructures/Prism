#pragma once

#include <string>
#include <cstdint>
#include <string_view>

namespace ngx::protocol
{
    /**
     * @brief `websocket` 帧容器
     * @note `websocket` 帧是 `websocket` 协议的基本单位，用于在客户端和服务端之间传输数据
     */
    class frame
    {
    public:
        enum class type : uint8_t
        {
            connect = 0x01,
            data = 0x02,
            close = 0x03,
            udp = 0x04,
            keepalive = 0xFF
        };

        frame(enum type type, std::uint32_t streamid, std::string_view data);

        [[nodiscard]] std::string_view data() const noexcept;
        [[nodiscard]] enum type type() const noexcept;
        [[nodiscard]] std::uint32_t stream_id() const noexcept;

    private:
        std::uint32_t stream_id_;
        enum type type_;
        std::string data_;
    }; // class frame

    [[nodiscard]] std::string serialize(const frame &frame_instance);

    [[nodiscard]] bool deserialize(std::string_view string_value, frame &frame_instance);
}
