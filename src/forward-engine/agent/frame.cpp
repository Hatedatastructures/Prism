#include <forward-engine/protocol/frame.hpp>
#include <boost/endian/conversion.hpp>
#include <cstring>
#include <stdexcept>

namespace ngx::protocol
{
    /**
     * @brief 序列化 `websocket` 帧
     * @param frame_instance 待序列化的帧
     * @return 序列化后的字符串
     */
    std::string serialize(const frame &frame_instance)
    {
        std::string result;
        // 4 字节 ID + 1 字节 type + payload
        result.resize(5 + frame_instance.payload.size());

        std::uint32_t net_id = boost::endian::native_to_big(frame_instance.id);
        std::memcpy(result.data(), &net_id, sizeof(std::uint32_t));

        result[4] = static_cast<char>(frame_instance.type);
        std::memcpy(result.data() + 5, frame_instance.payload.data(), frame_instance.payload.size());

        return result;
    }

    /**
     * @brief 反序列化 `websocket` 帧
     * @param string_value 待反序列化的字符串
     * @param frame_instance 反序列化后的帧
     * @return 是否成功反序列化
     */
    ngx::gist::code deserialize(std::string_view string_value, frame &frame_instance)
    {
        // 检查最小长度 4 字节 ID + 1 字节 type = 5 字节
        if (string_value.size() < 5)
        {
            return ngx::gist::code::bad_message;
        }

        std::uint32_t net_id;
        std::memcpy(&net_id, string_value.data(), sizeof(std::uint32_t));
        std::uint32_t id = boost::endian::big_to_native(net_id);

        auto raw_type = static_cast<std::uint8_t>(string_value[4]);
        const auto type = static_cast<enum frame::type>(raw_type);

        std::string_view payload(string_value.data() + 5, string_value.size() - 5);

        // 构造新帧并赋值给实例
        // 这要求 frame 是可复制赋值或可移动赋值（默认生成的是足够的）
        frame_instance = frame(type, id, payload);

        return ngx::gist::code::success;
    }
}
