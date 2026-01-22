#include <forward-engine/protocol/frame.hpp>
#include <boost/endian/conversion.hpp>
#include <cstring>
#include <stdexcept>

namespace ngx::protocol
{
    frame::frame(enum frame::type type, std::uint32_t streamid, std::string_view data)
        : stream_id_(streamid), type_(type), data_(data)
    {
    }

    std::string_view frame::data() const noexcept
    {
        return data_;
    }

    enum frame::type frame::type() const noexcept
    {
        return type_;
    }

    std::uint32_t frame::stream_id() const noexcept
    {
        return stream_id_;
    }

    /**
     * @brief 序列化 `websocket` 帧
     * @param frame_instance 待序列化的帧
     * @return 序列化后的字符串
     */
    std::string serialize(const frame &frame_instance)
    {
        std::string buffer;
        // 预留内存: 4 字节 ID + 1 字节 type+ 数据长度
        buffer.reserve(sizeof(uint32_t) + sizeof(uint8_t) + frame_instance.data().size());

        uint32_t net_id = boost::endian::native_to_big(frame_instance.stream_id());
        char id_bytes[sizeof(uint32_t)];
        std::memcpy(id_bytes, &net_id, sizeof(uint32_t));
        buffer.append(id_bytes, sizeof(uint32_t));

        buffer.push_back(static_cast<char>(frame_instance.type()));

        buffer.append(frame_instance.data());

        return buffer;
    }

    /**
     * @brief 反序列化 `websocket` 帧
     * @param string_value 待反序列化的字符串
     * @param frame_instance 反序列化后的帧
     * @return 是否成功反序列化
     */
    bool deserialize(std::string_view string_value, frame &frame_instance)
    {
        // 检查最小长度 4 字节 ID + 1 字节 type = 5 字节
        if (string_value.size() < 5)
        {
            return false;
        }

        uint32_t net_id;
        std::memcpy(&net_id, string_value.data(), sizeof(uint32_t));
        uint32_t id = boost::endian::big_to_native(net_id);

        auto raw_type = static_cast<uint8_t>(string_value[4]);
        const auto type = static_cast<enum frame::type>(raw_type);

        std::string_view payload(string_value.data() + 5, string_value.size() - 5);

        // 构造新帧并赋值给实例
        // 这要求 frame 是可复制赋值或可移动赋值（默认生成的是足够的）
        frame_instance = frame(type, id, payload);

        return true;
    }
}
