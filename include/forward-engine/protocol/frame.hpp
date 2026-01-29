/**
 * @file frame.hpp
 * @brief 通用协议帧定义
 * @details 定义了用于内部传输的通用数据帧结构，支持文本、二进制及控制帧。
 */
#pragma once

#include <string>
#include <string_view>
#include <forward-engine/gist.hpp>

namespace ngx::protocol
{
    /**
     * @brief 协议帧结构
     * @details 包含帧类型、ID 和负载数据。
     */
    struct frame
    {
        /**
         * @brief 帧类型枚举
         */
        enum class type : std::uint8_t
        {
            text = 0x1,   // 文本帧
            binary = 0x2, // 二进制帧
            close = 0x8,  // 关闭帧
            ping = 0x9,   // Ping 帧 (心跳)
            pong = 0xA,   // Pong 帧 (心跳响应)
        };

        type type; // 帧类型
        std::uint32_t id; // 帧 ID (用于多路复用或排序)
        std::string payload; // 帧负载数据

        frame() = default;
        
        /**
         * @brief 构造帧
         * @param type 帧类型
         * @param id 帧 ID
         * @param payload 负载数据
         */
        frame(const enum type type, const std::uint32_t id, const std::string_view payload)
            : type(type), id(id), payload(payload) {}
    };

    /**
     * @brief 序列化帧
     * @param frame_instance 待序列化的帧对象
     * @return `std::string` 序列化后的二进制数据
     */
    [[nodiscard]] auto serialize(const frame &frame_instance)
        -> std::string;

    /**
     * @brief 反序列化帧
     * @param string_value 输入的二进制数据
     * @param frame_instance 输出的帧对象
     * @return `gist::code` 反序列化结果状态码
     */
    [[nodiscard]] auto deserialize(std::string_view string_value, frame &frame_instance)
        -> gist::code;
}
