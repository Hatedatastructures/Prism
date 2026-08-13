/**
 * @file codec.hpp
 * @brief smux 帧编解码策略实现声明
 * @details 定义 multiplex::smux::smux_codec，实现 smux v1 协议的帧
 *          编解码（8 字节定长帧头）。帧格式：
 *          [Version 1B][Cmd 1B][Length 2B LE][StreamID 4B LE][Payload]。
 *          命令类型映射：SYN→syn、FIN→fin、PSH→data、NOP→control。
 *          复用 frame.hpp 的 deserialization/make_data_frame/make_fin，
 *          是 codec 策略接口的 smux 具体实现。
 * @note 无状态、无协程，纯帧格式变换，可单测
 */
#pragma once

#include <prism/protocol/multiplex/codec.hpp>

#include <cstddef>
#include <span>
#include <string_view>

namespace psm::multiplex::smux
{

    /**
     * @class smux_codec
     * @brief smux 帧编解码策略
     * @details 实现 multiplex::codec 接口，负责 smux 帧头的解析与
     *          数据帧/结束帧的构造。帧头 8 字节定长，Length/StreamID
     *          小端序，命令类型见 frame.hpp 的 command 枚举。
     */
    class smux_codec final : public multiplex::codec
    {
    public:
        /**
         * @brief 获取帧头长度（固定 8 字节）
         */
        [[nodiscard]] auto header_size() const noexcept -> std::size_t override;

        /**
         * @brief 解析 smux 帧头
         * @param header 8 字节帧头
         * @return 帧元信息（命令映射为语义分类）
         */
        [[nodiscard]] auto decode_header(std::span<const std::byte> header) -> frame_meta override;

        /**
         * @brief 构造 PSH 数据帧（8 字节帧头 + 载荷）
         */
        [[nodiscard]] auto encode_data(std::uint32_t stream_id, std::span<const std::byte> payload)
            -> memory::vector<std::byte> override;

        /**
         * @brief 构造 FIN 结束帧（仅帧头）
         */
        [[nodiscard]] auto encode_fin(std::uint32_t stream_id) -> memory::vector<std::byte> override;

        /**
         * @brief 获取协议名称
         */
        [[nodiscard]] auto type_name() const noexcept -> std::string_view override;
    };

} // namespace psm::multiplex::smux
