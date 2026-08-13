/**
 * @file codec.hpp
 * @brief yamux 帧编解码策略实现声明
 * @details 定义 multiplex::yamux::yamux_codec，实现 yamux 协议的帧
 *          编解码（12 字节大端帧头）。帧格式：
 *          [Version 1B][Type 1B][Flags 2B BE][StreamID 4B BE][Length 4B BE]。
 *          Data 帧映射为 data 语义（SYN/FIN/RST 标志由 control 层
 *          检查 meta.flags 分发），WindowUpdate/Ping/GoAway 映射为
 *          control 语义（由 control 按 meta.raw_type 解释）。
 *          复用 frame.hpp 的 parse_header/build_data/build_fin。
 * @note 无状态、无协程，纯帧格式变换，可单测
 */
#pragma once

#include <prism/protocol/multiplex/codec.hpp>

#include <cstddef>
#include <span>
#include <string_view>

namespace psm::multiplex::yamux
{

    /**
     * @class yamux_codec
     * @brief yamux 帧编解码策略
     * @details 实现 multiplex::codec 接口，负责 yamux 帧头的解析与
     *          数据帧/结束帧的构造。帧头 12 字节大端序，Length 字段
     *          在 Data 帧中为载荷长度、控制帧中为增量/ID/原因码。
     */
    class yamux_codec final : public multiplex::codec
    {
    public:
        /**
         * @brief 获取帧头长度（固定 12 字节）
         */
        [[nodiscard]] auto header_size() const noexcept -> std::size_t override;

        /**
         * @brief 解析 yamux 帧头
         * @param header 12 字节帧头
         * @return 帧元信息（类型映射为语义分类，flags 保留供 control 分发）
         */
        [[nodiscard]] auto decode_header(std::span<const std::byte> header) -> frame_meta override;

        /**
         * @brief 构造 Data 帧（12 字节帧头 + 载荷）
         */
        [[nodiscard]] auto encode_data(std::uint32_t stream_id, std::span<const std::byte> payload)
            -> memory::vector<std::byte> override;

        /**
         * @brief 构造 Data(FIN) 帧（仅帧头）
         */
        [[nodiscard]] auto encode_fin(std::uint32_t stream_id) -> memory::vector<std::byte> override;

        /**
         * @brief 获取协议名称
         */
        [[nodiscard]] auto type_name() const noexcept -> std::string_view override;
    };

} // namespace psm::multiplex::yamux
