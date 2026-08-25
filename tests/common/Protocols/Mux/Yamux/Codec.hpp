/**
 * @file Codec.hpp
 * @brief yamux 帧编解码（纯函数，零状态，大端序）
 * @details 帧格式：[Version 1B][Type 1B][Flags 2B BE][StreamID 4B BE][Length 4B BE]，
 *          Length 字段含义随 Type 变化（Data = 载荷长）。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include <common/Core/Error.hpp>
#include <common/Core/Parser.hpp>
#include <common/Protocols/Mux/Codec.hpp>
#include <common/Protocols/Mux/Yamux/Types.hpp>

namespace Preview::Mux::Yamux
{

    /**
     * @brief 编码帧头为 12 字节大端序数组
     * @param hdr 帧头
     * @return 编码后的字节数组
     */
    [[nodiscard]] inline auto BuildHeader(const FrameHeader &hdr) noexcept
        -> std::array<std::uint8_t, FrameHdrsize>
    {
        std::array<std::uint8_t, FrameHdrsize> out{};
        out[0] = hdr.version;
        out[1] = static_cast<std::uint8_t>(hdr.Type);
        out[2] = static_cast<std::uint8_t>((static_cast<std::uint16_t>(hdr.flag) >> 8) & 0xFF);
        out[3] = static_cast<std::uint8_t>(static_cast<std::uint16_t>(hdr.flag) & 0xFF);
        out[4] = static_cast<std::uint8_t>((hdr.StreamId >> 24) & 0xFF);
        out[5] = static_cast<std::uint8_t>((hdr.StreamId >> 16) & 0xFF);
        out[6] = static_cast<std::uint8_t>((hdr.StreamId >> 8) & 0xFF);
        out[7] = static_cast<std::uint8_t>(hdr.StreamId & 0xFF);
        out[8] = static_cast<std::uint8_t>((hdr.length >> 24) & 0xFF);
        out[9] = static_cast<std::uint8_t>((hdr.length >> 16) & 0xFF);
        out[10] = static_cast<std::uint8_t>((hdr.length >> 8) & 0xFF);
        out[11] = static_cast<std::uint8_t>(hdr.length & 0xFF);
        return out;
    }

    /**
     * @brief 构造完整帧（帧头 + 载荷）
     * @param hdr 帧头（length 自动填充）
     * @param payload 载荷
     * @return 完整帧
     */
    [[nodiscard]] inline auto Build(const FrameHeader &hdr, std::span<const std::uint8_t> payload = {})
        -> std::vector<std::uint8_t>
    {
        auto HdrCopy = hdr;
        if (HdrCopy.Type == MessageType::Data)
        {
            HdrCopy.length = static_cast<std::uint32_t>(payload.size());
        }
        const auto Header = BuildHeader(HdrCopy);
        std::vector<std::uint8_t> out;
        out.reserve(FrameHdrsize + payload.size());
        out.insert(out.end(), Header.begin(), Header.end());
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    /**
     * @brief 构造 WindowUpdate 帧（SYN/ACK 打开/确认流）
     * @param f 标志位
     * @param StreamId 流标识符
     * @param delta 窗口增量
     * @return 12 字节帧
     */
    [[nodiscard]] inline auto BuildWinupd(Flags f, std::uint32_t StreamId, std::uint32_t delta) noexcept
        -> std::array<std::uint8_t, FrameHdrsize>
    {
        const FrameHeader hdr{
            .Type = MessageType::window_update,
            .flag = f,
            .StreamId = StreamId,
            .length = delta,
        };
        return BuildHeader(hdr);
    }

    /**
     * @brief 构造 Ping 帧
     * @param f 标志位（SYN 请求 / ACK 响应）
     * @param ping_id 心跳标识
     * @return 12 字节帧
     */
    [[nodiscard]] inline auto BuildPing(Flags f, std::uint32_t ping_id) noexcept
        -> std::array<std::uint8_t, FrameHdrsize>
    {
        const FrameHeader hdr{
            .Type = MessageType::ping,
            .flag = f,
            .StreamId = 0,
            .length = ping_id,
        };
        return BuildHeader(hdr);
    }

    /**
     * @brief 构造 GoAway 帧
     * @param Code 终止原因码
     * @return 12 字节帧
     */
    [[nodiscard]] inline auto BuildGoaway(AwayCode Code) noexcept -> std::array<std::uint8_t, FrameHdrsize>
    {
        const FrameHeader hdr{
            .Type = MessageType::go_away,
            .flag = Flags::none,
            .StreamId = 0,
            .length = static_cast<std::uint32_t>(Code),
        };
        return BuildHeader(hdr);
    }

    /**
     * @brief 构造 Data 帧
     * @param f 标志位（none/SYN/FIN/RST）
     * @param StreamId 流标识符
     * @param payload 载荷
     * @return 完整帧
     */
    [[nodiscard]] inline auto BuildData(Flags f, std::uint32_t StreamId,
                                         std::span<const std::uint8_t> payload) noexcept
        -> std::vector<std::uint8_t>
    {
        const FrameHeader hdr{
            .Type = MessageType::Data,
            .flag = f,
            .StreamId = StreamId,
        };
        return Build(hdr, payload);
    }

    /**
     * @brief 构造 Data(SYN) 帧（sing-mux 兼容新流创建）
     * @param StreamId 流标识符
     * @param payload 载荷
     * @return 完整帧
     */
    [[nodiscard]] inline auto BuildSyn(std::uint32_t StreamId,
                                        std::span<const std::uint8_t> payload) noexcept
        -> std::vector<std::uint8_t>
    {
        return BuildData(Flags::syn, StreamId, payload);
    }

    /**
     * @brief 构造 Data(FIN) 帧
     * @param StreamId 流标识符
     * @return 12 字节帧
     */
    [[nodiscard]] inline auto BuildSyn(std::uint32_t StreamId) noexcept
        -> std::array<std::uint8_t, FrameHdrsize>
    {
        const FrameHeader hdr{
            .Type = MessageType::Data,
            .flag = Flags::fin,
            .StreamId = StreamId,
        };
        return BuildHeader(hdr);
    }

    /**
     * @brief 解析 12 字节帧头
     * @param Data 至少 12 字节
     * @param out 输出帧头
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseHeader(std::span<const std::uint8_t> Data, FrameHeader &out) noexcept
        -> Error
    {
        if (Data.size() < FrameHdrsize)
        {
            return Error::need_more;
        }
        out.version = Data[0];
        if (out.version != ProtocolVersion)
        {
            return Error::bad_magic;
        }
        out.Type = static_cast<MessageType>(Data[1]);
        switch (out.Type)
        {
        case MessageType::Data:
        case MessageType::window_update:
        case MessageType::ping:
        case MessageType::go_away: break;
        default: return Error::bad_message;
        }
        out.flag = static_cast<Flags>(static_cast<std::uint16_t>(Data[2]) << 8 |
                                      static_cast<std::uint16_t>(Data[3]));
        out.StreamId = static_cast<std::uint32_t>(Data[4]) << 24 |
                        static_cast<std::uint32_t>(Data[5]) << 16 | static_cast<std::uint32_t>(Data[6]) << 8 |
                        static_cast<std::uint32_t>(Data[7]);
        out.length = static_cast<std::uint32_t>(Data[8]) << 24 | static_cast<std::uint32_t>(Data[9]) << 16 |
                     static_cast<std::uint32_t>(Data[10]) << 8 | static_cast<std::uint32_t>(Data[11]);
        return Error::none;
    }

    /**
     * @brief 校验负载（yamux 无额外校验）
     * @return 错误码（恒为 none）
     */
    [[nodiscard]] inline auto ParsePayload(FrameHeader &, std::span<const std::uint8_t>) -> Error
    {
        return Error::none;
    }

    /**
     * @struct Codec
     * @brief yamux 帧编解码策略（供共享会话框架模板传参）
     * @details 实现 FrameCodec concept：帧构造与帧事件判定。
     *          开流 = WindowUpdate(SYN)，数据/半关/重置均为 Data 帧
     *          + 对应标志位。
     */
    struct Codec
    {
        /// 帧类型
        using FrameType = FrameHeader;

        /// 帧头长度
        static inline constexpr std::size_t HeaderLen = FrameHdrsize;

        /// 最大负载长度（yamux 无硬限制，取 16MB）
        static inline constexpr std::size_t MaxPayloadLen = 16 * 1024 * 1024;

        /**
         * @brief 由帧头计算负载长度
         * @param Frame 帧头
         * @return 负载长度（非 Data 帧恒为 0）
         */
        [[nodiscard]] static auto PayloadLen(const FrameType &Frame) noexcept -> std::size_t
        {
            if (Frame.Type == MessageType::Data)
            {
                return Frame.length;
            }
            return 0;
        }

        /**
         * @brief 解析帧头
         * @param Data 帧头字节
         * @param out 输出帧头
         * @return 错误码
         */
        static auto ParseHeader(std::span<const std::uint8_t> Data, FrameType &out) -> Error
        {
            return Yamux::ParseHeader(Data, out);
        }

        /**
         * @brief 解析负载
         * @param Frame 帧头
         * @param Data 负载字节
         * @return 错误码（恒为 none）
         */
        static auto ParsePayload(FrameType &Frame, std::span<const std::uint8_t> Data) -> Error
        {
            return Yamux::ParsePayload(Frame, Data);
        }

        /**
         * @brief 帧事件判定
         * @param Frame 帧头
         * @return 流事件（Data+SYN=开流 / Data+FIN=半关 / Data+RST=重置 /
         * Data=数据 / 其余=rst 忽略）
         */
        [[nodiscard]] static auto FrameEvent(const FrameType &Frame) noexcept -> Mux::StreamEvent
        {
            if (Frame.Type == MessageType::Data)
            {
                if (HasFlag(Frame.flag, Flags::syn))
                {
                    return Mux::StreamEvent::Open;
                }
                if (HasFlag(Frame.flag, Flags::fin))
                {
                    return Mux::StreamEvent::fin;
                }
                if (HasFlag(Frame.flag, Flags::rst))
                {
                    return Mux::StreamEvent::rst;
                }
                return Mux::StreamEvent::Data;
            }
            return Mux::StreamEvent::rst; // winupd/ping/goaway：会话级，忽略
        }

        /**
         * @brief 会话级控制帧判定
         * @param Frame 帧头
         * @return true = 会话级（window_update / ping / go_away，忽略）
         */
        [[nodiscard]] static auto IsControl(const FrameType &Frame) noexcept -> bool
        {
            return Frame.Type != MessageType::Data;
        }

        /**
         * @brief 取帧流标识
         * @param Frame 帧头
         * @return 流标识符
         */
        [[nodiscard]] static auto FrameStreamId(const FrameType &Frame) noexcept -> std::uint32_t
        {
            return Frame.StreamId;
        }

        /**
         * @brief 构造开流帧（WindowUpdate+SYN，Length = 初始窗口）
         * @param Id 流标识符
         * @return 完整帧
         */
        [[nodiscard]] static auto BuildOpen(std::uint32_t Id) -> std::vector<std::uint8_t>
        {
            const auto Frame = Yamux::BuildWinupd(Flags::syn, Id, DefaultWindow);
            return {Frame.begin(), Frame.end()};
        }

        /**
         * @brief 构造数据帧（Data）
         * @param Id 流标识符
         * @param Data 负载
         * @return 完整帧
         */
        [[nodiscard]] static auto BuildData(std::uint32_t Id, std::span<const std::uint8_t> Data)
            -> std::vector<std::uint8_t>
        {
            return Yamux::BuildData(Flags::none, Id, Data);
        }

        /**
         * @brief 构造 FIN 帧（Data+FIN，半关）
         * @param Id 流标识符
         * @return 完整帧
         */
        [[nodiscard]] static auto BuildSyn(std::uint32_t Id) -> std::vector<std::uint8_t>
        {
            const auto Frame = Yamux::BuildSyn(Id);
            return {Frame.begin(), Frame.end()};
        }

        /**
         * @brief 构造 RST 帧（Data+RST，重置流）
         * @param Id 流标识符
         * @return 完整帧
         */
        [[nodiscard]] static auto BuildRst(std::uint32_t Id) -> std::vector<std::uint8_t>
        {
            return Yamux::BuildData(Flags::rst, Id, {});
        }
    };

    static_assert(Mux::FrameCodec<Codec>, "Yamux::Codec 必须满足 FrameCodec");

} // namespace Preview::Mux::Yamux
