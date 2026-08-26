/**
 * @file Codec.hpp
 * @brief sing-mux（h2mux）帧编解码（纯函数，零状态，大端序）
 * @details 帧格式：[Type 1B][Length 4B BE][StreamID 4B BE] = 9 字节，
 *          与 sing-box singmux 协议兼容。
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
#include <common/Protocols/Mux/H2Mux/Types.hpp>

namespace Preview::Mux::H2Mux
{

    /**
     * @brief 构造 sing-mux 帧
     * @param Type 帧类型
     * @param StreamId 流标识符
     * @param payload 负载
     * @return 完整帧
     */
    [[nodiscard]] inline auto Build(FrameType Type, std::uint32_t StreamId,
                                    std::span<const std::uint8_t> Payload = {}) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.reserve(FrameHdrsize + Payload.size());
        out.push_back(static_cast<std::uint8_t>(Type));
        out.push_back(static_cast<std::uint8_t>((Payload.size() >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((Payload.size() >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((Payload.size() >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(Payload.size() & 0xFF));
        out.push_back(static_cast<std::uint8_t>((StreamId >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((StreamId >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((StreamId >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(StreamId & 0xFF));
        out.insert(out.end(), Payload.begin(), Payload.end());
        return out;
    }

    /**
     * @brief 构造 DATA 帧
     * @param StreamId 流标识符
     * @param payload 负载
     * @return 完整帧
     */
    [[nodiscard]] inline auto BuildData(std::uint32_t StreamId, std::span<const std::uint8_t> Payload)
        -> std::vector<std::uint8_t>
    {
        return Build(FrameType::Data, StreamId, Payload);
    }

    /**
     * @brief 构造 WindowUpdate 帧
     * @param StreamId 流标识符
     * @param delta 窗口增量
     * @return 9 字节帧
     */
    [[nodiscard]] inline auto BuildWinupd(std::uint32_t StreamId, std::uint32_t delta)
        -> std::array<std::uint8_t, FrameHdrsize>
    {
        const auto Raw =
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(&delta), sizeof(delta));
        const auto Frame = Build(FrameType::WindowUpdate, StreamId, Raw);
        std::array<std::uint8_t, FrameHdrsize> out{};
        std::memcpy(out.data(), Frame.data(), FrameHdrsize);
        return out;
    }

    /**
     * @brief 构造 Ping 帧
     * @param PingId 心跳标识（携带于负载 4 字节）
     * @return 13 字节帧
     */
    [[nodiscard]] inline auto BuildPing(std::uint32_t PingId) -> std::vector<std::uint8_t>
    {
        const auto Payload = std::array<std::uint8_t, 4>{
            static_cast<std::uint8_t>((PingId >> 24) & 0xFF),
            static_cast<std::uint8_t>((PingId >> 16) & 0xFF),
            static_cast<std::uint8_t>((PingId >> 8) & 0xFF),
            static_cast<std::uint8_t>(PingId & 0xFF),
        };
        return Build(FrameType::Ping, 0, Payload);
    }

    /**
     * @brief 构造 Close 帧
     * @param StreamId 流标识符
     * @return 9 字节帧
     */
    [[nodiscard]] inline auto BuildClose(std::uint32_t StreamId) -> std::array<std::uint8_t, FrameHdrsize>
    {
        const auto Frame = Build(FrameType::Close, StreamId);
        std::array<std::uint8_t, FrameHdrsize> out{};
        std::memcpy(out.data(), Frame.data(), FrameHdrsize);
        return out;
    }

    /**
     * @brief 解析 9 字节帧头
     * @param Data 至少 9 字节
     * @param out 输出帧头
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseHeader(std::span<const std::uint8_t> Data, FrameHeader &out) -> Error
    {
        if (Data.size() < FrameHdrsize)
        {
            return Error::NeedMore;
        }
        out.Type = static_cast<FrameType>(Data[0]);
        out.length = static_cast<std::uint32_t>(Data[1]) << 24 | static_cast<std::uint32_t>(Data[2]) << 16 |
                     static_cast<std::uint32_t>(Data[3]) << 8 | static_cast<std::uint32_t>(Data[4]);
        if (out.length > MaxFrameLength)
        {
            return Error::BadLength;
        }
        out.StreamId = static_cast<std::uint32_t>(Data[5]) << 24 |
                        static_cast<std::uint32_t>(Data[6]) << 16 | static_cast<std::uint32_t>(Data[7]) << 8 |
                        static_cast<std::uint32_t>(Data[8]);
        return Error::None;
    }

    /**
     * @brief 校验负载
     * @return 错误码（恒为 none）
     */
    [[nodiscard]] inline auto ParsePayload(FrameHeader &, std::span<const std::uint8_t>) -> Error
    {
        return Error::None;
    }

    /**
     * @struct Codec
     * @brief sing-mux 帧编解码策略（供共享会话框架模板传参）
     * @details 实现 FrameCodec concept：帧构造与帧事件判定。
     *          协议无 SYN/RST 独立帧：开流 = 首 DATA 帧（隐式），
     *          关闭/重置均以 CLOSE 帧表达。
     */
    struct Codec
    {
        /// 帧类型
        using FrameType = FrameHeader;

        /// 帧头长度
        static inline constexpr std::size_t HeaderLen = FrameHdrsize;

        /// 最大负载长度
        static inline constexpr std::size_t MaxPayloadLen = MaxFrameLength;

        /**
         * @brief 由帧头计算负载长度
         * @param Frame 帧头
         * @return 负载长度
         */
        [[nodiscard]] static auto PayloadLen(const FrameType &Frame) noexcept -> std::size_t
        {
            return Frame.length;
        }

        /**
         * @brief 解析帧头
         * @param Data 帧头字节
         * @param out 输出帧头
         * @return 错误码
         */
        static auto ParseHeader(std::span<const std::uint8_t> Data, FrameType &out) -> Error
        {
            return H2Mux::ParseHeader(Data, out);
        }

        /**
         * @brief 解析负载
         * @param Frame 帧头
         * @param Data 负载字节
         * @return 错误码（恒为 none）
         */
        static auto ParsePayload(FrameType &Frame, std::span<const std::uint8_t> Data) -> Error
        {
            return H2Mux::ParsePayload(Frame, Data);
        }

        /**
         * @brief 帧事件判定
         * @param Frame 帧头
         * @return 流事件（DATA=数据/隐式开流，CLOSE=半关，
         * WINDOW_UPDATE/PING=rst 忽略）
         */
        [[nodiscard]] static auto FrameEvent(const FrameType &Frame) noexcept -> Mux::StreamEvent
        {
            switch (Frame.Type)
            {
            case H2Mux::FrameType::Data: return Mux::StreamEvent::Data;
            case H2Mux::FrameType::Close: return Mux::StreamEvent::Fin;
            default: return Mux::StreamEvent::Rst; // window_update/ping 忽略
            }
        }

        /**
         * @brief 会话级控制帧判定
         * @param Frame 帧头
         * @return true = 会话级（window_update / ping，忽略）
         */
        [[nodiscard]] static auto IsControl(const FrameType &Frame) noexcept -> bool
        {
            return Frame.Type != H2Mux::FrameType::Data && Frame.Type != H2Mux::FrameType::Close;
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
         * @brief 构造开流帧
         * @param Id 流标识符
         * @return 完整帧
         * @details h2mux 无 SYN 帧：首数据帧即开流，此处为空帧。
         */
        [[nodiscard]] static auto BuildOpen(std::uint32_t Id) -> std::vector<std::uint8_t>
        {
            return BuildData(Id, {});
        }

        /**
         * @brief 构造数据帧（DATA）
         * @param Id 流标识符
         * @param Data 负载
         * @return 完整帧
         */
        [[nodiscard]] static auto BuildData(std::uint32_t Id, std::span<const std::uint8_t> Data)
            -> std::vector<std::uint8_t>
        {
            return H2Mux::BuildData(Id, Data);
        }

        /**
         * @brief 构造 FIN 帧（CLOSE，半关）
         * @param Id 流标识符
         * @return 完整帧
         */
        [[nodiscard]] static auto BuildFin(std::uint32_t Id) -> std::vector<std::uint8_t>
        {
            const auto Frame = H2Mux::BuildClose(Id);
            return {Frame.begin(), Frame.end()};
        }

        /**
         * @brief 构造 RST 帧（CLOSE，重置流）
         * @param Id 流标识符
         * @return 完整帧
         * @warning sing-mux 无独立 RST 帧，以 CLOSE 帧近似（对端按半关处理）
         */
        [[nodiscard]] static auto BuildRst(std::uint32_t Id) -> std::vector<std::uint8_t>
        {
            return BuildFin(Id);
        }
    };

    static_assert(Mux::FrameCodec<Codec>, "H2Mux::Codec 必须满足 FrameCodec");

} // namespace Preview::Mux::H2Mux
