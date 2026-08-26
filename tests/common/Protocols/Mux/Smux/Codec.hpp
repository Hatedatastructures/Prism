/**
 * @file Codec.hpp
 * @brief smux 帧编解码（纯函数，零状态）
 * @details 提供帧构造（Build）与增量解析（Parse），全部为无状态
 *          纯函数，通过 Parser<Config> 组合成状态机。
 *          帧格式：[Version 1B][Cmd 1B][Length 2B LE][StreamID 4B LE][Payload]
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
#include <common/Protocols/Mux/Smux/Types.hpp>

namespace Preview::Mux::Smux
{

    /**
     * @brief 构造 smux 帧字节序列
     * @param hdr 帧头
     * @param payload 负载数据
     * @return 完整帧（帧头 + 负载）
     */
    [[nodiscard]] inline auto Build(const FrameHeader &hdr, std::span<const std::uint8_t> payload = {})
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.reserve(FrameHdrsize + payload.size());
        out.push_back(hdr.version);
        out.push_back(static_cast<std::uint8_t>(hdr.cmd));
        out.push_back(static_cast<std::uint8_t>(hdr.length & 0xFF));
        out.push_back(static_cast<std::uint8_t>((hdr.length >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hdr.StreamId & 0xFF));
        out.push_back(static_cast<std::uint8_t>((hdr.StreamId >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((hdr.StreamId >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((hdr.StreamId >> 24) & 0xFF));
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    /**
     * @brief 构造 SYN 帧
     * @param StreamId 流标识符
     * @return 8 字节帧
     */
    [[nodiscard]] inline auto BuildSyn(std::uint32_t StreamId) -> std::array<std::uint8_t, FrameHdrsize>
    {
        const FrameHeader hdr{.cmd = Command::Syn, .StreamId = StreamId};
        const auto Frame = Build(hdr);
        std::array<std::uint8_t, FrameHdrsize> out{};
        std::memcpy(out.data(), Frame.data(), FrameHdrsize);
        return out;
    }

    /**
     * @brief 构造 FIN 帧
     * @param StreamId 流标识符
     * @return 8 字节帧
     */
    [[nodiscard]] inline auto BuildFin(std::uint32_t StreamId) -> std::array<std::uint8_t, FrameHdrsize>
    {
        const FrameHeader hdr{.cmd = Command::Fin, .StreamId = StreamId};
        const auto Frame = Build(hdr);
        std::array<std::uint8_t, FrameHdrsize> out{};
        std::memcpy(out.data(), Frame.data(), FrameHdrsize);
        return out;
    }

    /**
     * @brief 构造 PSH（数据）帧
     * @param StreamId 流标识符
     * @param payload 负载
     * @return 完整帧
     */
    [[nodiscard]] inline auto BuildPush(std::uint32_t StreamId, std::span<const std::uint8_t> payload)
        -> std::vector<std::uint8_t>
    {
        const FrameHeader hdr{
            .cmd = Command::Push,
            .length = static_cast<std::uint16_t>(payload.size()),
            .StreamId = StreamId,
        };
        return Build(hdr, payload);
    }

    /**
     * @brief 解析 8 字节帧头
     * @param Data 至少 8 字节
     * @param out 输出帧头
     * @return 错误码（bad_magic = 版本/命令非法）
     */
    [[nodiscard]] inline auto ParseHeader(std::span<const std::uint8_t> Data, FrameHeader &out) -> Error
    {
        if (Data.size() < FrameHdrsize)
        {
            return Error::NeedMore;
        }
        out.version = Data[0];
        if (out.version != ProtocolVersion)
        {
            return Error::BadMagic;
        }
        out.cmd = static_cast<Command>(Data[1]);
        switch (out.cmd)
        {
        case Command::Syn:
        case Command::Fin:
        case Command::Push:
        case Command::Nop: break;
        default: return Error::BadMessage;
        }
        out.length = static_cast<std::uint16_t>(Data[2]) | static_cast<std::uint16_t>(Data[3]) << 8;
        if (out.length > MaxFrameLength)
        {
            return Error::BadLength;
        }
        out.StreamId = static_cast<std::uint32_t>(Data[4]) | static_cast<std::uint32_t>(Data[5]) << 8 |
                        static_cast<std::uint32_t>(Data[6]) << 16 | static_cast<std::uint32_t>(Data[7]) << 24;
        return Error::None;
    }

    /**
     * @brief 校验负载（smux 无额外校验，直接返回 none）
     * @return 恒为 Error::None
     */
    [[nodiscard]] inline auto ParsePayload(FrameHeader &, std::span<const std::uint8_t>) -> Error
    {
        return Error::None;
    }

    /**
     * @struct Codec
     * @brief smux 帧编解码策略（供共享会话框架模板传参）
     * @details 实现 FrameCodec concept：帧构造与帧事件判定。
     *          协议无独立 RST 帧，BuildRst 以 FIN 帧近似（见下）。
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
            return Smux::ParseHeader(Data, out);
        }

        /**
         * @brief 解析负载
         * @param Frame 帧头
         * @param Data 负载字节
         * @return 错误码（恒为 none）
         */
        static auto ParsePayload(FrameType &Frame, std::span<const std::uint8_t> Data) -> Error
        {
            return Smux::ParsePayload(Frame, Data);
        }

        /**
         * @brief 帧事件判定
         * @param Frame 帧头
         * @return 流事件（syn=开流 / fin=半关 / Push=数据 / 其余=rst）
         */
        [[nodiscard]] static auto FrameEvent(const FrameType &Frame) noexcept -> Mux::StreamEvent
        {
            switch (Frame.cmd)
            {
            case Command::Syn: return Mux::StreamEvent::Open;
            case Command::Fin: return Mux::StreamEvent::Fin;
            case Command::Push: return Mux::StreamEvent::Data;
            default: return Mux::StreamEvent::Rst; // nop 忽略
            }
        }

        /**
         * @brief 会话级控制帧判定
         * @param Frame 帧头
         * @return true = 会话级（nop 心跳，忽略）
         */
        [[nodiscard]] static auto IsControl(const FrameType &Frame) noexcept -> bool
        {
            return Frame.cmd == Command::Nop;
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
         * @brief 构造开流帧（SYN）
         * @param Id 流标识符
         * @return 完整帧
         */
        [[nodiscard]] static auto BuildOpen(std::uint32_t Id) -> std::vector<std::uint8_t>
        {
            const auto Frame = Smux::BuildSyn(Id);
            return {Frame.begin(), Frame.end()};
        }

        /**
         * @brief 构造数据帧（PSH）
         * @param Id 流标识符
         * @param Data 负载
         * @return 完整帧
         */
        [[nodiscard]] static auto BuildData(std::uint32_t Id, std::span<const std::uint8_t> Data)
            -> std::vector<std::uint8_t>
        {
            return Smux::BuildPush(Id, Data);
        }

        /**
         * @brief 构造 FIN 帧（半关）
         * @param Id 流标识符
         * @return 完整帧
         */
        [[nodiscard]] static auto BuildFin(std::uint32_t Id) -> std::vector<std::uint8_t>
        {
            const auto Frame = Smux::BuildFin(Id);
            return {Frame.begin(), Frame.end()};
        }

        /**
         * @brief 构造 RST 帧
         * @param Id 流标识符
         * @return 完整帧
         * @warning smux 协议无 RST 帧，以 FIN 帧近似。语义差异：
         *          本端 Reset() 后丢弃流，但对端收到的是 FIN（半关），
         *          仍可继续向本端数据帧——上层必须按"半关"而非"重置"
         *          处理对端行为，测试断言需留意。
         */
        [[nodiscard]] static auto BuildRst(std::uint32_t Id) -> std::vector<std::uint8_t>
        {
            return BuildFin(Id);
        }
    };

    static_assert(Mux::FrameCodec<Codec>, "Smux::Codec 必须满足 FrameCodec");

} // namespace Preview::Mux::Smux
