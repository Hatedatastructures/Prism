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
#include <span>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Parser.hpp>
#include <Prism/Protocols/Mux/Codec.hpp>
#include <Prism/Protocols/Mux/Yamux/Types.hpp>

namespace Prism::Mux::Yamux::Detail
{

    /**
     * @brief 编码帧头为 12 字节大端序数组
     * @param Header 帧头
     * @return 编码后的字节数组
     */
    [[nodiscard]] auto BuildHeader(const FrameHeader &Header) noexcept
        -> std::array<std::uint8_t, FrameHdrsize>;

    /**
     * @brief 构造完整帧（帧头 + 载荷）
     * @param Header 帧头（Data 的 length 自动填充）
     * @param Payload 载荷
     * @return 完整帧
     */
    [[nodiscard]] auto Build(
        const FrameHeader &Header,
        std::span<const std::uint8_t> Payload = {}) -> std::vector<std::uint8_t>;

    /**
     * @brief 构造 WindowUpdate 帧（SYN/ACK 打开/确认流）
     * @param FlagsValue 标志位
     * @param StreamId 流标识符
     * @param Delta 窗口增量
     * @return 12 字节帧
     */
    [[nodiscard]] auto BuildWinupd(
        Flags FlagsValue,
        std::uint32_t StreamId,
        std::uint32_t Delta) noexcept
        -> std::array<std::uint8_t, FrameHdrsize>;

    /**
     * @brief 构造普通窗口更新帧
     * @param StreamId 流标识符
     * @param Delta 已消费的窗口增量
     * @return 12 字节窗口更新帧
     */
    [[nodiscard]] auto BuildWindowUpdate(std::uint32_t StreamId, std::uint32_t Delta)
        -> std::vector<std::uint8_t>;

    /**
     * @brief 构造 Ping 帧
     * @param FlagsValue 标志位（SYN 请求 / ACK 响应）
     * @param PingId 心跳标识
     * @return 12 字节帧
     */
    [[nodiscard]] auto BuildPing(Flags FlagsValue, std::uint32_t PingId) noexcept
        -> std::array<std::uint8_t, FrameHdrsize>;

    /**
     * @brief 构造 GoAway 帧
     * @param Code 终止原因码
     * @return 12 字节帧
     */
    [[nodiscard]] auto BuildGoaway(AwayCode Code) noexcept
        -> std::array<std::uint8_t, FrameHdrsize>;

    /**
     * @brief 构造 Data 帧
     * @param FlagsValue 标志位（none/SYN/FIN/RST）
     * @param StreamId 流标识符
     * @param Payload 载荷
     * @return 完整帧
     */
    [[nodiscard]] auto BuildData(
        Flags FlagsValue,
        std::uint32_t StreamId,
        std::span<const std::uint8_t> Payload) noexcept
        -> std::vector<std::uint8_t>;

    /**
     * @brief 构造 Data(SYN) 帧（sing-mux 兼容新流创建）
     * @param StreamId 流标识符
     * @param Payload 载荷
     * @return 完整帧
     */
    [[nodiscard]] auto BuildSyn(
        std::uint32_t StreamId,
        std::span<const std::uint8_t> Payload) noexcept
        -> std::vector<std::uint8_t>;

    /**
     * @brief 构造 Data(FIN) 帧
     * @param StreamId 流标识符
     * @return 12 字节帧
     */
    [[nodiscard]] auto BuildFin(std::uint32_t StreamId) noexcept
        -> std::array<std::uint8_t, FrameHdrsize>;

    /**
     * @brief 解析 12 字节帧头
     * @param Data 至少 12 字节
     * @param Output 输出帧头
     * @return 错误码
     */
    [[nodiscard]] auto ParseHeader(
        std::span<const std::uint8_t> Data,
        FrameHeader &Output) noexcept -> Error;

    /**
     * @brief 校验负载（yamux 不执行额外负载内容校验）
     * @return 始终返回 None；帧长度预算由共享 Session/Parser 处理
     */
    [[nodiscard]] auto ParsePayload(FrameHeader &, std::span<const std::uint8_t>) -> Error;

    /**
     * @struct Codec
     * @brief yamux 帧编解码策略（供共享会话框架模板传参）
     * @details 实现 FrameCodec concept：帧构造与帧事件判定。
     *          开流 = WindowUpdate(SYN)，数据/半关/重置均为 Data 帧
     *          + 对应标志位；普通 WindowUpdate 属于会话控制帧。
     */
    struct Codec
    {
        /// 帧类型
        using FrameType = FrameHeader;

        /// 帧头长度
        static inline constexpr std::size_t HeaderLen = FrameHdrsize;

        /// 最大负载长度（yamux 无硬限制，取 16MB）
        static inline constexpr std::size_t MaxPayloadLen = 16 * 1024 * 1024;

        /// yamux 必须先收到 WindowUpdate(SYN) 才能建立流
        static inline constexpr bool AllowsImplicitOpen = false;

        /// yamux 的数据发送受每流窗口约束
        static inline constexpr bool UsesFlowControl = true;

        /// 初始流窗口
        static inline constexpr std::uint32_t InitialWindow = DefaultWindow;

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
         * @param Output 输出帧头
         * @return 错误码
         */
        static auto ParseHeader(
            std::span<const std::uint8_t> Data,
            FrameType &Output) -> Error
        {
            return Prism::Mux::Yamux::Detail::ParseHeader(Data, Output);
        }

        /**
         * @brief 解析负载
         * @param Frame 帧头
         * @param Data 负载字节
         * @return 始终返回 None；帧长度预算由共享 Session/Parser 处理
         */
        static auto ParsePayload(FrameType &Frame, std::span<const std::uint8_t> Data) -> Error
        {
            return Prism::Mux::Yamux::Detail::ParsePayload(Frame, Data);
        }

        /**
         * @brief 帧事件判定
         * @param Frame 帧头
         * @return 流事件（WindowUpdate+SYN/Data+SYN=开流 /
         * Data+FIN=半关 / Data+RST=重置 / Data=数据 /
         * 其余=rst 忽略）
         */
        [[nodiscard]] static auto FrameEvent(const FrameType &Frame) noexcept -> Mux::StreamEvent
        {
            if (Frame.Type == MessageType::WindowUpdate && HasFlag(Frame.flag, Flags::Syn))
            {
                return Mux::StreamEvent::Open;
            }
            if (Frame.Type == MessageType::Data)
            {
                if (HasFlag(Frame.flag, Flags::Syn))
                {
                    return Mux::StreamEvent::Open;
                }
                if (HasFlag(Frame.flag, Flags::Fin))
                {
                    return Mux::StreamEvent::Fin;
                }
                if (HasFlag(Frame.flag, Flags::Rst))
                {
                    return Mux::StreamEvent::Rst;
                }
                return Mux::StreamEvent::Data;
            }
            return Mux::StreamEvent::Rst; // winupd/ping/goaway：会话级，忽略
        }

        /**
         * @brief 会话级控制帧判定
         * @param Frame 帧头
         * @return true = 普通窗口更新、ping 或 go_away；SYN 开流帧不是控制帧
         */
        [[nodiscard]] static auto IsControl(const FrameType &Frame) noexcept -> bool
        {
            if (Frame.Type == MessageType::WindowUpdate)
            {
                return !HasFlag(Frame.flag, Flags::Syn);
            }
            return Frame.Type == MessageType::Ping || Frame.Type == MessageType::GoAway;
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
         * @brief 判断是否为窗口更新帧
         * @param Frame 待判断帧
         * @return true = WindowUpdate
         */
        [[nodiscard]] static auto IsWindowUpdate(const FrameType &Frame) noexcept -> bool
        {
            return Frame.Type == MessageType::WindowUpdate;
        }

        /**
         * @brief 判断是否为远端新流窗口声明
         * @param Frame 待判断帧
         * @return true = SYN 且不是 ACK
         */
        [[nodiscard]] static auto IsOpenFrame(const FrameType &Frame) noexcept -> bool
        {
            if (Frame.Type == MessageType::WindowUpdate)
            {
                return HasFlag(Frame.flag, Flags::Syn) && !HasFlag(Frame.flag, Flags::Ack);
            }
            return Frame.Type == MessageType::Data && HasFlag(Frame.flag, Flags::Syn) &&
                   !HasFlag(Frame.flag, Flags::Ack);
        }

        /**
         * @brief 判断是否为流打开确认
         * @param Frame 待判断帧
         * @return true = WindowUpdate ACK
         */
        [[nodiscard]] static auto IsWindowAck(const FrameType &Frame) noexcept -> bool
        {
            return Frame.Type == MessageType::WindowUpdate && HasFlag(Frame.flag, Flags::Ack);
        }

        /**
         * @brief 读取窗口增量
         * @param Frame 待判断帧
         * @return Length 字段
         */
        [[nodiscard]] static auto WindowDelta(const FrameType &Frame) noexcept -> std::uint32_t
        {
            return Frame.length;
        }

        /**
         * @brief 取得远端为本端发送方向声明的窗口
         * @param Frame 远端开流帧
         * @return 可发送字节数
         */
        [[nodiscard]] static auto OpenSendWindow(const FrameType &Frame) noexcept -> std::uint32_t
        {
            if (Frame.Type == MessageType::WindowUpdate && Frame.length != 0)
            {
                return Frame.length;
            }
            return DefaultWindow;
        }

        /**
         * @brief 构造开流帧（WindowUpdate+SYN，Length = 初始窗口）
         * @param Id 流标识符
         * @return 完整帧
         */
        [[nodiscard]] static auto BuildOpen(std::uint32_t Id) -> std::vector<std::uint8_t>
        {
            const auto Frame = Prism::Mux::Yamux::Detail::BuildWinupd(
                Flags::Syn, Id, DefaultWindow);
            return {Frame.begin(), Frame.end()};
        }

        /**
         * @brief 构造新流窗口确认帧
         * @param Id 流标识符
         * @return WindowUpdate(ACK) 帧
         */
        [[nodiscard]] static auto BuildOpenAck(std::uint32_t Id) -> std::vector<std::uint8_t>
        {
            const auto Frame = Prism::Mux::Yamux::Detail::BuildWinupd(
                Flags::Ack, Id, DefaultWindow);
            return {Frame.begin(), Frame.end()};
        }

        /**
         * @brief 构造接收窗口归还帧
         * @param Id 流标识符
         * @param Delta 已消费的字节数
         * @return 完整窗口更新帧
         */
        [[nodiscard]] static auto BuildWindowUpdate(std::uint32_t Id, std::uint32_t Delta)
            -> std::vector<std::uint8_t>
        {
            return Prism::Mux::Yamux::Detail::BuildWindowUpdate(Id, Delta);
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
            return Prism::Mux::Yamux::Detail::BuildData(Flags::None, Id, Data);
        }

        /**
         * @brief 构造 FIN 帧（Data+FIN，半关）
         * @param Id 流标识符
         * @return 完整帧
         */
        [[nodiscard]] static auto BuildFin(std::uint32_t Id) -> std::vector<std::uint8_t>
        {
            const auto Frame = Prism::Mux::Yamux::Detail::BuildFin(Id);
            return {Frame.begin(), Frame.end()};
        }

        /**
         * @brief 构造 RST 帧（Data+RST，重置流）
         * @param Id 流标识符
         * @return 完整帧
         */
        [[nodiscard]] static auto BuildRst(std::uint32_t Id) -> std::vector<std::uint8_t>
        {
            return Prism::Mux::Yamux::Detail::BuildData(Flags::Rst, Id, {});
        }
    };

    static_assert(Mux::FrameCodec<Codec>, "Yamux::Codec 必须满足 FrameCodec");

} // namespace Prism::Mux::Yamux
