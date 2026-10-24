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
#include <span>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Parser.hpp>
#include <Prism/Protocols/Mux/Codec.hpp>
#include <Prism/Protocols/Mux/H2Mux/Types.hpp>

namespace Prism::Mux::H2Mux
{

    /**
     * @brief 构造 sing-mux 帧
     * @param Type 帧类型
     * @param StreamId 流标识符
     * @param Payload 负载
     * @return 完整帧
     */
    [[nodiscard]] auto Build(
        FrameType Type,
        std::uint32_t StreamId,
        std::span<const std::uint8_t> Payload = {}) -> std::vector<std::uint8_t>;

    /**
     * @brief 构造 DATA 帧
     * @param StreamId 流标识符
     * @param Payload 负载
     * @return 完整帧
     */
    [[nodiscard]] auto BuildData(
        std::uint32_t StreamId,
        std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>;

    /**
     * @brief 构造 WindowUpdate 帧
     * @param StreamId 流标识符
     * @param Delta 窗口增量
     * @return 13 字节帧
     */
    [[nodiscard]] auto BuildWinupd(std::uint32_t StreamId, std::uint32_t Delta)
        -> std::array<std::uint8_t, FrameHdrsize + sizeof(std::uint32_t)>;

    /**
     * @brief 构造 Ping 帧
     * @param PingId 心跳标识（携带于负载 4 字节）
     * @return 13 字节帧
     */
    [[nodiscard]] auto BuildPing(std::uint32_t PingId) -> std::vector<std::uint8_t>;

    /**
     * @brief 构造 Close 帧
     * @param StreamId 流标识符
     * @return 9 字节帧
     */
    [[nodiscard]] auto BuildClose(std::uint32_t StreamId)
        -> std::array<std::uint8_t, FrameHdrsize>;

    /**
     * @brief 解析 9 字节帧头
     * @param Data 至少 9 字节
     * @param Output 输出帧头
     * @return 错误码
     * @details 帧头阶段完成两层校验，避免先按声明长度分配/读取大
     *          payload，再在会话层丢弃的远程放大路径：
     *          - 未知 FrameType 直接 bad_message；
     *          - 控制帧固定长度：window_update/ping 必须 4 字节，
     *            close 必须 0 字节，否则 bad_length；
     *          - DATA 帧允许 0..MaxFrameLength 任意长度。
     */
    [[nodiscard]] auto ParseHeader(
        std::span<const std::uint8_t> Data,
        FrameHeader &Output) -> Error;

    /**
     * @brief 校验负载
     * @return 精确匹配返回 None，截断返回 NeedMore，超报返回 BadLength
     */
    [[nodiscard]] auto ParsePayload(
        FrameHeader &Frame,
        std::span<const std::uint8_t> Data) -> Error;

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

        /// sing-mux 没有独立 SYN，首个 DATA 帧隐式建立流
        static inline constexpr bool AllowsImplicitOpen = true;

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
         * @param Output 输出帧头
         * @return 错误码
         */
        static auto ParseHeader(
            std::span<const std::uint8_t> Data,
            FrameType &Output) -> Error
        {
            return H2Mux::ParseHeader(Data, Output);
        }

        /**
         * @brief 解析负载
         * @param Frame 帧头
         * @param Data 负载字节
         * @return 精确匹配返回 None，截断返回 NeedMore，超报返回 BadLength
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
            case H2Mux::FrameType::Data:
                return Mux::StreamEvent::Data;
            case H2Mux::FrameType::Close:
                return Mux::StreamEvent::Fin;
            default:
                return Mux::StreamEvent::Rst; // window_update/ping 忽略
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

} // namespace Prism::Mux::H2Mux
