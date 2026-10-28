/**
 * @file Frame.hpp
 * @brief HTTP/2 帧编解码（自包含实现，不依赖 nghttp2）
 * @details 9 字节帧头 + 各类帧载荷编解码：
 *          - FrameHeader：9 字节帧头（len24 + Type + Flags + stream_id31）
 *          - BuildFrame / ParseFrame：通用帧组装/解析
 *          - 各帧载荷：DATA/HEADERS/SETTINGS/PING/GOAWAY/WINDOW_UPDATE/RST_STREAM
 * @note HPACK 头压缩见 Codec.hpp；流状态机见 Session.hpp
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Http2/Types.hpp>

namespace Prism::Http2::Detail
{

    /// 帧类型（RFC 7540 §6）
    enum class FrameType : std::uint8_t
    {
        Data = 0x0,          ///< DATA
        Headers = 0x1,       ///< HEADERS
        Priority = 0x2,      ///< PRIORITY
        RstStream = 0x3,    ///< RST_STREAM
        Settings = 0x4,      ///< SETTINGS
        PushPromise = 0x5,  ///< PUSH_PROMISE
        Ping = 0x6,          ///< PING
        Goaway = 0x7,        ///< GOAWAY
        WindowUpdate = 0x8, ///< WINDOW_UPDATE
        Continuation = 0x9,  ///< CONTINUATION
    };

    /**
     * @brief HTTP/2 帧编码参数
     * @details Payload 为借用视图，仅在 BuildFrame 调用期间读取。
     */
    struct FrameParameters
    {
        FrameType Type;
        std::uint8_t Flags;
        std::uint32_t StreamId;
        std::span<const std::byte> Payload;
    };

    /// 帧标志位（RFC 7540 §6）
    enum FrameFlag : std::uint8_t
    {
        FlagNone = 0x0,
        FlagEndStream = 0x1,    ///< END_STREAM
        FlagEndHeaders = 0x4,   ///< END_HEADERS
        FlagPadded = 0x8,        ///< PADDED
        FlagPriority = 0x20,     ///< PRIORITY
        FlagAck = 0x1,           ///< ACK
        FlagSettingsAck = 0x1,  ///< SETTINGS ACK
    };

    /// 帧头（9 字节）
    struct FrameHeader
    {
        std::uint32_t Length{0}; ///< 载荷长度（24 位；保留以兼容现有调用方）
        FrameType Type{FrameType::Data}; ///< 帧类型
        std::uint8_t Flags{0};        ///< 标志位
        std::uint32_t StreamId{0};   ///< 流 ID（31 位）
    };


    /// GOAWAY 参数
    struct GoawayParams
    {
        std::uint32_t LastStreamId{0}; ///< 最后处理的流 ID
        std::uint32_t ErrorCode{0};     ///< 错误码
        std::vector<std::byte> Debug;    ///< 调试数据
    };

    /// WINDOW_UPDATE 载荷
    struct WindowUpdateParams
    {
        std::uint32_t Increment{0}; ///< 窗口增量（31 位）
    };

    /// RST_STREAM 载荷
    struct RstStreamParams
    {
        std::uint32_t ErrorCode{0}; ///< 错误码
    };

    /// 帧头大小（固定 9 字节）
    constexpr std::size_t FrameHeaderSize = 9;

    /// 最大帧载荷（默认 16384）
    constexpr std::size_t DefaultFramePayload = 16384;

    /// 初始流窗口（65535）
    constexpr std::uint32_t DefaultInitialWindow = 65535;

    /// 连接流 ID（0）
    constexpr std::uint32_t ConnectionStreamId = 0;

    /**
     * @brief 校验仅凭 9 字节帧头即可确定的载荷长度约束。
     * @details 这里只检查固定长度、固定最小前缀和 SETTINGS 对齐；不解释流 ID、
     *          依赖关系或载荷字段语义。未知帧类型按协议允许的长度处理。
     */
    [[nodiscard]] constexpr auto HasValidFrameLength(const FrameHeader &Header) noexcept -> bool
    {
        switch (Header.Type)
        {
        case FrameType::Data:
            return (Header.Flags & FlagPadded) == 0 || Header.Length >= 1;
        case FrameType::Headers:
            return Header.Length >=
                   (((Header.Flags & FlagPadded) != 0) ? 1U : 0U) +
                       (((Header.Flags & FlagPriority) != 0) ? 5U : 0U);
        case FrameType::Priority:
            return Header.Length == 5;
        case FrameType::RstStream:
        case FrameType::WindowUpdate:
            return Header.Length == 4;
        case FrameType::Settings:
            return (Header.Flags & FlagAck) != 0
                       ? Header.Length == 0
                       : Header.Length % 6 == 0;
        case FrameType::PushPromise:
            return Header.Length >= (((Header.Flags & FlagPadded) != 0) ? 5U : 4U);
        case FrameType::Ping:
            return Header.Length == 8;
        case FrameType::Goaway:
            return Header.Length >= 8;
        case FrameType::Continuation:
        default:
            return true;
        }
    }

    /**
     * @brief 编码 24 位长度
     * @param Length 长度值（≤ 0xFFFFFF）
     * @param Output 输出缓冲区（3 字节）
     */
    auto EncodeLen24(
        std::uint32_t Length,
        std::span<std::byte, 3> Output) noexcept -> void;

    /**
     * @brief 解码 24 位长度
     * @param Input 输入缓冲区（3 字节）
     * @return 长度值
     */
    [[nodiscard]] auto DecodeLen24(
        std::span<const std::byte, 3> Input) noexcept -> std::uint32_t;

    /**
     * @brief 编码 31 位流 ID / 窗口增量
     * @param Value 值（≤ 0x7FFFFFFF）
     * @param Output 输出缓冲区（4 字节）
     */
    auto EncodeU31(
        std::uint32_t Value,
        std::span<std::byte, 4> Output) noexcept -> void;

    /**
     * @brief 编码 32 位错误码
     * @param ErrorCode 错误码
     * @param Output 输出缓冲区（4 字节）
     */
    auto EncodeU32(
        std::uint32_t ErrorCode,
        std::span<std::byte, 4> Output) noexcept -> void;

    /**
     * @brief 解码 31 位值
     * @param Input 输入缓冲区（至少 4 字节）
     * @return 值
     */
    [[nodiscard]] auto DecodeU31(
        std::span<const std::byte> Input) noexcept -> std::uint32_t;

    /**
     * @brief 解码 32 位错误码
     * @param Input 输入缓冲区（至少 4 字节）
     * @return 32 位值；不足返回 0
     */
    [[nodiscard]] auto DecodeU32(
        std::span<const std::byte> Input) noexcept -> std::uint32_t;

    /**
     * @brief 构建帧（帧头 + 载荷）
     * @param Params 帧类型、标志位、流 ID 与载荷
     * @return 完整帧字节（9 + Payload.size()）
     */
    [[nodiscard]] auto BuildFrame(const FrameParameters &Params) -> std::vector<std::byte>;

    /**
     * @brief 解析帧头
     * @param Data 输入（至少 9 字节）
     * @return 解析后的帧头；不足返回 std::nullopt
     */
    [[nodiscard]] auto ParseFrameHeader(
        std::span<const std::byte> Data)
        -> std::optional<FrameHeader>;

    /**
     * @brief 编码 SETTINGS 参数
     * @param Entries 参数列表
     * @return 载荷字节
     */
    [[nodiscard]] auto EncodeSettings(
        std::span<const SettingsEntry> Entries)
        -> std::vector<std::byte>;

    /**
     * @brief 解码 SETTINGS 载荷
     * @param Data 载荷字节
     * @return 参数列表；长度非法返回 std::nullopt
     */
    [[nodiscard]] auto DecodeSettings(
        std::span<const std::byte> Data)
        -> std::optional<std::vector<SettingsEntry>>;

    /**
     * @brief 编码 WINDOW_UPDATE 载荷
     * @param Increment 窗口增量
     * @return 4 字节载荷
     */
    [[nodiscard]] auto EncodeWindowUpdate(std::uint32_t Increment) -> std::array<std::byte, 4>;

    /**
     * @brief 编码 RST_STREAM 载荷
     * @param ErrorCode 错误码
     * @return 4 字节载荷
     */
    [[nodiscard]] auto EncodeRstStream(std::uint32_t ErrorCode) -> std::array<std::byte, 4>;

    /**
     * @brief 编码 GOAWAY 载荷
     * @param Params GOAWAY 参数
     * @return 载荷字节
     */
    [[nodiscard]] auto EncodeGoaway(const GoawayParams &Params) -> std::vector<std::byte>;


} // namespace Prism::Http2::Detail
