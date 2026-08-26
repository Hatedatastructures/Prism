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

#include <common/Core/Error.hpp>

namespace Preview::Http2
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
        std::uint32_t length{0};      ///< 载荷长度（24 位）
        FrameType Type{FrameType::Data}; ///< 帧类型
        std::uint8_t Flags{0};        ///< 标志位
        std::uint32_t StreamId{0};   ///< 流 ID（31 位）
    };

    /// SETTINGS 参数
    struct SettingsEntry
    {
        std::uint16_t Id{0};     ///< 参数 ID
        std::uint32_t value{0};  ///< 参数值
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
        std::uint32_t increment{0}; ///< 窗口增量（31 位）
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
     * @brief 编码 24 位长度
     * @param len 长度值（≤ 0xFFFFFF）
     * @param out 输出缓冲区（3 字节）
     */
    inline void EncodeLen24(std::uint32_t len, std::span<std::byte, 3> out) noexcept
    {
        out[0] = static_cast<std::byte>((len >> 16) & 0xFF);
        out[1] = static_cast<std::byte>((len >> 8) & 0xFF);
        out[2] = static_cast<std::byte>(len & 0xFF);
    }

    /**
     * @brief 解码 24 位长度
     * @param in 输入缓冲区（3 字节）
     * @return 长度值
     */
    [[nodiscard]] inline auto DecodeLen24(std::span<const std::byte, 3> in) noexcept -> std::uint32_t
    {
        return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[0])) << 16) |
               (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[1])) << 8) |
               static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[2]));
    }

    /**
     * @brief 编码 31 位流 ID / 窗口增量
     * @param val 值（≤ 0x7FFFFFFF）
     * @param out 输出缓冲区（4 字节）
     */
    inline void EncodeU31(std::uint32_t val, std::span<std::byte, 4> out) noexcept
    {
        out[0] = static_cast<std::byte>((val >> 24) & 0x7F);
        out[1] = static_cast<std::byte>((val >> 16) & 0xFF);
        out[2] = static_cast<std::byte>((val >> 8) & 0xFF);
        out[3] = static_cast<std::byte>(val & 0xFF);
    }

    /**
     * @brief 解码 31 位值
     * @param in 输入缓冲区（至少 4 字节）
     * @return 值
     */
    [[nodiscard]] inline auto DecodeU31(std::span<const std::byte> in) noexcept -> std::uint32_t
    {
        if (in.size() < 4)
        {
            return 0;
        }
        return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[0]) & 0x7F) << 24) |
               (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[1])) << 16) |
               (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[2])) << 8) |
               static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[3]));
    }

    /**
     * @brief 构建帧（帧头 + 载荷）
     * @param Type 帧类型
     * @param Flags 标志位
     * @param StreamId 流 ID
     * @param payload 载荷（可空）
     * @return 完整帧字节（9 + payload.size()）
     */
    [[nodiscard]] inline auto BuildFrame(FrameType Type, std::uint8_t Flags, std::uint32_t StreamId,
                                          std::span<const std::byte> payload) -> std::vector<std::byte>
    {
        std::vector<std::byte> Frame;
        Frame.reserve(FrameHeaderSize + payload.size());
        Frame.resize(FrameHeaderSize);
        const auto Header = std::span<std::byte>(Frame.data(), FrameHeaderSize);
        EncodeLen24(static_cast<std::uint32_t>(payload.size()), Header.first<3>());
        Header[3] = static_cast<std::byte>(Type);
        Header[4] = static_cast<std::byte>(Flags);
        EncodeU31(StreamId, Header.last<4>());
        Frame.insert(Frame.end(), payload.begin(), payload.end());
        return Frame;
    }

    /**
     * @brief 解析帧头
     * @param Data 输入（至少 9 字节）
     * @return 解析后的帧头；不足返回 std::nullopt
     */
    [[nodiscard]] inline auto ParseFrameHeader(std::span<const std::byte> Data)
        -> std::optional<FrameHeader>
    {
        if (Data.size() < FrameHeaderSize)
        {
            return std::nullopt;
        }
        FrameHeader h;
        const auto Head = Data.first<9>();
        h.length = DecodeLen24(Head.first<3>());
        h.Type = static_cast<FrameType>(std::to_integer<std::uint8_t>(Head[3]));
        h.Flags = std::to_integer<std::uint8_t>(Head[4]);
        h.StreamId = DecodeU31(Head.last<4>());
        return h;
    }

    /**
     * @brief 编码 SETTINGS 参数
     * @param entries 参数列表
     * @return 载荷字节
     */
    [[nodiscard]] inline auto EncodeSettings(std::span<const SettingsEntry> entries)
        -> std::vector<std::byte>
    {
        std::vector<std::byte> out;
        out.reserve(entries.size() * 6);
        for (const auto &e : entries)
        {
            out.push_back(static_cast<std::byte>((e.Id >> 8) & 0xFF));
            out.push_back(static_cast<std::byte>(e.Id & 0xFF));
            out.push_back(static_cast<std::byte>((e.value >> 24) & 0xFF));
            out.push_back(static_cast<std::byte>((e.value >> 16) & 0xFF));
            out.push_back(static_cast<std::byte>((e.value >> 8) & 0xFF));
            out.push_back(static_cast<std::byte>(e.value & 0xFF));
        }
        return out;
    }

    /**
     * @brief 解码 SETTINGS 载荷
     * @param Data 载荷字节
     * @return 参数列表；长度非法返回 std::nullopt
     */
    [[nodiscard]] inline auto DecodeSettings(std::span<const std::byte> Data)
        -> std::optional<std::vector<SettingsEntry>>
    {
        if (Data.size() % 6 != 0)
        {
            return std::nullopt;
        }
        std::vector<SettingsEntry> entries;
        entries.reserve(Data.size() / 6);
        for (std::size_t I = 0; I < Data.size(); I += 6)
        {
            SettingsEntry e;
            e.Id = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Data[I])) << 8) |
                static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Data[I + 1])));
            e.value = (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Data[I + 2])) << 24) |
                      (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Data[I + 3])) << 16) |
                      (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Data[I + 4])) << 8) |
                      static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Data[I + 5]));
            entries.push_back(e);
        }
        return entries;
    }

    /**
     * @brief 编码 WINDOW_UPDATE 载荷
     * @param increment 窗口增量
     * @return 4 字节载荷
     */
    [[nodiscard]] inline auto EncodeWindowUpdate(std::uint32_t increment) -> std::array<std::byte, 4>
    {
        std::array<std::byte, 4> out{};
        EncodeU31(increment, out);
        return out;
    }

    /**
     * @brief 编码 RST_STREAM 载荷
     * @param ErrorCode 错误码
     * @return 4 字节载荷
     */
    [[nodiscard]] inline auto EncodeRstStream(std::uint32_t ErrorCode) -> std::array<std::byte, 4>
    {
        std::array<std::byte, 4> out{};
        EncodeU31(ErrorCode, out);
        return out;
    }

    /**
     * @brief 编码 GOAWAY 载荷
     * @param params GOAWAY 参数
     * @return 载荷字节
     */
    [[nodiscard]] inline auto EncodeGoaway(const GoawayParams &params) -> std::vector<std::byte>
    {
        std::vector<std::byte> out;
        out.reserve(8 + params.Debug.size());
        out.resize(8);
        const auto Head = std::span<std::byte>(out.data(), 8);
        EncodeU31(params.LastStreamId, Head.first<4>());
        EncodeU31(params.ErrorCode, Head.last<4>());
        out.insert(out.end(), params.Debug.begin(), params.Debug.end());
        return out;
    }

    /// 常见 SETTINGS 参数 ID（RFC 7540 §6.5.2）
    constexpr std::uint16_t SettingsHeaderTableSize = 0x1;
    constexpr std::uint16_t SettingsEnablePush = 0x2;
    constexpr std::uint16_t SettingsMaxConcurrentStreams = 0x3;
    constexpr std::uint16_t SettingsInitialWindowSize = 0x4;
    constexpr std::uint16_t SettingsMaxFrameSize = 0x5;
    constexpr std::uint16_t SettingsMaxHeaderListSize = 0x6;

    /// 常见错误码（RFC 7540 §7）
    constexpr std::uint32_t ErrorNoError = 0x0;
    constexpr std::uint32_t ErrorProtocol = 0x1;
    constexpr std::uint32_t ErrorInternal = 0x2;
    constexpr std::uint32_t ErrorFlowControl = 0x3;
    constexpr std::uint32_t ErrorStreamClosed = 0x5;
    constexpr std::uint32_t ErrorFrameSize = 0x6;
    constexpr std::uint32_t ErrorRefusedStream = 0x7;
    constexpr std::uint32_t ErrorCancel = 0x8;
    constexpr std::uint32_t ErrorCompression = 0x9;

} // namespace Preview::Http2
