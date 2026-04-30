/**
 * @file frame.hpp
 * @brief yamux 协议帧格式定义与编解码
 * @details 定义 yamux 多路复用协议的帧格式、消息类型、标志位和编解码函数。
 * 帧格式为 12 字节定长帧头，所有多字节字段使用大端序（网络字节序）：
 * [Version 1B][Type 1B][Flags 2B BE][StreamID 4B BE][Length 4B BE]。
 * 消息类型与 Length 字段的对应关系：Data 中 Length 为载荷字节数，
 * WindowUpdate 中 Length 为窗口增量，Ping 中 Length 为 ping 标识符，
 * GoAway 中 Length 为错误码。兼容 Hashicorp/yamux 协议规范，
 * Version 固定为 0。与 smux 的 8 字节小端帧头不同，yamux 使用
 * 12 字节大端帧头，并引入完整的流量控制（窗口管理）和标志位系统。
 */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace psm::multiplex::yamux
{
    // 协议版本号，yamux 规范规定 Version 字段固定为 0
    constexpr std::uint8_t protocol_version = 0x00;

    // 帧头大小（字节）：Version(1) + Type(1) + Flags(2) + StreamID(4) + Length(4) = 12
    constexpr std::size_t frame_header_size = 12;

    // 初始流窗口大小（256KB），用于 WindowUpdate SYN/ACK 的 Length 字段和接收窗口阈值
    constexpr std::uint32_t initial_stream_window = 256 * 1024;

    /**
     * @enum message_type
     * @brief yamux 帧消息类型，对应帧头的 Type 字段（1 字节）
     */
    enum class message_type : std::uint8_t
    {
        /** @brief 数据帧，承载流数据或携带 SYN/FIN/RST 标志控制流生命周期 */
        data = 0x00,
        /** @brief 窗口更新帧，用于流量控制或携带 SYN/ACK 标志打开/确认流 */
        window_update = 0x01,
        /** @brief 心跳帧，SYN 为请求，ACK 为响应 */
        ping = 0x02,
        /** @brief 会话终止帧，Length 字段携带终止原因码 */
        go_away = 0x03
    }; // enum message_type

    // 标志位

    /**
     * @enum flags
     * @brief yamux 帧标志位，对应帧头的 Flags 字段（2 字节大端序）
     * @details 标志位可组合使用，不同消息类型下语义不同：
     * Data+SYN 为携带地址数据的新流创建（sing-mux 兼容模式），
     * Data+FIN 为半关闭流（发送端不再发送数据），Data+RST 为强制重置流，
     * WindowUpdate+SYN 为客户端打开新流（Length 为初始窗口大小），
     * WindowUpdate+ACK 为确认流创建（Length 为服务端初始窗口大小），
     * Ping+SYN 为心跳请求，Ping+ACK 为心跳响应
     */
    enum class flags : std::uint16_t
    {
        /** @brief 无标志 */
        none = 0x0000,
        /** @brief SYN 同步标志，用于打开流或发起心跳请求 */
        syn = 0x0001,
        /** @brief ACK 确认标志，用于确认流创建或回复心跳 */
        ack = 0x0002,
        /** @brief FIN 半关闭标志，发送端不再发送数据 */
        fin = 0x0004,
        /** @brief RST 重置标志，强制关闭流 */
        rst = 0x0008
    }; // enum flags

    // 标志位按位与运算
    [[nodiscard]] constexpr flags operator&(flags a, flags b) noexcept
    {
        return static_cast<flags>(static_cast<std::uint16_t>(a) & static_cast<std::uint16_t>(b));
    }

    /**
     * @brief 检查标志位组合中是否包含指定标志
     * @param f 待检查的标志组合
     * @param flag 目标标志
     * @return true 表示包含该标志
     */
    [[nodiscard]] constexpr bool has_flag(flags f, flags flag) noexcept
    {
        return (f & flag) != flags::none;
    }

    /**
     * @enum go_away_code
     * @brief GoAway 帧的终止原因码，对应 GoAway 帧的 Length 字段
     */
    enum class go_away_code : std::uint32_t
    {
        /** @brief 协议错误，收到无法识别的帧或非法状态转换 */
        protocol_error = 1
    }; // enum go_away_code

    // 帧结构

    /**
     * @struct frame_header
     * @brief yamux 解析后的帧头（12 字节），所有多字节字段使用大端序
     * @details 存储 parse_header 的解析结果，各字段含义因消息类型而异。
     * Length 在 Data 帧中为载荷长度，在 WindowUpdate 帧中为窗口增量，
     * 在 Ping 帧中为 ping 标识符，在 GoAway 帧中为终止原因码。
     */
    struct frame_header
    {
        std::uint8_t version = protocol_version; // 协议版本，固定为 0
        message_type type = message_type::data;  // 消息类型
        flags flag = flags::none;                // 标志位组合
        std::uint32_t stream_id = 0;             // 流标识符，会话级帧为 0
        std::uint32_t length = 0;                // 长度字段，含义取决于消息类型

        /**
         * @brief 检查是否为会话级消息（StreamID == 0）
         * @return true 表示该帧属于会话级（如 Ping、GoAway）
         */
        [[nodiscard]] bool is_session() const noexcept
        {
            return stream_id == 0;
        }
    }; // struct frame_header

    // 帧编解码函数

    /**
     * @brief 编码帧头为 12 字节大端序数组
     * @param hdr 帧头结构
     * @return 编码后的 12 字节数组
     */
    [[nodiscard]] std::array<std::byte, frame_header_size> build_header(const frame_header &hdr) noexcept;

    /**
     * @brief 解析 12 字节帧头
     * @param buffer 输入缓冲区，至少包含 12 字节
     * @return 解析结果，Version 或 Type 非法时返回 nullopt
     */
    [[nodiscard]] std::optional<frame_header> parse_header(std::span<const std::byte> buffer) noexcept;

    /**
     * @brief 构建 WindowUpdate 帧（仅 12 字节帧头，无载荷）
     * @param f 标志位，SYN 用于打开流，ACK 用于确认流
     * @param stream_id 流标识符
     * @param delta 窗口增量（字节数）
     * @return 编码后的 12 字节数组
     */
    [[nodiscard]] std::array<std::byte, frame_header_size> build_window_update_frame(
        flags f, std::uint32_t stream_id, std::uint32_t delta) noexcept;

    /**
     * @brief 构建 Ping 帧（仅 12 字节帧头，无载荷）
     * @param f 标志位，SYN 为请求，ACK 为响应
     * @param ping_id ping 标识符，响应帧必须携带与请求相同的 ID
     * @return 编码后的 12 字节数组
     */
    [[nodiscard]] std::array<std::byte, frame_header_size> build_ping_frame(
        flags f, std::uint32_t ping_id) noexcept;

    /**
     * @brief 构建 GoAway 帧（仅 12 字节帧头，无载荷）
     * @param code 终止原因码
     * @return 编码后的 12 字节数组
     */
    [[nodiscard]] std::array<std::byte, frame_header_size> build_go_away_frame(go_away_code code) noexcept;

    /**
     * @struct data_frame
     * @brief 完整的 Data 帧（12 字节帧头 + 载荷）
     * @details 用于测试和调试场景，将帧头与载荷打包返回。
     * 生产环境中 header 与 payload 通过 outbound_frame 分离传递。
     */
    struct data_frame
    {
        std::array<std::byte, frame_header_size> header{}; // 编码后的帧头
        std::vector<std::byte> payload;                     // 帧载荷
    }; // struct data_frame

    /**
     * @brief 构建 Data 帧（帧头 + 载荷）
     * @param f 标志位（none/SYN/FIN/RST 或其组合）
     * @param stream_id 流标识符
     * @param payload 帧载荷数据（可为空）
     * @return 包含帧头和载荷的 data_frame 结构
     */
    [[nodiscard]] data_frame make_data_frame(flags f, std::uint32_t stream_id,
                                             std::span<const std::byte> payload) noexcept;

    /**
     * @brief 构建 Data(SYN) 帧（帧头 + 载荷）
     * @param stream_id 流标识符
     * @param payload 帧载荷数据（通常携带目标地址）
     * @return 包含帧头和载荷的 data_frame 结构
     * @details 等价于 make_data_frame(flags::syn, stream_id, payload)，
     * 用于 sing-mux 兼容模式的新流创建。
     */
    [[nodiscard]] data_frame make_syn_frame(std::uint32_t stream_id,
                                            std::span<const std::byte> payload) noexcept;

    /**
     * @brief 构建 Data(FIN) 帧（仅 12 字节帧头，无载荷）
     * @param stream_id 流标识符
     * @return 编码后的 12 字节数组
     * @details FIN 帧不携带载荷，Length 字段为 0。
     */
    [[nodiscard]] std::array<std::byte, frame_header_size> make_fin_frame(std::uint32_t stream_id) noexcept;

} // namespace psm::multiplex::yamux
