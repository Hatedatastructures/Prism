/**
 * @file codec.hpp
 * @brief 帧编解码策略接口
 * @details 定义 multiplex::codec，多路复用协议的帧格式抽象。
 *          每个协议（smux/yamux/h2mux）提供独立实现，负责帧头
 *          编解码与数据帧/结束帧的构造。协议差异点全部下沉至此：
 *          control 层只消费统一的 frame_meta，不感知具体帧布局。
 *          相当于协议与帧格式之间的"翻译官"——上层说逻辑帧，
 *          它翻译成线上字节。
 * @note 设计原则：codec 是纯帧格式变换，无状态、无协程，
 *       不持有任何 I/O 资源，可单测、可替换
 * @note 线程安全：纯函数语义，天然线程安全
 */
#pragma once

#include <prism/foundation/memory/container.hpp>
#include <prism/net/connection/types.hpp>

#include <cstdint>
#include <span>
#include <string_view>

namespace psm::multiplex
{

    /**
     * @enum addr_mode
     * @brief UDP 数据报地址编码模式
     * @details 描述 mux 帧中 UDP 数据报的目标地址携带方式：
     *          length_prefixed 模式目标地址在流建立时确定，帧内仅
     *          [Length 2B BE][Payload]；packet_addr 模式每帧携带
     *          SOCKS5 地址格式的目标。由 *_control 决定并注入回调。
     */
    enum class addr_mode : std::uint8_t
    {
        length_prefixed, ///< 仅 length+payload，目标地址使用流建立时解析的地址
        packet_addr      ///< 每帧携带 SOCKS5 地址格式的目标地址
    };

    /**
     * @enum frame_kind
     * @brief 协议无关的帧语义分类
     * @details control 层按此分类分发帧处理：
     *          数据帧进入流管道，同步帧触发流建立，结束帧触发半关闭，
     *          复位帧强制关闭，控制帧由 control 自行解释原始类型码。
     */
    enum class frame_kind : std::uint8_t
    {
        data,    ///< 数据帧（携带载荷）
        syn,     ///< 同步帧（携带目标地址，建立新流）
        fin,     ///< 结束帧（半关闭流）
        rst,     ///< 复位帧（强制关闭流）
        control, ///< 控制帧（窗口/心跳/告警等，语义由 control 按 raw_type 解释）
    };

    /**
     * @struct frame_meta
     * @brief 帧头解析结果
     * @details decode_header 的输出，包含语义分类、流标识符、
     *          载荷长度、标志位与原始类型码。载荷长度用于决定
     *          帧循环读取多少字节作为载荷。
     */
    struct frame_meta
    {
        frame_kind kind{frame_kind::control}; ///< 语义分类
        std::uint32_t stream_id{0};           ///< 流标识符
        std::uint32_t length{0};              ///< 载荷字节数
        std::uint16_t flags{0};               ///< 协议标志位
        std::uint8_t raw_type{0};             ///< 原始类型码（control 帧语义判断用）
    };

    /**
     * @class codec
     * @brief 帧编解码策略接口
     * @details 每个多路复用协议实现一个子类：
     *          - smux_codec：8 字节定长头 + PacketAddr 标志
     *          - yamux_codec：12 字节定长头 + 窗口/心跳帧
     *          - h2_codec：nghttp2 帧桥接
     */
    class codec
    {
    public:
        virtual ~codec() = default;

        /**
         * @brief 获取帧头长度
         * @return 帧头字节数（定长帧协议为固定值）
         */
        [[nodiscard]] virtual auto header_size() const noexcept -> std::size_t = 0;

        /**
         * @brief 解析帧头
         * @param header 帧头字节（长度不小于 header_size()）
         * @return 帧头元信息（语义分类、流标识符、载荷长度）
         */
        [[nodiscard]] virtual auto decode_header(std::span<const std::byte> header) -> frame_meta = 0;

        /**
         * @brief 构造数据帧（完整帧字节：帧头 + 载荷）
         * @param stream_id 目标流标识符
         * @param payload 载荷数据
         * @return 编码后的完整帧字节
         */
        [[nodiscard]] virtual auto encode_data(std::uint32_t stream_id, std::span<const std::byte> payload)
            -> memory::vector<std::byte> = 0;

        /**
         * @brief 构造结束帧（完整帧字节）
         * @param stream_id 目标流标识符
         * @return 编码后的完整帧字节
         */
        [[nodiscard]] virtual auto encode_fin(std::uint32_t stream_id) -> memory::vector<std::byte> = 0;

        /**
         * @brief 获取协议名称
         * @return 协议名字符串（smux/yamux/h2mux，用于日志）
         */
        [[nodiscard]] virtual auto type_name() const noexcept -> std::string_view = 0;
    };

} // namespace psm::multiplex
